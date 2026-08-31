import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import { BudgetManager, type BudgetManagerOptions } from "./budgets";
import { ContainmentDetector, type ContainmentOptions } from "./containment";
import {
	EscalationController,
	type EscalationOptions,
	RecoveryController,
	type RecoveryOptions,
} from "./escalation";
import { EventStore } from "./events";
import {
	parseOMPRuntimePolicy,
	PolicyCache,
	type PolicyCacheOptions,
	type SignedPolicyBundle,
} from "./policyCache";
import type {
	BudgetAdmission,
	BudgetLimits,
	Clock,
	EscalationRequest,
	EscalationResult,
	EventSink,
	RecoveryResult,
	ExtensionEvent,
	RequestContext,
	RequestMetadata,
	ResponseResult,
} from "./types";

export interface ControllerTransport {
	fetchPolicy: () => Promise<SignedPolicyBundle | null>;
}

export type AlertHook = (event: ExtensionEvent) => Promise<void> | void;

export interface ExtensionOptions {
	observeOnly?: boolean;
	budgetLimits?: BudgetLimits;
	containment?: ContainmentOptions;
	policy?: PolicyCacheOptions;
	budget?: BudgetManagerOptions;
	escalation?: EscalationOptions;
	recovery?: RecoveryOptions;
	eventSink?: EventSink;
	clock?: Clock;
	transport?: ControllerTransport;
	alert?: AlertHook;
	eventPath?: string;
}

export interface RequestAdmission {
	allowed: boolean;
	metadata: RequestMetadata;
	reason: string | null;
	manual: boolean;
}

export interface ResponseObservation {
	parked: boolean;
	alreadyParked: boolean;
	consumedTokens: number;
	escalation: EscalationResult | null;
	recovery: RecoveryResult | null;
}

const noAlert: AlertHook = () => {};
const RESEARCHER_TIMEOUT_MS = 30 * 60 * 1_000;
const RESEARCHER_PROMPT = [
	"Continue the parent scout's unresolved investigation.",
	"Return evidence-backed findings without starting another researcher.",
].join(" ");
const RECOVERY_PROMPT = [
	"Continue the parent agent's unresolved goal.",
	"Return evidence-backed findings without starting another recovery agent.",
].join(" ");

export function requestMetadata(context: RequestContext): RequestMetadata {
	const explicitSelector = context.explicitSelector === true || context.selector !== null && context.selector !== undefined;
	return {
		role: context.role,
		agent: context.agent,
		explicitSelector,
		selector: context.selector ?? null,
		overrideSource: context.overrideSource ?? null,
		project: context.project,
		session: context.session,
		clientFallback: [...(context.clientFallback ?? [])],
		directCloud: context.directCloud === true,
		manualCloud: context.manualCloud === true,
	};
}

export class OMPModelControlExtension {
	readonly budgets: BudgetManager;
	readonly containment: ContainmentDetector;
	readonly escalation: EscalationController;
	readonly recovery: RecoveryController;
	readonly policy: PolicyCache;
	private readonly eventSink: EventSink;
	private readonly transport: ControllerTransport | null;
	private readonly alert: AlertHook;
	private readonly clock: Clock;
	private readonly observeOnly: boolean;
	private initialization: Promise<void> | null = null;
	private syncChain: Promise<void> = Promise.resolve();

	constructor(options: ExtensionOptions = {}) {
		this.observeOnly = options.observeOnly ?? false;
		this.clock = options.clock ?? (() => Date.now());
		const eventStore = options.eventSink === undefined ? new EventStore({ path: options.eventPath, clock: this.clock }) : null;
		const rawEventSink = options.eventSink ?? eventStore?.asSink() ?? (async () => {});
		this.eventSink = async (event) => {
			try {
				await rawEventSink(event);
			} catch (error) {
				if (event.subject === "event_sink_failed") return;
				try {
					await rawEventSink({
						id: randomUUID(),
						time: new Date(this.clock()).toISOString(),
						subsystem: "extension",
						severity: "error",
						subject: "event_sink_failed",
						detail: { failedSubject: event.subject, reason: String(error) },
					});
				} catch {
					return;
				}
			}
		};
		this.budgets = new BudgetManager({
			limits: options.budgetLimits ?? options.budget?.limits,
			clock: this.clock,
			eventSink: this.eventSink,
		});
		this.containment = new ContainmentDetector({ ...options.containment, clock: options.containment?.clock ?? this.clock });
		this.policy = new PolicyCache({ ...options.policy, clock: options.policy?.clock ?? this.clock });
		this.transport = options.transport ?? null;
		this.alert = options.alert ?? noAlert;
		this.escalation = new EscalationController({
			...options.escalation,
			eventSink: options.escalation?.eventSink ?? this.eventSink,
			canStartResearcher: options.escalation?.canStartResearcher ?? ((request) => this.canStartResearcher(request)),
		});
		this.recovery = new RecoveryController({
			...options.recovery,
			eventSink: options.recovery?.eventSink ?? this.eventSink,
		});
	}

	async initialize(): Promise<void> {
		if (this.initialization === null) this.initialization = this.restorePolicy();
		await this.initialization;
	}

	async beforeRequest(context: RequestContext, estimatedTokens = 0): Promise<RequestAdmission> {
		await this.initialize();
		await this.syncNow();
		const metadata = requestMetadata(context);
		if (this.containment.isParked(context.transcriptId)) {
			if (this.observeOnly) {
				this.containment.resume(context.transcriptId);
				await this.emit("containment", "warning", "would_block_request", {
					agent: context.agent, project: context.project, transcriptId: context.transcriptId, reason: "transcript_parked",
				});
			} else {
				await this.emit("containment", "warning", "parked_request_blocked", {
					agent: context.agent, project: context.project, transcriptId: context.transcriptId,
				});
				await this.emitRequestObservation(context, metadata, false, "transcript_parked", estimatedTokens);
				return { allowed: false, metadata, reason: "transcript_parked", manual: metadata.explicitSelector || metadata.manualCloud };
			}
		}
		if (this.observeOnly) {
			const observation = this.budgets.observe(context, estimatedTokens);
			if (observation.manual) await this.emitManualWarning(context, metadata, { allowed: true, manual: true, reason: null });
			if (observation.wouldBlockReason !== null) {
				await this.emit("budget", "warning", "would_block_request", {
					agent: context.agent, project: context.project, transcriptId: context.transcriptId, reason: observation.wouldBlockReason,
				});
				if (context.role === "scout-bounded") {
					await this.emit("escalation", "warning", "would_escalate", {
						agent: context.agent, project: context.project, transcriptId: context.transcriptId, reason: observation.wouldBlockReason,
					});
				}
			}
			await this.emitRequestObservation(context, metadata, true, null, estimatedTokens);
			await this.budgets.flushEvents();
			return { allowed: true, metadata, reason: null, manual: observation.manual };
		}
		const budget = this.budgets.admit(context, estimatedTokens);
		if (budget.manual) await this.emitManualWarning(context, metadata, budget);
		await this.emitRequestObservation(context, metadata, budget.allowed, budget.reason, estimatedTokens);
		await this.budgets.flushEvents();
		return { allowed: budget.allowed, metadata, reason: budget.reason, manual: budget.manual };
	}

	async afterResponse(context: RequestContext, response: ResponseResult): Promise<ResponseObservation> {
		const consumedTokens = response.totalTokens ?? (response.inputTokens ?? 0) + (response.outputTokens ?? 0);
		this.budgets.consume(context.transcriptId, consumedTokens);
		if (context.directCloud === true) {
			await this.emit("usage", "info", "usage_observed", {
				provider: context.provider ?? null,
				accountLabel: context.accountLabel ?? null,
				consumedTokens,
				attribution: context.manualCloud === true || context.explicitSelector === true ? "manual" : "direct",
			});
		}
		const shouldEscalate = context.role === "scout-bounded" && this.budgets.isEnvelopeBreached(context);
		if (this.observeOnly && shouldEscalate) {
			await this.emit("escalation", "warning", "would_escalate", {
				agent: context.agent, project: context.project, transcriptId: context.transcriptId,
				reason: "envelope_breached",
			});
		}
		const escalation = shouldEscalate && !this.observeOnly ? await this.escalate(context) : null;
		const result = this.containment.observe(response.output, context.transcriptId, !this.observeOnly);
		if (!result.park) return { parked: false, alreadyParked: result.alreadyParked, consumedTokens, escalation, recovery: null };
		if (this.observeOnly) {
			const detail = {
				agent: context.agent,
				project: context.project,
				transcriptId: context.transcriptId,
				reason: "completion_equivalent_output",
			};
			await this.emit("containment", "warning", "would_park_transcript", { ...detail, consumedTokens });
			await this.emit("budget", "warning", "would_close_budget", detail);
			await this.emit("containment", "warning", "would_abort_request", detail);
			await this.emit("containment", "warning", "would_block_session_stop", detail);
			await this.emit("recovery", "warning", "would_spawn_recovery", detail);
			return { parked: false, alreadyParked: false, consumedTokens, escalation, recovery: null };
		}
		const recovery = await this.recover(context);
		const closure = this.budgets.close(context.transcriptId);
		const event = await this.emit("containment", "critical", "agent_parked", {
			agent: context.agent,
			project: context.project,
			transcriptId: context.transcriptId,
			consumedTokens: closure?.consumedTokens ?? consumedTokens,
			reason: "completion_equivalent_output",
		});
		try {
			await this.alert(event);
		} catch (error) {
			await this.emit("containment", "error", "alert_failed", { reason: String(error), agent: context.agent });
		}
		return { parked: true, alreadyParked: false, consumedTokens, escalation, recovery };
	}

	get isObserveOnly(): boolean {
		return this.observeOnly;
	}

	async escalate(context: RequestContext): Promise<EscalationResult> {
		const request: EscalationRequest = {
			transcriptId: context.transcriptId,
			agent: context.agent,
			project: context.project,
			provider: context.provider ?? null,
			cwd: context.cwd ?? null,
			sessionFile: context.sessionFile ?? null,
		};
		return this.escalation.escalate(request, context.role);
	}

	private async recover(context: RequestContext): Promise<RecoveryResult> {
		const request: EscalationRequest = {
			transcriptId: context.transcriptId,
			agent: context.agent,
			project: context.project,
			provider: context.provider ?? null,
			cwd: context.cwd ?? null,
			sessionFile: context.sessionFile ?? null,
		};
		return this.recovery.handoff(request, context.role);
	}

	resume(transcriptId: string): void {
		this.containment.resume(transcriptId);
		this.budgets.resume(transcriptId);
	}

	async syncNow(): Promise<void> {
		const sync = this.syncChain.then(() => this.syncOnce(), () => this.syncOnce());
		this.syncChain = sync.then(() => {}, () => {});
		await sync;
	}

	private async restorePolicy(): Promise<void> {
		const result = await this.policy.restoreLastKnownGood();
		if (result.restored) {
			const active = this.policy.currentPolicy();
			if (active !== null) await this.applyRuntimePolicy(active);
			return;
		}
		if (result.reason === "missing") return;
		await this.emit("policy", "warning", "policy_cache_restore_failed", { reason: result.reason });
	}

	private async syncOnce(): Promise<void> {
		if (this.transport === null) return;
		try {
			const bundle = await this.transport.fetchPolicy();
			if (bundle === null) return;
			const result = await this.policy.apply(bundle);
			if (!result.accepted) {
				await this.emit("policy", "warning", "policy_rejected", { reason: result.reason });
				return;
			}
			await this.applyRuntimePolicy(bundle);
		} catch (error) {
			await this.emit("policy", "error", "controller_sync_failed", { reason: String(error) });
		}
	}

	private async applyRuntimePolicy(bundle: SignedPolicyBundle): Promise<void> {
		const runtime = parseOMPRuntimePolicy(bundle.payload);
		if (runtime === undefined) return;
		if (runtime === null) {
			await this.emit("policy", "warning", "policy_runtime_invalid", { payloadDigest: bundle.payloadDigest });
			return;
		}
		if (runtime.budgets !== undefined) this.budgets.updateLimits(runtime.budgets);
		if (runtime.containment !== undefined) this.containment.updatePolicy(runtime.containment);
		await this.emit("policy", "info", "policy_runtime_applied", {
			payloadDigest: bundle.payloadDigest,
			sequence: bundle.sequence,
		});
	}

	private canStartResearcher(request: EscalationRequest): boolean {
		return this.budgets.admit({
			role: "researcher",
			agent: researcherAgentName(request.agent),
			project: request.project,
			session: null,
			transcriptId: `${request.transcriptId}:researcher`,
			provider: request.provider,
		}).allowed;
	}

	private async emitRequestObservation(
		context: RequestContext,
		metadata: RequestMetadata,
		allowed: boolean,
		reason: string | null,
		estimatedTokens: number,
	): Promise<void> {
		await this.emit("request", allowed ? "info" : "warning", "request_observed", {
			role: metadata.role,
			agent: metadata.agent,
			explicitSelector: metadata.explicitSelector,
			selector: metadata.selector,
			overrideSource: metadata.overrideSource,
			project: metadata.project,
			session: metadata.session,
			clientFallback: metadata.clientFallback,
			directCloud: metadata.directCloud,
			manualCloud: metadata.manualCloud,
			transcriptId: context.transcriptId,
			estimatedTokens,
			allowed,
			reason,
		});
	}

	private async emitManualWarning(
		context: RequestContext,
		metadata: RequestMetadata,
		budget: BudgetAdmission,
	): Promise<void> {
		await this.emit("request", "warning", "manual_selection_warning", {
			agent: context.agent,
			project: context.project,
			transcriptId: context.transcriptId,
			session: metadata.session,
			role: metadata.role,
			selector: metadata.selector,
			explicitSelector: metadata.explicitSelector,
			overrideSource: metadata.overrideSource,
			clientFallback: metadata.clientFallback,
			directCloud: metadata.directCloud,
			manualCloud: metadata.manualCloud,
			reason: budget.reason ?? "manual_selection",
		});
	}

	private async emit(
		subsystem: string,
		severity: ExtensionEvent["severity"],
		subject: string,
		detail: ExtensionEvent["detail"],
	): Promise<ExtensionEvent> {
		const event: ExtensionEvent = {
			id: randomUUID(),
			time: new Date(this.clock()).toISOString(),
			subsystem,
			severity,
			subject,
			detail,
		};
		await this.eventSink(event);
		return event;
	}
}

export interface OMPHookPayload {
	role?: string;
	agent?: string;
	project?: string | null;
	session?: string | null;
	selector?: string | null;
	explicitSelector?: boolean;
	overrideSource?: string | null;
	clientFallback?: string[];
	directCloud?: boolean;
	manualCloud?: boolean;
	automatic?: boolean;
	transcriptId?: string;
	provider?: string | null;
	estimatedTokens?: number;
	accountLabel?: string | null;
}

export interface OMPModel {
	provider: string;
	id: string;
}

export interface OMPMessageContent {
	type: string;
	text?: string;
}

export interface OMPMessageUsage {
	inputTokens?: number;
	outputTokens?: number;
	totalTokens?: number;
}

export interface OMPMessage {
	role: string;
	content: OMPMessageContent[];
	usage?: OMPMessageUsage;
}

export interface OMPHookContext {
	cwd: string;
	model?: OMPModel;
	role?: string;
	agent?: string;
	project?: string | null;
	session?: string | null;
	transcriptId?: string;
	sessionManager?: {
		getSessionId: () => string;
		getSessionFile: () => string | undefined;
	};
	ui: { notify: (message: string, type?: "info" | "warning" | "error") => void };
	abort: () => void;
}

export interface OMPEventPayloads {
	session_start: { type: "session_start" };
	before_provider_request: { type: "before_provider_request"; payload: OMPHookPayload };
	message_end: { type: "message_end"; message: OMPMessage };
	session_stop: { type: "session_stop" };
	input: { type: "input"; text: string; source: "interactive" | "rpc" | "extension" };
}

export interface OMPEventResults {
	session_start: void;
	before_provider_request: OMPHookPayload;
	message_end: void;
	session_stop: void | { decision: "block"; reason: string };
	input: void | { handled: boolean };
}

export type OMPEventName = keyof OMPEventPayloads;
export type OMPEventHandler<EventName extends OMPEventName> = (
	event: OMPEventPayloads[EventName],
	context: OMPHookContext,
) => OMPEventResults[EventName] | Promise<OMPEventResults[EventName]>;

export interface OMPCommandDefinition {
	description: string;
	handler: (args: string, context: OMPHookContext) => void | Promise<void>;
}

export interface OMPExecOptions {
	cwd?: string;
	signal?: AbortSignal;
	timeout?: number;
}

export interface OMPExecResult {
	stdout: string;
	stderr: string;
	code: number;
	killed: boolean;
}

export interface OMPEventApi {
	on: <EventName extends OMPEventName>(event: EventName, handler: OMPEventHandler<EventName>) => void;
	registerCommand?: (name: string, definition: OMPCommandDefinition) => void;
	exec: (command: string, args: string[], options?: OMPExecOptions) => Promise<OMPExecResult>;
}

export function loadOMPExtension(pi: OMPEventApi, options: ExtensionOptions = {}): OMPModelControlExtension {
	const extension = new OMPModelControlExtension({
		...options,
		observeOnly: options.observeOnly ?? true,
		escalation: {
			...options.escalation,
			startResearcher: options.escalation?.startResearcher ?? ompResearcherStarter(pi),
		},
		recovery: {
			...options.recovery,
			startRecovery: options.recovery?.startRecovery ?? ompRecoveryStarter(pi),
		},
	});
	const requests = new Map<string, RequestContext>();
	const manualSelections = new Set<string>();

	pi.on("session_start", async () => {
		await extension.initialize();
	});
	pi.on("input", (event, context) => {
		const transcriptId = sessionId(context);
		if (/^\/model(?:\s|$)/u.test(event.text.trim())) manualSelections.add(transcriptId);
		if (extension.isObserveOnly || !extension.containment.isParked(transcriptId)) return;
		context.ui.notify("This transcript is parked. Run /modelctl-resume to continue.", "warning");
		return { handled: true };
	});
	pi.on("before_provider_request", async (event, context) => {
		const transcriptId = sessionId(context);
		const request = requestContext(event.payload, context, manualSelections.has(transcriptId));
		requests.set(transcriptId, request);
		const admission = await extension.beforeRequest(request, tokenEstimate(event.payload));
		if (!extension.isObserveOnly && !admission.allowed) {
			context.ui.notify(`Model request blocked: ${admission.reason ?? "policy"}`, "warning");
			context.abort();
		}
		return event.payload;
	});
	pi.on("message_end", async (event, context) => {
		if (event.message.role !== "assistant") return;
		const transcriptId = sessionId(context);
		const request = requests.get(transcriptId) ?? requestContext({}, context, manualSelections.has(transcriptId));
		const response = responseResult(event.message);
		if (response === null) return;
		const observation = await extension.afterResponse(request, response);
		if (observation.escalation?.started === true && observation.escalation.researcherTranscriptId !== null) {
			context.ui.notify(
				`modelctl started researcher transcript ${observation.escalation.researcherTranscriptId}.`,
				"info",
			);
		} else if (observation.escalation !== null) {
			context.ui.notify(
				`modelctl could not start a researcher: ${observation.escalation.reason ?? "unknown"}.`,
				"warning",
			);
		}
		if (extension.isObserveOnly || !observation.parked) return;
		context.ui.notify("Repeated completion-equivalent output parked this transcript.", "error");
		context.abort();
	});
	pi.on("session_stop", async (_event, context) => {
		await extension.syncNow();
		const transcriptId = sessionId(context);
		if (extension.isObserveOnly || !extension.containment.isParked(transcriptId)) return;
		return { decision: "block", reason: "Transcript parked by modelctl loop containment." };
	});
	pi.registerCommand?.("modelctl-resume", {
		description: "Resume a transcript parked by modelctl",
		handler: (_args, context) => {
			extension.resume(sessionId(context));
			context.ui.notify("modelctl resumed this transcript.", "info");
		},
	});
	return extension;
}

export default function load(pi: OMPEventApi): OMPModelControlExtension {
	return loadOMPExtension(pi);
}

interface OMPSessionEvent {
	type?: string;
	version?: number;
	id?: string;
}

export function parseResearcherSessionId(output: string): string | null {
	for (const line of output.split(/\r?\n/u)) {
		if (line.trim().length === 0) continue;
		try {
			const parsed: unknown = JSON.parse(line);
			if (Object.prototype.toString.call(parsed) !== "[object Object]") continue;
			// SAFETY: JSON.parse returned a plain object. Each field is checked before use.
			const event = parsed as OMPSessionEvent;
			if (event.type !== "session" || event.version !== 3) continue;
			if (Object.prototype.toString.call(event.id) !== "[object String]") continue;
			const id = String(event.id).trim();
			if (id.length > 0) return id;
		} catch {
			continue;
		}
	}
	return null;
}

function ompResearcherStarter(pi: OMPEventApi): (request: EscalationRequest) => Promise<string> {
	return ompForkStarter(pi, "researcher", researcherAgentName, RESEARCHER_PROMPT);
}

function ompRecoveryStarter(pi: OMPEventApi): (request: EscalationRequest) => Promise<string> {
	return ompForkStarter(pi, "recovery", recoveryAgentName, RECOVERY_PROMPT);
}

function ompForkStarter(
	pi: OMPEventApi,
	role: "researcher" | "recovery",
	name: (agent: string) => string,
	prompt: string,
): (request: EscalationRequest) => Promise<string> {
	return async (request) => {
		if (request.cwd === null) throw new Error(`${role}_working_directory_unavailable`);
		if (request.sessionFile === null || !isAbsolute(request.sessionFile)) throw new Error("parent_session_file_unavailable");
		const result = await pi.exec("env", [
			`OMP_AGENT_ROLE=${role}`,
			`OMP_AGENT_NAME=${name(request.agent)}`,
			"omp",
			"-p",
			"--mode",
			"json",
			"--model",
			"slow",
			"--thinking",
			"high",
			"--fork",
			request.sessionFile,
			prompt,
		], { cwd: request.cwd, timeout: RESEARCHER_TIMEOUT_MS });
		if (result.killed) throw new Error(`${role}_process_killed`);
		if (result.code !== 0) throw new Error(`${role}_process_exit_${result.code}`);
		return parseResearcherSessionId(result.stdout) ?? "";
	};
}

function researcherAgentName(agent: string): string {
	return `${agent}:researcher`;
}

function recoveryAgentName(agent: string): string {
	return `${agent}:recovery`;
}

function requestContext(payload: OMPHookPayload, context: OMPHookContext, manualSelection: boolean): RequestContext {
	const transcriptId = sessionId(context);
	const selector = payload.selector ?? (context.model === undefined ? null : `${context.model.provider}/${context.model.id}`);
	return {
		role: payload.role ?? process.env.OMP_AGENT_ROLE ?? context.role ?? "task",
		agent: payload.agent ?? process.env.OMP_AGENT_NAME ?? context.agent ?? "main",
		project: payload.project ?? context.project ?? context.cwd,
		session: payload.session ?? context.session ?? transcriptId,
		cwd: context.cwd,
		sessionFile: context.sessionManager?.getSessionFile() ?? null,
		selector,
		explicitSelector: payload.explicitSelector === true || manualSelection,
		overrideSource: payload.overrideSource ?? (manualSelection ? "interactive-command" : null),
		clientFallback: [...(payload.clientFallback ?? [])],
		directCloud: payload.directCloud === true,
		manualCloud: payload.manualCloud === true || manualSelection && payload.directCloud === true,
		automatic: payload.automatic !== false && !manualSelection,
		transcriptId: payload.transcriptId ?? transcriptId,
		provider: payload.provider ?? context.model?.provider ?? null,
		accountLabel: payload.accountLabel ?? process.env.MODELCTL_ACCOUNT_LABEL ?? null,
	};
}

function responseResult(message: OMPMessage): ResponseResult | null {
	const output = message.content.filter((item) => item.type === "text").map((item) => item.text ?? "").join("");
	if (output.length === 0) return null;
	return {
		output,
		inputTokens: message.usage?.inputTokens,
		outputTokens: message.usage?.outputTokens,
		totalTokens: message.usage?.totalTokens,
	};
}

function tokenEstimate(payload: OMPHookPayload): number {
	return payload.estimatedTokens ?? 0;
}

function sessionId(context: OMPHookContext): string {
	return context.sessionManager?.getSessionId() ?? context.transcriptId ?? context.session ?? randomUUID();
}


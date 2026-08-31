import { randomUUID } from "node:crypto";
import type {
	EscalationRequest,
	EscalationResult,
	EventSink,
	ExtensionEvent,
	RecoveryResult,
} from "./types";

export interface EscalationOptions {
	canStartResearcher?: (request: EscalationRequest) => boolean | Promise<boolean>;
	startResearcher?: (request: EscalationRequest) => string | Promise<string>;
	eventSink?: EventSink;
}

export interface RecoveryOptions {
	startRecovery?: (request: EscalationRequest) => string | Promise<string>;
	eventSink?: EventSink;
}

const permitResearcher: (request: EscalationRequest) => boolean = () => true;
const ignoreEvent: EventSink = async () => {};

export class EscalationController {
	private readonly canStartResearcher: (request: EscalationRequest) => boolean | Promise<boolean>;
	private readonly startResearcher: ((request: EscalationRequest) => string | Promise<string>) | null;
	private readonly eventSink: EventSink;
	private readonly escalatedScouts = new Set<string>();

	constructor(options: EscalationOptions = {}) {
		this.canStartResearcher = options.canStartResearcher ?? permitResearcher;
		this.startResearcher = options.startResearcher ?? null;
		this.eventSink = options.eventSink ?? ignoreEvent;
	}

	async escalate(request: EscalationRequest, role: string): Promise<EscalationResult> {
		if (role !== "scout-bounded") {
			await this.record(request, "warning", "researcher_escalation_blocked", "role_not_escalatable");
			return { started: false, blocked: true, reason: "role_not_escalatable", researcherTranscriptId: null };
		}
		if (this.escalatedScouts.has(request.transcriptId)) {
			await this.record(request, "warning", "researcher_escalation_blocked", "scout_already_escalated");
			return { started: false, blocked: true, reason: "scout_already_escalated", researcherTranscriptId: null };
		}
		this.escalatedScouts.add(request.transcriptId);
		if (!(await this.canStartResearcher(request))) {
			await this.record(request, "warning", "researcher_escalation_blocked", "budget_refused");
			return { started: false, blocked: true, reason: "budget_refused", researcherTranscriptId: null };
		}
		if (this.startResearcher === null) {
			await this.record(request, "error", "researcher_escalation_blocked", "researcher_start_unavailable");
			return { started: false, blocked: true, reason: "researcher_start_unavailable", researcherTranscriptId: null };
		}
		try {
			const researcherTranscriptId = await this.startResearcher(request);
			if (researcherTranscriptId.trim().length === 0) {
				await this.record(request, "error", "researcher_escalation_blocked", "researcher_start_invalid_id");
				return { started: false, blocked: true, reason: "researcher_start_invalid_id", researcherTranscriptId: null };
			}
			await this.record(request, "info", "researcher_escalation_started", null, researcherTranscriptId);
			return { started: true, blocked: false, reason: null, researcherTranscriptId };
		} catch (error) {
			const failure = error instanceof Error ? error.message : String(error);
			await this.record(request, "error", "researcher_escalation_blocked", "researcher_start_failed", undefined, failure);
			return { started: false, blocked: true, reason: "researcher_start_failed", researcherTranscriptId: null };
		}
	}

	private async record(
		request: EscalationRequest,
		severity: "info" | "warning" | "error",
		subject: string,
		reason: string | null,
		researcherTranscriptId?: string,
		failure?: string,
	): Promise<void> {
		const detail: ExtensionEvent["detail"] = {
			agent: request.agent,
			project: request.project,
			transcriptId: request.transcriptId,
			reason,
		};
		if (researcherTranscriptId !== undefined) detail.researcherTranscriptId = researcherTranscriptId;
		if (failure !== undefined) detail.failure = failure;
		try {
			await this.eventSink({
				id: randomUUID(),
				time: new Date().toISOString(),
				subsystem: "escalation",
				severity,
				subject,
				detail,
			});
		} catch {
			return;
		}
	}
}

export class RecoveryController {
	private readonly startRecovery: ((request: EscalationRequest) => string | Promise<string>) | null;
	private readonly eventSink: EventSink;
	private readonly handedOff = new Set<string>();

	constructor(options: RecoveryOptions = {}) {
		this.startRecovery = options.startRecovery ?? null;
		this.eventSink = options.eventSink ?? ignoreEvent;
	}

	async handoff(request: EscalationRequest, role: string): Promise<RecoveryResult> {
		if (role === "recovery" || request.agent.endsWith(":recovery")) {
			await this.record(request, "warning", "recovery_handoff_blocked", "recursive_recovery");
			return { started: false, blocked: true, reason: "recursive_recovery", recoveryTranscriptId: null };
		}
		if (this.handedOff.has(request.transcriptId)) {
			await this.record(request, "warning", "recovery_handoff_blocked", "recovery_already_started");
			return { started: false, blocked: true, reason: "recovery_already_started", recoveryTranscriptId: null };
		}
		this.handedOff.add(request.transcriptId);
		if (this.startRecovery === null) {
			await this.record(request, "error", "recovery_handoff_blocked", "recovery_start_unavailable");
			return { started: false, blocked: true, reason: "recovery_start_unavailable", recoveryTranscriptId: null };
		}
		try {
			const recoveryTranscriptId = await this.startRecovery(request);
			if (recoveryTranscriptId.trim().length === 0) {
				await this.record(request, "error", "recovery_handoff_blocked", "recovery_start_invalid_id");
				return { started: false, blocked: true, reason: "recovery_start_invalid_id", recoveryTranscriptId: null };
			}
			await this.record(request, "info", "recovery_handoff_started", null, recoveryTranscriptId);
			return { started: true, blocked: false, reason: null, recoveryTranscriptId };
		} catch (error) {
			const failure = error instanceof Error ? error.message : String(error);
			await this.record(request, "error", "recovery_handoff_blocked", "recovery_start_failed", undefined, failure);
			return { started: false, blocked: true, reason: "recovery_start_failed", recoveryTranscriptId: null };
		}
	}

	private async record(
		request: EscalationRequest,
		severity: "info" | "warning" | "error",
		subject: string,
		reason: string | null,
		recoveryTranscriptId?: string,
		failure?: string,
	): Promise<void> {
		const detail: ExtensionEvent["detail"] = {
			agent: request.agent,
			project: request.project,
			transcriptId: request.transcriptId,
			reason,
		};
		if (recoveryTranscriptId !== undefined) detail.recoveryTranscriptId = recoveryTranscriptId;
		if (failure !== undefined) detail.failure = failure;
		try {
			await this.eventSink({
				id: randomUUID(),
				time: new Date().toISOString(),
				subsystem: "recovery",
				severity,
				subject,
				detail,
			});
		} catch {
			return;
		}
	}
}

import { describe, expect, test } from "bun:test";
import {
	loadOMPExtension,
	parseResearcherSessionId,
	type OMPCommandDefinition,
	type OMPEventApi,
	type OMPEventHandler,
	type OMPEventName,
	type OMPExecResult,
	type OMPHookContext,
} from "../src/index";
import type { BudgetLimits, ExtensionEvent } from "../src/types";

type HandlerRegistry = { [EventName in OMPEventName]: OMPEventHandler<EventName> };

interface HarnessOptions {
	threshold?: number;
	role?: string;
	budgetLimits?: BudgetLimits;
	execResult?: OMPExecResult;
}

function harness(options: HarnessOptions = {}) {
	const notRegistered = async (): Promise<never> => { throw new Error("OMP handler was not registered"); };
	const handlers: HandlerRegistry = {
		session_start: notRegistered,
		input: notRegistered,
		before_provider_request: notRegistered,
		message_end: notRegistered,
		session_stop: notRegistered,
	};
	const commands = new Map<string, OMPCommandDefinition>();
	const events: ExtensionEvent[] = [];
	const notifications: string[] = [];
	const executions: Array<{ command: string; args: string[]; timeout?: number; cwd?: string }> = [];
	let abortCount = 0;
	const api: OMPEventApi = {
		on: (event, handler) => { Object.assign(handlers, { [event]: handler }); },
		registerCommand: (name, definition) => { commands.set(name, definition); },
		exec: async (command, args, execOptions) => {
			executions.push({ command, args, timeout: execOptions?.timeout, cwd: execOptions?.cwd });
			return options.execResult ?? { stdout: "", stderr: "", code: 0, killed: false };
		},
	};
	const context: OMPHookContext = {
		cwd: "/fixture-project",
		role: options.role ?? "task",
		agent: "fixture-agent",
		sessionManager: {
			getSessionId: () => "fixture-session",
			getSessionFile: () => "/sessions/fixture-session.jsonl",
		},
		model: { provider: "fixture-provider", id: "fixture-model" },
		ui: { notify: (message) => { notifications.push(message); } },
		abort: () => { abortCount += 1; },
	};
	const extension = loadOMPExtension(api, {
		observeOnly: false,
		budgetLimits: options.budgetLimits,
		containment: { threshold: options.threshold },
		eventSink: async (event) => { events.push(event); },
		policy: {
			fileSystem: {
				readFile: async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); },
				makeDirectory: async () => {},
			},
			cachePath: "/not-used/modelctl-policy.json",
		},
	});
	return {
		handlers,
		commands,
		context,
		events,
		executions,
		extension,
		notifications,
		abortCount: () => abortCount,
	};
}

describe("OMP runtime adapter", () => {
	test("attributes an interactive model selection through the real provider hook", async () => {
		const fixture = harness();
		await fixture.handlers.input({ type: "input", text: "/model fixture-provider/fixture-model", source: "interactive" }, fixture.context);
		await fixture.handlers.before_provider_request({
			type: "before_provider_request",
			payload: { estimatedTokens: 4, directCloud: true, accountLabel: "primary" },
		}, fixture.context);
		await fixture.handlers.message_end({
			type: "message_end",
			message: {
				role: "assistant",
				content: [{ type: "text", text: "done" }],
				usage: { totalTokens: 9 },
			},
		}, fixture.context);

		const warning = fixture.events.find((event) => event.subject === "manual_selection_warning");
		expect(warning?.detail).toMatchObject({
			agent: "fixture-agent",
			project: "/fixture-project",
			transcriptId: "fixture-session",
			selector: "fixture-provider/fixture-model",
			explicitSelector: true,
			overrideSource: "interactive-command",
			directCloud: true,
			manualCloud: true,
		});
		expect(fixture.events.find((event) => event.subject === "usage_observed")?.detail).toEqual({
			provider: "fixture-provider",
			accountLabel: "primary",
			consumedTokens: 9,
			attribution: "manual",
		});
		expect(fixture.abortCount()).toBe(0);
	});

	test("parks repeated output and resumes only through the registered command", async () => {
		const fixture = harness({ threshold: 2 });
		await fixture.handlers.before_provider_request({ type: "before_provider_request", payload: {} }, fixture.context);
		const message = {
			type: "message_end" as const,
			message: { role: "assistant", content: [{ type: "text", text: "same answer" }], usage: { totalTokens: 3 } },
		};
		await fixture.handlers.message_end(message, fixture.context);
		await fixture.handlers.message_end(message, fixture.context);

		expect(fixture.extension.containment.isParked("fixture-session")).toBe(true);
		expect(fixture.abortCount()).toBe(1);
		expect(await fixture.handlers.session_stop({ type: "session_stop" }, fixture.context)).toEqual({
			decision: "block",
			reason: "Transcript parked by modelctl loop containment.",
		});
		expect(await fixture.handlers.input({ type: "input", text: "continue", source: "interactive" }, fixture.context)).toEqual({ handled: true });

		const resume = fixture.commands.get("modelctl-resume");
		expect(resume).toBeDefined();
		await resume?.handler("", fixture.context);
		expect(fixture.extension.containment.isParked("fixture-session")).toBe(false);
		expect(await fixture.handlers.session_stop({ type: "session_stop" }, fixture.context)).toBeUndefined();
	});

	test("parses only the current OMP session event", () => {
		expect(parseResearcherSessionId([
			"not json",
			JSON.stringify({ type: "session", version: 3, id: "researcher-session" }),
		].join("\n"))).toBe("researcher-session");
		expect(parseResearcherSessionId(JSON.stringify({ type: "session", version: 2, id: "old-session" }))).toBeNull();
		expect(parseResearcherSessionId(JSON.stringify({ type: "message", version: 3, id: "message-id" }))).toBeNull();
	});

	test("starts one forked researcher after a scout breaches its agent budget", async () => {
		const fixture = harness({
			role: "scout-bounded",
			budgetLimits: { agent: { "fixture-agent": 1 } },
			execResult: {
				stdout: `${JSON.stringify({ type: "session", version: 3, id: "researcher-session" })}\n`,
				stderr: "",
				code: 0,
				killed: false,
			},
		});
		await fixture.handlers.before_provider_request({
			type: "before_provider_request",
			payload: {},
		}, fixture.context);

		await fixture.handlers.message_end({
			type: "message_end",
			message: {
				role: "assistant",
				content: [{ type: "text", text: "research result" }],
				usage: { totalTokens: 2 },
			},
		}, fixture.context);

		expect(fixture.executions).toHaveLength(1);
		expect(fixture.executions[0]).toEqual({
			command: "env",
			args: [
				"OMP_AGENT_ROLE=researcher",
				"OMP_AGENT_NAME=fixture-agent:researcher",
				"omp",
				"-p",
				"--mode",
				"json",
				"--model",
				"slow",
				"--thinking",
				"high",
				"--fork",
				"/sessions/fixture-session.jsonl",
				"Continue the parent scout's unresolved investigation. Return evidence-backed findings without starting another researcher.",
			],
			timeout: 1_800_000,
			cwd: "/fixture-project",
		});
		expect(fixture.events.find((event) => event.subject === "researcher_escalation_started")?.detail)
			.toMatchObject({ researcherTranscriptId: "researcher-session" });
		expect(fixture.notifications).toContain("modelctl started researcher transcript researcher-session.");
	});

	test("records failed and malformed researcher processes as blocked", async () => {
		const cases = [
			{
				result: { stdout: "", stderr: "", code: 7, killed: false },
				reason: "researcher_start_failed",
				failure: "researcher_process_exit_7",
			},
			{
				result: { stdout: `${JSON.stringify({ type: "message", version: 3 })}\n`, stderr: "", code: 0, killed: false },
				reason: "researcher_start_invalid_id",
				failure: undefined,
			},
		];

		for (const item of cases) {
			const fixture = harness({
				role: "scout-bounded",
				budgetLimits: { agent: { "fixture-agent": 1 } },
				execResult: item.result,
			});
			await fixture.handlers.before_provider_request({
				type: "before_provider_request",
				payload: {},
			}, fixture.context);
			await fixture.handlers.message_end({
				type: "message_end",
				message: {
					role: "assistant",
					content: [{ type: "text", text: "research result" }],
					usage: { totalTokens: 2 },
				},
			}, fixture.context);

			const blocked = fixture.events.find((event) => event.subject === "researcher_escalation_blocked");
			expect(blocked?.detail.reason).toBe(item.reason);
			expect(blocked?.detail.failure).toBe(item.failure);
			expect(blocked?.detail).not.toHaveProperty("researcherTranscriptId");
			expect(fixture.notifications).toContain(`modelctl could not start a researcher: ${item.reason}.`);
		}
	});
});

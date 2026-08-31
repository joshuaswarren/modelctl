import { describe, expect, test } from "bun:test";
import {
	loadOMPExtension,
	type OMPEventApi,
	type OMPEventHandler,
	type OMPEventName,
	type OMPExecResult,
	type OMPHookContext,
} from "../src/index";
import type { BudgetLimits, ExtensionEvent, RequestContext } from "../src/types";

type HandlerRegistry = { [EventName in OMPEventName]: OMPEventHandler<EventName> };

function harness(options: {
	threshold?: number;
	role?: string;
	budgetLimits?: BudgetLimits;
	execResult?: OMPExecResult;
	observeOnly?: boolean;
} = {}) {
	const notRegistered = async (): Promise<never> => { throw new Error("OMP handler was not registered"); };
	const handlers: HandlerRegistry = {
		session_start: notRegistered,
		input: notRegistered,
		before_provider_request: notRegistered,
		message_end: notRegistered,
		session_stop: notRegistered,
	};
	const events: ExtensionEvent[] = [];
	const executions: Array<{ command: string; args: string[]; timeout?: number; cwd?: string }> = [];
	let abortCount = 0;
	const context: OMPHookContext = {
		cwd: "/fixture-project",
		role: options.role ?? "task",
		agent: "fixture-agent",
		sessionManager: {
			getSessionId: () => "fixture-session",
			getSessionFile: () => "/sessions/fixture-session.jsonl",
		},
		model: { provider: "fixture-provider", id: "fixture-model" },
		ui: { notify: () => {} },
		abort: () => { abortCount += 1; },
	};
	const api: OMPEventApi = {
		on: (event, handler) => { Object.assign(handlers, { [event]: handler }); },
		exec: async (command, args, execOptions) => {
			executions.push({ command, args, timeout: execOptions?.timeout, cwd: execOptions?.cwd });
			return options.execResult ?? { stdout: "", stderr: "", code: 0, killed: false };
		},
	};
	const extension = loadOMPExtension(api, {
		observeOnly: options.observeOnly,
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
	const request: RequestContext = {
		role: options.role ?? "task",
		agent: "fixture-agent",
		project: "/fixture-project",
		session: "fixture-session",
		transcriptId: "fixture-session",
		provider: "fixture-provider",
	};
	return { handlers, context, request, events, executions, extension, abortCount: () => abortCount };
}

const repeatedMessage = {
	type: "message_end" as const,
	message: { role: "assistant", content: [{ type: "text", text: "same answer" }], usage: { totalTokens: 3 } },
};

describe("installed OMP extension safety", () => {
	test("observes containment without blocking, parking, closing, or aborting", async () => {
		const fixture = harness({ threshold: 2 });

		await fixture.handlers.before_provider_request({ type: "before_provider_request", payload: {} }, fixture.context);
		await fixture.handlers.message_end(repeatedMessage, fixture.context);
		await fixture.handlers.message_end(repeatedMessage, fixture.context);

		expect(fixture.extension.containment.isParked("fixture-session")).toBe(false);
		expect(fixture.extension.budgets.isClosed("fixture-session")).toBe(false);
		expect((await fixture.extension.beforeRequest(fixture.request)).allowed).toBe(true);
		expect(fixture.abortCount()).toBe(0);
		expect(await fixture.handlers.session_stop({ type: "session_stop" }, fixture.context)).toBeUndefined();
		for (const subject of ["would_park_transcript", "would_close_budget", "would_abort_request", "would_block_session_stop", "would_spawn_recovery"]) {
			expect(fixture.events.some((event) => event.subject === subject)).toBe(true);
		}
	});

	test("observes budget and escalation actions without blocking or spawning", async () => {
		const fixture = harness({
			role: "scout-bounded",
			budgetLimits: { agent: { "fixture-agent": 1 } },
		});

		const admission = await fixture.handlers.before_provider_request({
			type: "before_provider_request",
			payload: { estimatedTokens: 2 },
		}, fixture.context);
		await fixture.handlers.message_end({
			type: "message_end",
			message: { role: "assistant", content: [{ type: "text", text: "research result" }], usage: { totalTokens: 2 } },
		}, fixture.context);

		expect(admission).toEqual({ estimatedTokens: 2 });
		expect((await fixture.extension.beforeRequest(fixture.request, 2)).allowed).toBe(true);
		expect(fixture.executions).toHaveLength(0);
		expect(fixture.events.some((event) => event.subject === "would_block_request")).toBe(true);
		expect(fixture.events.some((event) => event.subject === "would_escalate")).toBe(true);
	});
});

describe("enforced containment recovery", () => {
	test("forks one bounded recovery agent when containment parks", async () => {
		const fixture = harness({
			threshold: 2,
			observeOnly: false,
			execResult: {
				stdout: "{\"type\":\"session\",\"version\":3,\"id\":\"recovery-session\"}\n",
				stderr: "",
				code: 0,
				killed: false,
			},
		});

		await fixture.handlers.before_provider_request({ type: "before_provider_request", payload: {} }, fixture.context);
		await fixture.handlers.message_end(repeatedMessage, fixture.context);
		await fixture.handlers.message_end(repeatedMessage, fixture.context);

		expect(fixture.extension.containment.isParked("fixture-session")).toBe(true);
		expect(fixture.executions).toHaveLength(1);
		expect(fixture.executions[0]?.args).toEqual([
			"OMP_AGENT_ROLE=recovery",
			"OMP_AGENT_NAME=fixture-agent:recovery",
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
			"Continue the parent agent's unresolved goal. Return evidence-backed findings without starting another recovery agent.",
		]);
		expect(fixture.events.some((event) => event.subject === "recovery_handoff_started")).toBe(true);
	});

	test("does not hand off a recovery agent recursively", async () => {
		const fixture = harness({ threshold: 1, observeOnly: false });
		fixture.context.role = "recovery";
		fixture.context.agent = "fixture-agent:recovery";

		await fixture.handlers.before_provider_request({ type: "before_provider_request", payload: {} }, fixture.context);
		await fixture.handlers.message_end(repeatedMessage, fixture.context);

		expect(fixture.executions).toHaveLength(0);
		expect(fixture.events.find((event) => event.subject === "recovery_handoff_blocked")?.detail.reason)
			.toBe("recursive_recovery");
	});
});

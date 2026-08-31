import { describe, expect, test } from "bun:test";
import {
	loadOMPExtension,
	type OMPEventApi,
	type OMPEventHandler,
	type OMPEventName,
	type OMPHookContext,
} from "../src/index";
import type { ExtensionEvent } from "../src/types";

type Handlers = { [Name in OMPEventName]: OMPEventHandler<Name> };

const missing = async (): Promise<never> => { throw new Error("handler missing"); };

function harness(agent = "fixture-agent") {
	const handlers: Handlers = {
		session_start: missing,
		input: missing,
		before_provider_request: missing,
		message_end: missing,
		session_stop: missing,
	};
	const events: ExtensionEvent[] = [];
	const executions: string[][] = [];
	const api: OMPEventApi = {
		on: (name, handler) => { Object.assign(handlers, { [name]: handler }); },
		exec: async (_command, args) => {
			executions.push(args);
			return {
				stdout: `${JSON.stringify({ type: "session", version: 3, id: "recovery-session" })}\n`,
				stderr: "",
				code: 0,
				killed: false,
			};
		},
	};
	const context: OMPHookContext = {
		cwd: "/fixture-project",
		role: "task",
		agent,
		sessionManager: {
			getSessionId: () => "parent-session",
			getSessionFile: () => "/sessions/parent-session.jsonl",
		},
		ui: { notify: () => {} },
		abort: () => {},
	};
	loadOMPExtension(api, {
		observeOnly: false,
		containment: { threshold: 2 },
		eventSink: async (event) => { events.push(event); },
		policy: {
			fileSystem: {
				readFile: async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); },
				makeDirectory: async () => {},
			},
			cachePath: "/not-used/modelctl-policy.json",
		},
	});
	return { handlers, context, events, executions };
}

const repeated = {
	type: "message_end" as const,
	message: { role: "assistant", content: [{ type: "text", text: "same answer" }], usage: { totalTokens: 3 } },
};

describe("parked-session recovery", () => {
	test("forks the parent once and records the recovery transcript", async () => {
		const fixture = harness();
		await fixture.handlers.before_provider_request({ type: "before_provider_request", payload: {} }, fixture.context);
		await fixture.handlers.message_end(repeated, fixture.context);
		await fixture.handlers.message_end(repeated, fixture.context);

		expect(fixture.executions).toHaveLength(1);
		expect(fixture.executions[0]).toContain("--fork");
		expect(fixture.executions[0]).toContain("/sessions/parent-session.jsonl");
		expect(fixture.events.find((event) => event.subject === "recovery_handoff_started")?.detail).toMatchObject({
			transcriptId: "parent-session",
			recoveryTranscriptId: "recovery-session",
		});
	});

	test("does not recurse from a recovery agent", async () => {
		const fixture = harness("fixture-agent:recovery");
		await fixture.handlers.before_provider_request({ type: "before_provider_request", payload: {} }, fixture.context);
		await fixture.handlers.message_end(repeated, fixture.context);
		await fixture.handlers.message_end(repeated, fixture.context);
		expect(fixture.executions).toHaveLength(0);
	});
});

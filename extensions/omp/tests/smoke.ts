import {
	loadOMPExtension,
	type OMPEventApi,
	type OMPEventHandler,
	type OMPEventName,
	type OMPHookContext,
} from "../src/index";

type HandlerRegistry = { [EventName in OMPEventName]: OMPEventHandler<EventName> };
const notRegistered = async (): Promise<never> => { throw new Error("OMP handler was not registered"); };
const handlers: HandlerRegistry = {
	session_start: notRegistered,
	input: notRegistered,
	before_provider_request: notRegistered,
	message_end: notRegistered,
	session_stop: notRegistered,
};
const registered = new Set<OMPEventName>();
const api: OMPEventApi = {
	on: (event, handler) => {
		Object.assign(handlers, { [event]: handler });
		registered.add(event);
	},
	exec: async () => ({ stdout: "", stderr: "", code: 0, killed: false }),
};
const notifications: string[] = [];
let aborted = false;
const context: OMPHookContext = {
	cwd: "/smoke-project",
	role: "task",
	agent: "smoke-agent",
	sessionManager: {
		getSessionId: () => "smoke-transcript",
		getSessionFile: () => "/sessions/smoke-transcript.jsonl",
	},
	model: { provider: "smoke-provider", id: "smoke-model" },
	ui: { notify: (message) => { notifications.push(message); } },
	abort: () => { aborted = true; },
};
const extension = loadOMPExtension(api, {
	eventSink: async () => {},
	policy: {
		fileSystem: {
			readFile: async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); },
			makeDirectory: async () => {},
		},
		cachePath: "/not-used/modelctl-policy.json",
	},
});

const expectedHooks: OMPEventName[] = [
	"session_start",
	"input",
	"before_provider_request",
	"message_end",
	"session_stop",
];
if (expectedHooks.some((hook) => !registered.has(hook))) throw new Error("required OMP hooks were not registered");

const start = handlers.session_start;
const beforeRequest = handlers.before_provider_request;
const messageEnd = handlers.message_end;
const stop = handlers.session_stop;

await start({ type: "session_start" }, context);
await beforeRequest({ type: "before_provider_request", payload: { estimatedTokens: 1 } }, context);
await messageEnd({
	type: "message_end",
	message: { role: "assistant", content: [{ type: "text", text: "ok" }], usage: { totalTokens: 1 } },
}, context);
await stop({ type: "session_stop" }, context);

if (aborted) throw new Error("synthetic request was aborted");
if (notifications.length !== 0) throw new Error("synthetic request produced an unexpected notification");
if (extension.budgets.usageSnapshot().agent["smoke-agent"] !== 1) throw new Error("synthetic usage was not metered");
console.log(JSON.stringify({ loaded: true, hooks: expectedHooks, meteredTokens: 1 }));

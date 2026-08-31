import { generateKeyPairSync, sign as signData, type KeyObject } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { OMPModelControlExtension } from "../src/index";
import { PolicyCache, policyId, signingContent, type SignedPolicyBundle } from "../src/policyCache";
import type { ExtensionEvent, FileSystem, JsonValue, RequestContext } from "../src/types";

type EventList = ExtensionEvent[];

type SignedFixture = {
	bundle: SignedPolicyBundle;
	publicKey: KeyObject;
	privateKey: KeyObject;
};

function context(overrides: Partial<RequestContext> = {}): RequestContext {
	return {
		role: "task",
		agent: "agent-a",
		project: "project-a",
		session: "session-a",
		transcriptId: "transcript-a",
		provider: "provider-a",
		...overrides,
	};
}

function signedBundle(sequence: number, payload: { [key: string]: JsonValue }): SignedFixture {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const bundle: SignedPolicyBundle = {
		keyId: "key-1",
		issuedAt: "1970-01-01T00:00:01Z",
		expiresAt: "1970-01-01T00:00:10Z",
		nonce: `nonce-${sequence}`,
		sequence,
		payloadDigest: policyId(payload),
		signature: "",
		payload,
	};
	bundle.signature = signData(null, signingContent(bundle), privateKey).toString("base64");
	return { bundle, publicKey, privateKey };
}

function resign(bundle: SignedPolicyBundle, privateKey: KeyObject, changes: Partial<SignedPolicyBundle>): SignedPolicyBundle {
	const candidate = { ...bundle, ...changes, signature: "" };
	candidate.payloadDigest = policyId(candidate.payload);
	candidate.signature = signData(null, signingContent(candidate), privateKey).toString("base64");
	return candidate;
}

describe("U5 hardening", () => {
	test("invokes the injected researcher starter and returns its transcript ID", async () => {
		const events: EventList = [];
		let starts = 0;
		const extension = new OMPModelControlExtension({
			eventSink: async (event) => { events.push(event); },
			escalation: {
				canStartResearcher: async () => true,
				startResearcher: async () => {
					starts += 1;
					return "researcher-from-omp";
				},
			},
		});
		const scout = context({ role: "scout-bounded", transcriptId: "scout-1" });

		const result = await extension.escalate(scout);

		expect(result).toEqual({
			started: true,
			blocked: false,
			reason: null,
			researcherTranscriptId: "researcher-from-omp",
		});
		expect(starts).toBe(1);
		expect(events.some((event) => event.subject === "researcher_escalation_started")).toBe(true);
	});

	test("records role and duplicate escalation refusals", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({
			eventSink: async (event) => { events.push(event); },
			escalation: {
				canStartResearcher: async () => true,
				startResearcher: async () => "researcher-1",
			},
		});

		await extension.escalate(context({ role: "researcher", transcriptId: "researcher-1" }));
		await extension.escalate(context({ role: "scout-bounded", transcriptId: "scout-1" }));
		await extension.escalate(context({ role: "scout-bounded", transcriptId: "scout-1" }));

		expect(events.map((event) => event.subject)).toEqual([
			"researcher_escalation_blocked",
			"researcher_escalation_started",
			"researcher_escalation_blocked",
		]);
	});

	test("swallows event and alert failures without breaking containment", async () => {
		const events: EventList = [];
		let firstEvent = true;
		const extension = new OMPModelControlExtension({
			containment: { threshold: 1 },
			eventSink: async (event) => {
				if (firstEvent) {
					firstEvent = false;
					throw new Error("event sink down");
				}
				events.push(event);
			},
			alert: async () => { throw new Error("alert down"); },
		});
		const request = context();

		expect((await extension.beforeRequest(request)).allowed).toBe(true);
		const response = await extension.afterResponse(request, { output: "same", totalTokens: 2 });

		expect(response.parked).toBe(true);
		expect(events.some((event) => event.subject === "event_sink_failed")).toBe(true);
		expect(events.some((event) => event.subject === "alert_failed")).toBe(true);
	});

	test("does not read policy state in the constructor and serializes sync", async () => {
		let reads = 0;
		let activeFetches = 0;
		let maximumFetches = 0;
		const fileSystem: FileSystem = {
			appendFile: async () => {},
			readFile: async () => {
				reads += 1;
				return "{}";
			},
			makeDirectory: async () => {},
		};
		const extension = new OMPModelControlExtension({
			policy: { fileSystem, cachePath: "/tmp/modelctl-policy.json" },
			transport: {
				fetchPolicy: async () => {
					activeFetches += 1;
					maximumFetches = Math.max(maximumFetches, activeFetches);
					await Promise.resolve();
					activeFetches -= 1;
					return null;
				},
			},
		});

		expect(reads).toBe(0);
		await extension.initialize();
		await Promise.all([extension.syncNow(), extension.syncNow()]);

		expect(reads).toBe(1);
		expect(maximumFetches).toBe(1);
	});

	test("keeps the prior policy when atomic cache persistence fails", async () => {
		const first = signedBundle(1, { threshold: "5" });
		const second = resign(first.bundle, first.privateKey, { sequence: 2, nonce: "nonce-2", payload: { threshold: "6" } });
		let writes = 0;
		const fileSystem = {
			readFile: async () => "",
			makeDirectory: async () => {},
			writeFile: async () => {
				writes += 1;
				if (writes > 1) throw new Error("disk full");
			},
			renameFile: async () => {},
		};
		const cache = new PolicyCache({
			keys: [{ keyId: "key-1", publicKey: first.publicKey }],
			clock: () => 2_000,
			fileSystem,
			cachePath: "/tmp/modelctl-policy.json",
		});

		expect((await cache.apply(first.bundle)).accepted).toBe(true);
		expect((await cache.apply(second)).accepted).toBe(false);
		expect(writes).toBe(2);
		expect(cache.currentPolicy()?.sequence).toBe(1);
	});

	test("restores replay fences and rejects a replay after restart", async () => {
		const first = signedBundle(1, { threshold: "5" });
		const second = resign(first.bundle, first.privateKey, { sequence: 2, nonce: "nonce-2", payload: { threshold: "6" } });
		let stored = "";
		let temporary = "";
		const fileSystem = {
			readFile: async () => stored,
			makeDirectory: async () => {},
			writeFile: async (path: string, content: string) => {
				if (path.endsWith(".tmp")) temporary = content;
				else stored = content;
			},
			renameFile: async () => { stored = temporary; },
		};
		const firstCache = new PolicyCache({
			keys: [{ keyId: "key-1", publicKey: first.publicKey }],
			clock: () => 2_000,
			fileSystem,
			cachePath: "/tmp/modelctl-policy.json",
		});
		await firstCache.apply(first.bundle);
		await firstCache.apply(second);

		const restarted = new PolicyCache({
			keys: [{ keyId: "key-1", publicKey: first.publicKey }],
			clock: () => 2_000,
			fileSystem,
			cachePath: "/tmp/modelctl-policy.json",
		});
		await restarted.restoreLastKnownGood();

		expect((await restarted.apply(first.bundle)).reason).toBe("sequence_replay");
		expect(restarted.currentPolicy()?.sequence).toBe(2);
	});

	test("reports cache restore failures while requests remain available", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({
			eventSink: async (event) => { events.push(event); },
			policy: {
				fileSystem: {
					readFile: async () => { throw new Error("cache unreadable"); },
					makeDirectory: async () => {},
				},
				cachePath: "/tmp/modelctl-policy.json",
			},
		});

		await extension.initialize();

		expect((await extension.beforeRequest(context())).allowed).toBe(true);
		expect(events.some((event) => event.subject === "policy_cache_restore_failed")).toBe(true);
	});

	test("blocks a parked transcript until an explicit resume", async () => {
		const extension = new OMPModelControlExtension({
			containment: { threshold: 1 },
			eventSink: async () => {},
		});
		const request = context({ transcriptId: "parked-transcript" });

		expect((await extension.beforeRequest(request)).allowed).toBe(true);
		expect((await extension.afterResponse(request, { output: "done", totalTokens: 1 })).parked).toBe(true);
		expect((await extension.beforeRequest(request)).reason).toBe("transcript_parked");
		extension.resume(request.transcriptId);
		expect((await extension.beforeRequest(request)).allowed).toBe(true);
	});

	test("applies signed containment thresholds and budget limits", async () => {
		const fixture = signedBundle(1, {
			version: 1,
			omp: {
				containment: { threshold: 2, windowMs: 120_000 },
				budgets: { agent: { "agent-a": 5 } },
			},
		});
		const events: EventList = [];
		const extension = new OMPModelControlExtension({
			eventSink: async (event) => { events.push(event); },
			policy: {
				keys: [{ keyId: fixture.bundle.keyId, publicKey: fixture.publicKey }],
				clock: () => 2_000,
				fileSystem: {
					readFile: async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); },
					makeDirectory: async () => {},
				},
			},
			transport: { fetchPolicy: async () => fixture.bundle },
		});
		const request = context({ transcriptId: "policy-configured" });

		expect((await extension.beforeRequest(request, 6)).reason).toBe("envelope_would_be_exceeded");
		expect((await extension.beforeRequest(request)).allowed).toBe(true);
		expect((await extension.afterResponse(request, { output: "repeat", totalTokens: 1 })).parked).toBe(false);
		expect((await extension.afterResponse(request, { output: "repeat", totalTokens: 1 })).parked).toBe(true);
		expect(events.some((event) => event.subject === "policy_runtime_applied")).toBe(true);
	});
});

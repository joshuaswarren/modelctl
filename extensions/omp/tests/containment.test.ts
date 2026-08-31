import { generateKeyPairSync, sign as signData, type KeyObject } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { ContainmentDetector } from "../src/containment";
import { OMPModelControlExtension } from "../src/index";
import { PolicyCache, policyId, signingContent, type SignedPolicyBundle } from "../src/policyCache";
import { EventStore, readEvents } from "../src/events";
import type { ExtensionEvent, FileSystem, RequestContext } from "../src/types";

type EventList = ExtensionEvent[];
type SignedFixture = { bundle: SignedPolicyBundle; publicKey: KeyObject; privateKey: KeyObject };

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

function sink(events: EventList): (event: ExtensionEvent) => Promise<void> {
	return async (event: ExtensionEvent): Promise<void> => {
		events.push(event);
	};
}

function signedBundle(sequence: number, payload: { [key: string]: string }): SignedFixture {
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
	candidate.signature = signData(null, signingContent(candidate), privateKey).toString("base64");
	return candidate;
}

describe("completion containment", () => {
	test("parks after five equivalent outputs and closes the agent budget", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({
			budgetLimits: { agent: { "agent-a": 100 } },
			containment: { threshold: 5, windowMs: 120_000, clock: () => 1_000 },
			eventSink: sink(events),
		});
		const request = context();

		await extension.beforeRequest(request);
		await extension.afterResponse(request, { output: "same answer", totalTokens: 10 });
		await extension.beforeRequest(request);
		await extension.afterResponse(request, { output: "same answer", totalTokens: 10 });
		await extension.beforeRequest(request);
		await extension.afterResponse(request, { output: "same answer", totalTokens: 10 });
		await extension.beforeRequest(request);
		await extension.afterResponse(request, { output: "same answer", totalTokens: 10 });
		await extension.beforeRequest(request);
		const result = await extension.afterResponse(request, { output: "same answer", totalTokens: 10 });

		expect(result.parked).toBe(true);
		expect(extension.containment.isParked(request.transcriptId)).toBe(true);
		expect(extension.budgets.isClosed(request.transcriptId)).toBe(true);
		expect(events.at(-1)?.detail).toMatchObject({ agent: "agent-a", project: "project-a", consumedTokens: 50 });
	});

	test("emits attributed direct and manual cloud usage after every response", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({ eventSink: sink(events) });
		const direct = context({
			transcriptId: "direct",
			directCloud: true,
			accountLabel: "primary",
		});
		const manual = context({
			transcriptId: "manual",
			directCloud: true,
			manualCloud: true,
			accountLabel: "primary",
		});

		await extension.beforeRequest(direct);
		await extension.afterResponse(direct, { output: "direct result", totalTokens: 11 });
		await extension.beforeRequest(manual);
		await extension.afterResponse(manual, { output: "manual result", totalTokens: 13 });

		const usage = events.filter((event) => event.subject === "usage_observed");
		expect(usage).toHaveLength(2);
		expect(usage[0]?.detail).toEqual({
			provider: "provider-a",
			accountLabel: "primary",
			consumedTokens: 11,
			attribution: "direct",
		});
		expect(usage[1]?.detail).toEqual({
			provider: "provider-a",
			accountLabel: "primary",
			consumedTokens: 13,
			attribution: "manual",
		});
	});

	test("resets the ring when a distinct output arrives", () => {
		const detector = new ContainmentDetector({ threshold: 3, windowMs: 120_000, clock: () => 1_000 });

		detector.observe("same", "transcript-2");
		detector.observe("same", "transcript-2");
		expect(detector.observe("different", "transcript-2").park).toBe(false);
		expect(detector.observe("same", "transcript-2").park).toBe(false);
	});

	test("contains repeated output while controller sync is unavailable", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({
			containment: { threshold: 2, windowMs: 120_000 },
			eventSink: sink(events),
			transport: { fetchPolicy: async () => { throw new Error("controller unavailable"); } },
		});
		const request = context({ transcriptId: "offline-transcript" });

		await extension.beforeRequest(request);
		await extension.afterResponse(request, { output: "same", totalTokens: 3 });
		const result = await extension.afterResponse(request, { output: "same", totalTokens: 3 });

		expect(result.parked).toBe(true);
		expect(events.some((event) => event.subject === "controller_sync_failed")).toBe(true);
	});
});

describe("escalation and budgets", () => {
	test("starts one researcher, never escalates a researcher, and records refusal", async () => {
		const events: EventList = [];
		let permits = true;
		const extension = new OMPModelControlExtension({
			eventSink: sink(events),
			escalation: {
				canStartResearcher: async () => permits,
				startResearcher: async () => "researcher-1",
			},
		});
		const scout = context({ role: "scout-bounded", transcriptId: "scout-1" });

		expect((await extension.escalate(scout)).started).toBe(true);
		expect((await extension.escalate(scout)).blocked).toBe(true);
		expect((await extension.escalate(context({ role: "researcher", transcriptId: "researcher-1" }))).started).toBe(false);
		permits = false;
		expect((await extension.escalate(context({ role: "scout-bounded", transcriptId: "scout-2" }))).reason).toBe("budget_refused");
		expect(events.some((event) => event.subject === "researcher_escalation_blocked")).toBe(true);
	});

	test("blocks the next automatic request after an envelope breach", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({
			budgetLimits: { agent: { "agent-a": 10 } },
			eventSink: sink(events),
		});
		const request = context();

		expect((await extension.beforeRequest(request)).allowed).toBe(true);
		await extension.afterResponse(request, { output: "one", totalTokens: 11 });
		expect((await extension.beforeRequest(context({ transcriptId: "next" }))).allowed).toBe(false);
		expect(events.some((event) => event.subject === "automatic_request_blocked")).toBe(true);

		expect((await extension.beforeRequest(context({ transcriptId: "manual", selector: "exact", explicitSelector: true }))).allowed).toBe(true);
	});
});

describe("policy and metadata", () => {
	test("rejects a tampered policy and keeps last known good", async () => {
		const first = signedBundle(1, { threshold: "5" });
		const cache = new PolicyCache({ keys: [{ keyId: "key-1", publicKey: first.publicKey }], clock: () => 2_000 });

		expect((await cache.apply(first.bundle)).accepted).toBe(true);
		const tampered = { ...first.bundle, payload: { threshold: "1" } };
		expect((await cache.apply(tampered)).accepted).toBe(false);
		expect(cache.currentPolicy()?.payload).toEqual({ threshold: "5" });
	});

	test("enforces freshness, sequence, nonce, rotation, and revocation", async () => {
		const first = signedBundle(1, { threshold: "5" });
		const cache = new PolicyCache({ keys: [{ keyId: "key-1", publicKey: first.publicKey }], clock: () => 2_000 });
		expect((await cache.apply(resign(first.bundle, first.privateKey, { sequence: 0, nonce: "expired", expiresAt: "1970-01-01T00:00:01.500Z" }))).reason).toBe("bundle_expired");
		expect((await cache.apply(resign(first.bundle, first.privateKey, { sequence: 0, nonce: "future", issuedAt: "1970-01-01T00:00:40Z" }))).reason).toBe("issued_in_future");

		expect((await cache.apply(first.bundle)).accepted).toBe(true);
		expect((await cache.apply(first.bundle)).reason).toBe("sequence_replay");
		const second = resign(first.bundle, first.privateKey, { sequence: 2, nonce: "nonce-2" });
		expect((await cache.apply(second)).accepted).toBe(true);
		expect((await cache.apply({ ...second, sequence: 3 })).reason).toBe("invalid_signature");
		const rotated = signedBundle(3, { threshold: "6" });
		cache.rotateKey({ keyId: "key-2", publicKey: rotated.publicKey });
		const rotatedBundle = resign(rotated.bundle, rotated.privateKey, { keyId: "key-2" });
		expect((await cache.apply(rotatedBundle)).accepted).toBe(true);
		cache.revokeKey("key-1");
		expect((await cache.apply(resign(second, first.privateKey, { sequence: 4, nonce: "nonce-4" }))).reason).toBe("untrusted_key");
		expect(cache.currentPolicy()?.sequence).toBe(3);
	});

	test("warns on manual selection with full R6 attribution", async () => {
		const events: EventList = [];
		const extension = new OMPModelControlExtension({ eventSink: sink(events) });
		const request = context({
			selector: "manual-model",
			explicitSelector: true,
			overrideSource: "frontmatter",
			clientFallback: ["fallback-a"],
			directCloud: true,
			manualCloud: true,
		});

		const admission = await extension.beforeRequest(request);

		expect(admission.allowed).toBe(true);
		expect(admission.metadata).toMatchObject({
			role: "task",
			agent: "agent-a",
			explicitSelector: true,
			selector: "manual-model",
			overrideSource: "frontmatter",
			project: "project-a",
			session: "session-a",
			clientFallback: ["fallback-a"],

			directCloud: true,
			manualCloud: true,
		});
		expect(events.some((event) => event.subject === "manual_selection_warning")).toBe(true);
	});
});

describe("durable events", () => {
	test("writes append-only JSONL records with required fields", async () => {
		const lines: string[] = [];
		const fileSystem: FileSystem = {
			appendFile: async (_path, content) => { lines.push(content); },
			readFile: async (_path) => lines.join(""),
			makeDirectory: async (_path) => {},
		};
		const store = new EventStore({
			path: "/tmp/modelctl-events.jsonl",
			clock: () => 1_000,
			eventId: () => "event-1",
			fileSystem,
		});

		await store.emit("request", "warning", "manual_selection_warning", { agent: "agent-a" });
		const events = await readEvents(fileSystem, "/tmp/modelctl-events.jsonl");

		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			id: "event-1",
			time: new Date(1_000).toISOString(),
			subsystem: "request",
			severity: "warning",
			subject: "manual_selection_warning",
			detail: { agent: "agent-a" },
		});
	});

	test("continues later writes after one append fails", async () => {
		const lines: string[] = [];
		let appendAttempts = 0;
		const fileSystem: FileSystem = {
			appendFile: async (_path, content) => {
				appendAttempts += 1;
				if (appendAttempts === 1) {
					throw new Error("disk full");
				}
				lines.push(content);
			},
			readFile: async (_path) => lines.join(""),
			makeDirectory: async (_path) => {},
		};
		const store = new EventStore({
			path: "/tmp/modelctl-events.jsonl",
			clock: () => 1_000,
			eventId: () => `event-${appendAttempts + 1}`,
			fileSystem,
		});

		await expect(store.emit("request", "error", "failed_write", {})).rejects.toThrow("disk full");
		await store.emit("request", "info", "recovered_write", {});
		const events = await readEvents(fileSystem, "/tmp/modelctl-events.jsonl");

		expect(appendAttempts).toBe(2);
		expect(events).toHaveLength(1);
		expect(events[0]?.subject).toBe("recovered_write");
	});
});

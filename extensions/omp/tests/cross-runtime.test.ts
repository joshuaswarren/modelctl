import { readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import { parseBundle, PolicyCache } from "../src/policyCache";

describe("Python and TypeScript policy contract", () => {
	test("accepts an envelope produced by the Python signer", async () => {
		const [serialized, publicKey] = await Promise.all([
			readFile(new URL("./fixtures/python-signed-envelope.json", import.meta.url), "utf8"),
			readFile(new URL("./fixtures/python-public-key.pem", import.meta.url), "utf8"),
		]);
		const envelope = parseBundle(serialized);
		if (envelope === null) throw new Error("Python fixture envelope is invalid");
		const cache = new PolicyCache({
			keys: [{ keyId: envelope.keyId, publicKey }],
			clock: () => Date.parse("2026-08-29T12:05:00Z"),
		});

		expect((await cache.apply(envelope)).accepted).toBe(true);
		expect(cache.currentPolicy()?.payloadDigest).toBe(envelope.payloadDigest);
		expect((await cache.apply({ ...envelope, payload: { version: 2 } })).reason).toBe("payload_digest_mismatch");
		expect(parseBundle(serialized.replace("2026-08-29T12:00:00Z", "2026-08-29T12:00:00+00:00"))).toBeNull();
		expect(parseBundle(serialized.replace(/"signature": "[^"]+"/u, "\"signature\": \"bad\""))).toBeNull();
	});
});

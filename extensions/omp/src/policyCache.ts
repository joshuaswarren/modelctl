import { createHash, verify as verifySignature, type KeyObject } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { BudgetLimits, Clock, JsonValue, MakeDirectory, ReadFile, RenameFile, WriteFile } from "./types";

interface PolicyFileSystem {
	readFile: ReadFile;
	makeDirectory: MakeDirectory;
	writeFile?: WriteFile;
	renameFile?: RenameFile;
}

type JsonObject = { [key: string]: JsonValue };

export interface SignedPolicyBundle {
	keyId: string;
	issuedAt: string;
	expiresAt: string;
	nonce: string;
	sequence: number;
	payloadDigest: string;
	signature: string;
	payload: JsonObject;
}

export interface OMPRuntimePolicy {
	budgets?: BudgetLimits;
	containment?: {
		threshold?: number;
		windowMs?: number;
	};
}

interface PersistedPolicyState {
	active: SignedPolicyBundle;
	highestSequence: number;
	seenNonces: string[];
}

export interface PolicyKey {
	keyId: string;
	publicKey: string | KeyObject;
}

export type SignatureVerifier = (
	key: PolicyKey,
	signature: string,
	content: Uint8Array,
) => boolean | Promise<boolean>;

export interface PolicyCacheOptions {
	keys?: PolicyKey[];
	clock?: Clock;
	maxClockSkewMs?: number;
	verifySignature?: SignatureVerifier;
	fileSystem?: PolicyFileSystem;
	cachePath?: string;
}

export interface PolicyApplyResult {
	accepted: boolean;
	reason: string | null;
	current: SignedPolicyBundle | null;
}

export interface PolicyRestoreResult {
	restored: boolean;
	reason: "missing" | "invalid" | "untrusted_key" | "invalid_signature" | "issued_in_future" | "bundle_expired" | "io_error" | null;
}

const defaultClock: Clock = () => Date.now();
const defaultCachePath = join(homedir(), ".omp", "cache", "modelctl-policy.json");
const nodeFileSystem: PolicyFileSystem = {
	readFile: async (path) => readFile(path, "utf8"),
	makeDirectory: async (path) => {
		await mkdir(path, { recursive: true });
	},
	writeFile: async (path, content) => {
		await writeFile(path, content, "utf8");
	},
	renameFile: async (source, destination) => {
		await rename(source, destination);
	},
};

export function canonicalJson(value: JsonValue): Uint8Array {
	return new TextEncoder().encode(canonicalString(value));
}

export function canonicalString(value: JsonValue): string {
	if (isJsonPrimitive(value)) return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalString).join(",")}]`;
	const entries = Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
	return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalString(item)}`).join(",")}}`;
}

export function policyId(payload: JsonObject): string {
	return createHash("sha256").update(canonicalJson(payload)).digest("hex");
}

export function signingContent(bundle: SignedPolicyBundle): Uint8Array {
	return canonicalJson({
		expiresAt: bundle.expiresAt,
		issuedAt: bundle.issuedAt,
		keyId: bundle.keyId,
		nonce: bundle.nonce,
		payloadDigest: bundle.payloadDigest,
		sequence: bundle.sequence,
	});
}

export function verifyEd25519(key: PolicyKey, signature: string, content: Uint8Array): boolean {
	const decoded = decodeSignature(signature);
	if (decoded === null) return false;
	try {
		return verifySignature(null, content, key.publicKey, decoded);
	} catch {
		return false;
	}
}

export class PolicyCache {
	private readonly keys = new Map<string, PolicyKey>();
	private readonly revoked = new Set<string>();
	private readonly seenNonces = new Set<string>();
	private readonly clock: Clock;
	private readonly maxClockSkewMs: number;
	private readonly verify: SignatureVerifier;
	private readonly fileSystem: PolicyFileSystem;
	private readonly cachePath: string;
	private active: SignedPolicyBundle | null = null;
	private highestSequence = -1;
	private operationChain: Promise<void> = Promise.resolve();

	constructor(options: PolicyCacheOptions = {}) {
		for (const key of options.keys ?? []) this.keys.set(key.keyId, key);
		this.clock = options.clock ?? defaultClock;
		this.maxClockSkewMs = Math.max(0, options.maxClockSkewMs ?? 30_000);
		this.verify = options.verifySignature ?? verifyEd25519;
		this.fileSystem = options.fileSystem ?? nodeFileSystem;
		this.cachePath = options.cachePath ?? defaultCachePath;
	}

	apply(bundle: SignedPolicyBundle): Promise<PolicyApplyResult> {
		return this.serialized(() => this.applyNow(bundle));
	}

	restoreLastKnownGood(): Promise<PolicyRestoreResult> {
		return this.serialized(() => this.restoreNow());
	}

	currentPolicy(): SignedPolicyBundle | null {
		return this.active;
	}

	addKey(key: PolicyKey): void {
		if (this.revoked.has(key.keyId)) throw new Error("revoked keyId cannot be reused");
		this.keys.set(key.keyId, key);
	}

	rotateKey(key: PolicyKey): void {
		this.addKey(key);
	}

	revokeKey(keyId: string): void {
		this.revoked.add(keyId);
		if (this.active?.keyId === keyId) this.active = null;
	}

	isRevoked(keyId: string): boolean {
		return this.revoked.has(keyId);
	}

	private async applyNow(bundle: SignedPolicyBundle): Promise<PolicyApplyResult> {
		const reason = await this.validate(bundle, this.highestSequence, this.seenNonces);
		if (reason !== null) return this.reject(reason);
		const seenNonces = new Set(this.seenNonces);
		seenNonces.add(bundle.nonce);
		const state = {
			active: bundle,
			highestSequence: bundle.sequence,
			seenNonces: [...seenNonces],
		};
		try {
			await this.persist(state);
		} catch {
			return this.reject("cache_persist_failed");
		}
		this.active = bundle;
		this.highestSequence = bundle.sequence;
		this.seenNonces.clear();
		for (const nonce of seenNonces) this.seenNonces.add(nonce);
		return { accepted: true, reason: null, current: bundle };
	}

	private async restoreNow(): Promise<PolicyRestoreResult> {
		let serialized: string;
		try {
			serialized = await this.fileSystem.readFile(this.cachePath);
		} catch (error) {
			const missing = error instanceof Error && Reflect.get(error, "code") === "ENOENT";
			return { restored: false, reason: missing ? "missing" : "io_error" };
		}
		const state = parseState(serialized);
		if (state === null) return { restored: false, reason: "invalid" };
		const key = this.keys.get(state.active.keyId);
		if (key === undefined || this.revoked.has(state.active.keyId)) {
			return { restored: false, reason: "untrusted_key" };
		}
		if (!(await this.verify(key, state.active.signature, signingContent(state.active)))) {
			return { restored: false, reason: "invalid_signature" };
		}
		const freshness = this.freshnessReason(state.active);
		if (freshness !== null) return { restored: false, reason: freshness };
		if (state.active.payloadDigest !== policyId(state.active.payload)
			|| state.highestSequence !== state.active.sequence
			|| !state.seenNonces.includes(state.active.nonce)) {
			return { restored: false, reason: "invalid" };
		}
		if (this.active !== null && state.highestSequence <= this.highestSequence) {
			return { restored: false, reason: "invalid" };
		}
		this.active = state.active;
		this.highestSequence = state.highestSequence;
		this.seenNonces.clear();
		for (const nonce of state.seenNonces) this.seenNonces.add(nonce);
		return { restored: true, reason: null };
	}

	private async validate(
		bundle: SignedPolicyBundle,
		highestSequence: number,
		seenNonces: ReadonlySet<string>,
	): Promise<string | null> {
		if (bundle.payloadDigest !== policyId(bundle.payload)) return "payload_digest_mismatch";
		const key = this.keys.get(bundle.keyId);
		if (key === undefined || this.revoked.has(bundle.keyId)) return "untrusted_key";
		if (!(await this.verify(key, bundle.signature, signingContent(bundle)))) return "invalid_signature";
		const freshness = this.freshnessReason(bundle);
		if (freshness !== null) return freshness;
		if (bundle.sequence <= highestSequence) return "sequence_replay";
		if (seenNonces.has(bundle.nonce)) return "nonce_replay";
		return null;
	}

	private freshnessReason(
		bundle: SignedPolicyBundle,
	): "issued_in_future" | "bundle_expired" | null {
		const now = this.clock();
		const issuedAt = Date.parse(bundle.issuedAt);
		const expiresAt = Date.parse(bundle.expiresAt);
		if (issuedAt > now + this.maxClockSkewMs) return "issued_in_future";
		if (expiresAt <= now) return "bundle_expired";
		return null;
	}

	private async persist(state: PersistedPolicyState): Promise<void> {
		if (this.fileSystem.writeFile === undefined) return;
		await this.fileSystem.makeDirectory(dirname(this.cachePath));
		const content = `${JSON.stringify(state)}\n`;
		if (this.fileSystem.renameFile === undefined) {
			await this.fileSystem.writeFile(this.cachePath, content);
			return;
		}
		const temporaryPath = `${this.cachePath}.tmp`;
		await this.fileSystem.writeFile(temporaryPath, content);
		await this.fileSystem.renameFile(temporaryPath, this.cachePath);
	}

	private reject(reason: string): PolicyApplyResult {
		return { accepted: false, reason, current: this.active };
	}

	private serialized<Result>(operation: () => Promise<Result>): Promise<Result> {
		const result = this.operationChain.then(operation, operation);
		this.operationChain = result.then(() => {}, () => {});
		return result;
	}
}

export function parseBundle(serialized: string): SignedPolicyBundle | null {
	try {
		const value: JsonValue = JSON.parse(serialized);
		return isJsonObject(value) ? bundleFromObject(value) : null;
	} catch {
		return null;
	}
}

export function parseOMPRuntimePolicy(payload: JsonObject): OMPRuntimePolicy | null | undefined {
	const value = payload.omp;
	if (value === undefined) return undefined;
	if (!isJsonObject(value)) return null;
	const result: OMPRuntimePolicy = {};
	if (value.budgets !== undefined) {
		const budgets = budgetLimitsFromJson(value.budgets);
		if (budgets === null) return null;
		result.budgets = budgets;
	}
	if (value.containment !== undefined) {
		if (!isJsonObject(value.containment)) return null;
		const threshold = optionalPositiveInteger(value.containment.threshold);
		const windowMs = optionalPositiveInteger(value.containment.windowMs);
		if (threshold === null || windowMs === null) return null;
		result.containment = {};
		if (threshold !== undefined) result.containment.threshold = threshold;
		if (windowMs !== undefined) result.containment.windowMs = windowMs;
	}
	return result;
}

function parseState(serialized: string): PersistedPolicyState | null {
	try {
		const value: JsonValue = JSON.parse(serialized);
		if (!isJsonObject(value)) return null;
		const activeValue = value.active ?? null;
		if (!isJsonObject(activeValue)) return null;
		const active = bundleFromObject(activeValue);
		const highestSequence = value.highestSequence ?? null;
		const seenNonces = value.seenNonces ?? null;
		if (active === null || !isNonnegativeInteger(highestSequence) || !isStringArray(seenNonces)) return null;
		return { active, highestSequence, seenNonces };
	} catch {
		return null;
	}
}

function bundleFromObject(value: JsonObject): SignedPolicyBundle | null {
	const keyId = value.keyId ?? null;
	const issuedAt = value.issuedAt ?? null;
	const expiresAt = value.expiresAt ?? null;
	const nonce = value.nonce ?? null;
	const sequence = value.sequence ?? null;
	const payloadDigest = value.payloadDigest ?? null;
	const signature = value.signature ?? null;
	const payload = value.payload ?? null;
	if (!isString(keyId) || !isRfc3339Utc(issuedAt) || !isRfc3339Utc(expiresAt) || !isString(nonce)) return null;
	if (!isNonnegativeInteger(sequence) || !isDigest(payloadDigest) || !isSignature(signature) || !isJsonObject(payload)) return null;
	if (Date.parse(expiresAt) <= Date.parse(issuedAt)) return null;
	return { keyId, issuedAt, expiresAt, nonce, sequence, payloadDigest, signature, payload };
}


function isJsonObject(value: JsonValue): value is JsonObject {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJsonPrimitive(value: JsonValue): value is string | number | boolean | null {
	return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isString(value: JsonValue): value is string {
	return typeof value === "string";
}

function isStringArray(value: JsonValue): value is string[] {
	return Array.isArray(value) && value.every(isString);
}

function isFiniteNumber(value: JsonValue): value is number {
	return typeof value === "number" && Number.isFinite(value);
}

function isNonnegativeInteger(value: JsonValue): value is number {
	return isFiniteNumber(value) && Number.isInteger(value) && value >= 0;
}

function isRfc3339Utc(value: JsonValue): value is string {
	return isString(value)
		&& /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value)
		&& Number.isFinite(Date.parse(value));
}

function isDigest(value: JsonValue): value is string {
	return isString(value) && /^[0-9a-f]{64}$/u.test(value);
}

function isSignature(value: JsonValue): value is string {
	return isString(value) && decodeSignature(value) !== null;
}

function decodeSignature(value: string): Buffer | null {
	if (!/^[A-Za-z0-9+/]{86}==$/u.test(value)) return null;
	const decoded = Buffer.from(value, "base64");
	return decoded.length === 64 && decoded.toString("base64") === value ? decoded : null;
}

function budgetLimitsFromJson(value: JsonValue): BudgetLimits | null {
	if (!isJsonObject(value)) return null;
	const allowed = new Set(["agent", "project", "provider"]);
	if (Object.keys(value).some((key) => !allowed.has(key))) return null;
	const result: BudgetLimits = {};
	for (const scope of ["agent", "project", "provider"] as const) {
		if (value[scope] === undefined) continue;
		const limits = limitRecordFromJson(value[scope]);
		if (limits === null) return null;
		result[scope] = limits;
	}
	return result;
}

function limitRecordFromJson(value: JsonValue): Record<string, number> | null {
	if (!isJsonObject(value)) return null;
	const limits: Record<string, number> = {};
	for (const [name, limit] of Object.entries(value)) {
		if (name.trim().length === 0 || !isNonnegativeInteger(limit)) return null;
		limits[name] = limit;
	}
	return limits;
}

function optionalPositiveInteger(value: JsonValue | undefined): number | null | undefined {
	if (value === undefined) return undefined;
	return isNonnegativeInteger(value) && value > 0 ? value : null;
}

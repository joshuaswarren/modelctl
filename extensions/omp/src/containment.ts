import { createHash } from "node:crypto";
import type { Clock, JsonValue } from "./types";

export interface ContainmentOptions {
	threshold?: number;
	windowMs?: number;
	clock?: Clock;
	normalize?: (output: string) => string;
	equivalence?: (left: string, right: string) => boolean;
}

export interface ContainmentObservation {
	transcriptId: string;
	hash: string;
	count: number;
	park: boolean;
	alreadyParked: boolean;
}

interface RingEntry {
	hash: string;
	normalized: string;
	time: number;
}

const defaultClock: Clock = () => Date.now();

export function normalizeOutput(output: string): string {
	const normalized = output.replaceAll("\r\n", "\n").replaceAll("\r", "\n").trim();
	try {
		return JSON.stringify(sortJson(JSON.parse(normalized)));
	} catch {
		return normalized.replace(/\s+/gu, " ");
	}
}

function sortJson(value: JsonValue): JsonValue {
	if (Array.isArray(value)) return value.map(sortJson);
	if (!isJsonObject(value)) return value;
	return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key] ?? null)]));
}

function isJsonObject(value: JsonValue): value is { [key: string]: JsonValue } {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hashOutput(output: string): string {
	return createHash("sha256").update(output, "utf8").digest("hex");
}

export class ContainmentDetector {
	private threshold: number;
	private windowMs: number;
	private readonly clock: Clock;
	private readonly normalize: (output: string) => string;
	private readonly equivalence: (left: string, right: string) => boolean;
	private readonly rings = new Map<string, RingEntry[]>();
	private readonly parked = new Set<string>();

	constructor(options: ContainmentOptions = {}) {
		this.threshold = Math.max(1, options.threshold ?? 5);
		this.windowMs = Math.max(1, options.windowMs ?? 120_000);
		this.clock = options.clock ?? defaultClock;
		this.normalize = options.normalize ?? normalizeOutput;
		this.equivalence = options.equivalence ?? ((left, right) => left === right);
	}

	updatePolicy(options: Pick<ContainmentOptions, "threshold" | "windowMs">): void {
		this.threshold = Math.max(1, options.threshold ?? this.threshold);
		this.windowMs = Math.max(1, options.windowMs ?? this.windowMs);
		this.rings.clear();
	}

	observe(output: string, transcriptId: string, markParked = true): ContainmentObservation {
		const normalized = this.normalize(output);
		const hash = hashOutput(normalized);
		if (this.parked.has(transcriptId)) {
			return { transcriptId, hash, count: this.rings.get(transcriptId)?.length ?? 0, park: false, alreadyParked: true };
		}

		const now = this.clock();
		const previous = this.rings.get(transcriptId) ?? [];
		const fresh = previous.filter((entry) => now - entry.time <= this.windowMs);
		const last = fresh.at(-1);
		const next = last && (last.hash === hash || this.equivalence(last.normalized, normalized))
			? [...fresh, { hash, normalized, time: now }]
			: [{ hash, normalized, time: now }];
		this.rings.set(transcriptId, next.slice(-this.threshold));
		const park = next.length >= this.threshold;
		if (park && markParked) this.parked.add(transcriptId);
		return { transcriptId, hash, count: next.length, park, alreadyParked: false };
	}

	isParked(transcriptId: string): boolean {
		return this.parked.has(transcriptId);
	}

	resume(transcriptId: string): void {
		this.parked.delete(transcriptId);
		this.rings.delete(transcriptId);
	}

	clear(transcriptId: string): void {
		this.resume(transcriptId);
	}
}

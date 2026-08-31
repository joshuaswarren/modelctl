import { appendFile, mkdir, readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Clock, EventSink, ExtensionEvent, FileSystem, Severity } from "./types";

export const DEFAULT_EVENT_PATH = join(homedir(), ".omp", "logs", "modelctl-events.jsonl");

const nodeFileSystem: FileSystem = {
	appendFile: async (path, content) => {
		await appendFile(path, content, "utf8");
	},
	readFile: async (path) => readFile(path, "utf8"),
	makeDirectory: async (path) => {
		await mkdir(path, { recursive: true });
	},
};

const nodeClock: Clock = () => Date.now();

export interface EventStoreOptions {
	path?: string;
	fileSystem?: FileSystem;
	clock?: Clock;
	eventId?: () => string;
}

export class EventStore {
	private readonly path: string;
	private readonly fileSystem: FileSystem;
	private readonly clock: Clock;
	private readonly eventId: () => string;
	private writeChain: Promise<void> = Promise.resolve();

	constructor(options: EventStoreOptions = {}) {
		this.path = options.path?.startsWith("~/") ? join(homedir(), options.path.slice(2)) : options.path ?? DEFAULT_EVENT_PATH;
		this.fileSystem = options.fileSystem ?? nodeFileSystem;
		this.clock = options.clock ?? nodeClock;
		this.eventId = options.eventId ?? randomUUID;
	}

	emit(
		subsystem: string,
		severity: Severity,
		subject: string,
		detail: ExtensionEvent["detail"],
	): Promise<ExtensionEvent> {
		const event: ExtensionEvent = {
			id: this.eventId(),
			time: new Date(this.clock()).toISOString(),
			subsystem,
			severity,
			subject,
			detail,
		};
		return this.append(`${JSON.stringify(event)}\n`).then(() => event);
	}

	asSink(): EventSink {
		return async (event) => {
			await this.append(`${JSON.stringify(event)}\n`);
		};
	}

	private append(line: string): Promise<void> {
		const write = this.writeChain.then(async () => {
			await this.fileSystem.makeDirectory(dirname(this.path));
			await this.fileSystem.appendFile(this.path, line);
		});
		this.writeChain = write.catch(() => {});
		return write;
	}
}

export async function readEvents(fileSystem: FileSystem, path: string): Promise<ExtensionEvent[]> {
	const content = await fileSystem.readFile(path);
	return content
		.split("\n")
		.filter((line) => line.length > 0)
		.map((line) => {
			// SAFETY: EventStore writes each line from the ExtensionEvent contract.
			return JSON.parse(line) as ExtensionEvent;
		});
}

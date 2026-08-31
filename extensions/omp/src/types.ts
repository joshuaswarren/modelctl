export type Severity = "debug" | "info" | "warning" | "error" | "critical";
export type ExtensionMode = "observe" | "enforce";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type Clock = () => number;
export type AppendFile = (path: string, content: string) => Promise<void>;
export type ReadFile = (path: string) => Promise<string>;
export type WriteFile = (path: string, content: string) => Promise<void>;
export type MakeDirectory = (path: string) => Promise<void>;
export type RenameFile = (source: string, destination: string) => Promise<void>;

export interface FileSystem {
	appendFile: AppendFile;
	readFile: ReadFile;
	makeDirectory: MakeDirectory;
	writeFile?: WriteFile;
	renameFile?: RenameFile;
}

export interface ExtensionEvent {
	id: string;
	time: string;
	subsystem: string;
	severity: Severity;
	subject: string;
	detail: Record<string, string | number | boolean | null | string[]>;
}

export type EventSink = (event: ExtensionEvent) => Promise<void>;

export interface RequestMetadata {
	role: string;
	agent: string;
	explicitSelector: boolean;
	selector: string | null;
	overrideSource: string | null;
	project: string | null;
	session: string | null;
	clientFallback: string[];
	directCloud: boolean;
	manualCloud: boolean;
}

export interface RequestContext {
	role: string;
	agent: string;
	project: string | null;
	session: string | null;
	cwd?: string;
	sessionFile?: string | null;
	selector?: string | null;
	explicitSelector?: boolean;
	overrideSource?: string | null;
	clientFallback?: string[];
	directCloud?: boolean;
	manualCloud?: boolean;
	automatic?: boolean;
	transcriptId: string;
	provider?: string | null;
	accountLabel?: string | null;
}

export interface BudgetLimits {
	agent?: Record<string, number>;
	project?: Record<string, number>;
	provider?: Record<string, number>;
}

export interface BudgetUsage {
	agent: Record<string, number>;
	project: Record<string, number>;
	provider: Record<string, number>;
}

export interface BudgetAdmission {
	allowed: boolean;
	manual: boolean;
	reason: string | null;
}

export interface BudgetObservation {
	manual: boolean;
	wouldBlockReason: string | null;
}

export interface BudgetClosure {
	transcriptId: string;
	agent: string;
	project: string | null;
	provider: string | null;
	consumedTokens: number;
}

export interface ResponseResult {
	output: string;
	inputTokens?: number;
	outputTokens?: number;
	totalTokens?: number;
}

export interface EscalationRequest {
	transcriptId: string;
	agent: string;
	project: string | null;
	provider: string | null;
	cwd: string | null;
	sessionFile: string | null;
}

export interface EscalationResult {
	started: boolean;
	blocked: boolean;
	reason: string | null;
	researcherTranscriptId: string | null;
}

export interface RecoveryResult {
	started: boolean;
	blocked: boolean;
	reason: string | null;
	recoveryTranscriptId: string | null;
}

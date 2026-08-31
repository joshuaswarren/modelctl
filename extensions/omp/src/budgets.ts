import { randomUUID } from "node:crypto";
import type {
	BudgetAdmission,
	BudgetClosure,
	BudgetLimits,
	BudgetObservation,
	BudgetUsage,
	Clock,
	EventSink,
	RequestContext,
} from "./types";

interface OpenBudget {
	context: RequestContext;
	consumedTokens: number;
	closed: boolean;
}

export interface BudgetManagerOptions {
	limits?: BudgetLimits;
	clock?: Clock;
	eventSink?: EventSink;
}

const emptyEventSink: EventSink = async () => {};

export class BudgetManager {
	private limits: BudgetLimits;
	private readonly eventSink: EventSink;
	private readonly usage: BudgetUsage = { agent: {}, project: {}, provider: {} };
	private readonly open = new Map<string, OpenBudget>();
	private readonly closed = new Set<string>();
	private eventChain: Promise<void> = Promise.resolve();

	constructor(options: BudgetManagerOptions = {}) {
		this.limits = copyLimits(options.limits ?? {});
		this.eventSink = options.eventSink ?? emptyEventSink;
	}

	updateLimits(limits: BudgetLimits): void {
		this.limits = copyLimits(limits);
	}

	admit(context: RequestContext, estimatedTokens = 0): BudgetAdmission {
		const manual = context.explicitSelector === true || context.manualCloud === true || context.automatic === false;
		if (this.closed.has(context.transcriptId)) return { allowed: false, manual, reason: "transcript_budget_closed" };
		if (!manual && this.isBreached(context)) {
			this.queueBlocked(context, "envelope_breached");
			return { allowed: false, manual, reason: "envelope_breached" };
		}
		if (!manual && this.wouldExceed(context, estimatedTokens)) {
			this.queueBlocked(context, "envelope_would_be_exceeded");
			return { allowed: false, manual, reason: "envelope_would_be_exceeded" };
		}
		if (!this.open.has(context.transcriptId)) {
			this.open.set(context.transcriptId, { context, consumedTokens: 0, closed: false });
		}
		return { allowed: true, manual, reason: null };
	}

	observe(context: RequestContext, estimatedTokens = 0): BudgetObservation {
		const manual = context.explicitSelector === true || context.manualCloud === true || context.automatic === false;
		const wouldBlockReason = this.closed.has(context.transcriptId)
			? "transcript_budget_closed"
			: !manual && this.isBreached(context)
				? "envelope_breached"
				: !manual && this.wouldExceed(context, estimatedTokens)
					? "envelope_would_be_exceeded"
					: null;
		if (!this.open.has(context.transcriptId)) {
			this.open.set(context.transcriptId, { context, consumedTokens: 0, closed: false });
		}
		return { manual, wouldBlockReason };
	}

	async flushEvents(): Promise<void> {
		await this.eventChain;
	}

	consume(transcriptId: string, tokens: number): BudgetUsage {
		const amount = Math.max(0, Math.floor(tokens));
		const budget = this.open.get(transcriptId);
		if (budget === undefined || budget.closed) return this.snapshot();
		budget.consumedTokens += amount;
		this.add(this.usage.agent, budget.context.agent, amount);
		if (budget.context.project !== null) this.add(this.usage.project, budget.context.project, amount);
		if (budget.context.provider !== null && budget.context.provider !== undefined) {
			this.add(this.usage.provider, budget.context.provider, amount);
		}
		return this.snapshot();
	}

	close(transcriptId: string): BudgetClosure | null {
		const budget = this.open.get(transcriptId);
		if (budget === undefined) return null;
		budget.closed = true;
		this.closed.add(transcriptId);
		return {
			transcriptId,
			agent: budget.context.agent,
			project: budget.context.project,
			provider: budget.context.provider ?? null,
			consumedTokens: budget.consumedTokens,
		};
	}

	isClosed(transcriptId: string): boolean {
		return this.closed.has(transcriptId);
	}

	resume(transcriptId: string): void {
		this.closed.delete(transcriptId);
		this.open.delete(transcriptId);
	}

	isEnvelopeBreached(context: RequestContext): boolean {
		return this.isBreached(context);
	}

	usageSnapshot(): BudgetUsage {
		return this.snapshot();
	}

	private wouldExceed(context: RequestContext, tokens: number): boolean {
		const amount = Math.max(0, Math.floor(tokens));
		return this.exceeds(this.usage.agent, this.limits.agent, context.agent, amount)
			|| (context.project !== null && this.exceeds(this.usage.project, this.limits.project, context.project, amount))
			|| (context.provider !== null && context.provider !== undefined
				&& this.exceeds(this.usage.provider, this.limits.provider, context.provider, amount));
	}

	private isBreached(context: RequestContext): boolean {
		return this.exceeds(this.usage.agent, this.limits.agent, context.agent, 0)
			|| (context.project !== null && this.exceeds(this.usage.project, this.limits.project, context.project, 0))
			|| (context.provider !== null && context.provider !== undefined
				&& this.exceeds(this.usage.provider, this.limits.provider, context.provider, 0));
	}

	private exceeds(
		usage: Record<string, number>,
		limits: Record<string, number> | undefined,
		key: string,
		additional: number,
	): boolean {
		const limit = limits?.[key];
		return limit !== undefined && (usage[key] ?? 0) + additional > limit;
	}

	private add(target: Record<string, number>, key: string, amount: number): void {
		target[key] = (target[key] ?? 0) + amount;
	}

	private snapshot(): BudgetUsage {
		return {
			agent: { ...this.usage.agent },
			project: { ...this.usage.project },
			provider: { ...this.usage.provider },
		};
	}


	private queueBlocked(context: RequestContext, reason: string): void {
		this.eventChain = this.eventChain.then(async () => {
			await this.eventSink({
				id: randomUUID(),
				time: new Date().toISOString(),
				subsystem: "budgets",
				severity: "warning",
				subject: "automatic_request_blocked",
				detail: {
					agent: context.agent,
					project: context.project,
					transcriptId: context.transcriptId,
					reason,
				},
			});
		});
	}
}

function copyLimits(limits: BudgetLimits): BudgetLimits {
	return {
		agent: limits.agent === undefined ? undefined : { ...limits.agent },
		project: limits.project === undefined ? undefined : { ...limits.project },
		provider: limits.provider === undefined ? undefined : { ...limits.provider },
	};
}

# Operating theory

## Problem

`modelctl` treats model routing as a signed control-plane problem.

Hosts report measured engine state. Controllers combine policy, quota, spend, and evaluation evidence.
Adapters render deterministic configuration for serving systems.

## Control boundaries

OMP enforces local limits through runtime hooks. It remains effective when both controllers are unavailable.
OMP records direct and manual cloud usage after each response.
The installed OMP extension loads observe-only by default. It reports enforcement actions without applying them.
Enforcement mode is explicit. A containment park starts one recovery agent from the parent session.
The recovery agent has a fixed timeout and cannot start another recovery agent.
Events use owner labels instead of provider identities.

Producers validate payloads before they allocate a durable sequence.
They sign one envelope before network activity and send the same bytes to both controllers.
Observe-only controllers record telemetry independently. Enforcing mode routes mutations through the active controller.

Public code defines portable contracts. Private files bind those contracts to real services.

## Consistency model

Safety depends on signed identity, freshness, durable sequences, and fencing.
Signed messages expire and reject replay.

The active controller authenticates each mutation before it allocates a replication sequence.
The standby authenticates both signed envelopes before replay changes.
Replication uses prepare, local commit, and remote commit phases.
A failed remote commit leaves an outbox record for restart recovery.

An operation ID binds to one signed-envelope fingerprint.
A second envelope cannot replace a pending or completed operation.
Promotion fences the old active before the standby changes role.

## Quota and runway

The broker collector reads sanitized snapshot files.
It rejects raw identities and posts the same signed record to both controllers.
Each quota record declares its unit.
Runway preserves raw quota usage and only projects token spend onto token quotas.

Runway prefers provider data over delayed dashboard and consumption estimates.
Unknown or silent sources remain unknown.
The controller validates quota schema before replication.
The controller runs one background loop to derive runway from durable quota and spend records.
Budget enforcement, host lifecycle, and canary decisions remain in their real policy modules.

## Evaluation and promotion

A candidate must match its catalog entry and pass hard-fit requirements before response evaluation starts.
Deterministic contracts run before judges.
Objective suites skip judges.
Subjective suites use at most three distinct model families.

Strict-local evaluation consumes no reserved serving capacity.
A new cloud destination requires exact egress approval.
Canary policy checks error rate, p95 latency, and quota draw.
Every decision reaches durable storage before route activation or rollback.

## Subscription selection

Selection qualifies routes before it considers subscription runway.
Promotion records identify candidates through the evaluation pipeline's canonical `inputs.candidate.id` field.
Unknown, stale, or mismatched runway cannot make a cloud route eligible.
Equal-time observations use the highest reported usage, which makes duplicate data fail conservatively.
An eligible incumbent stays selected only against equal-priority peers.
A higher-priority candidate reclaims the role as soon as it is eligible again, so a reserve dip does not strand a role on its fallback.

The selector maps each managed workload onto an OMP native role and fallback chain.
It preserves roles outside its policy and leaves blocked roles on their last-known-good configuration.
The OMP adapter changes only `modelRoles` and `retry.fallbackChains`.
It reads but never changes `task.agentModelOverrides`.
Failure receipts report the adapter's actual native write set.
Receipt creation syncs both file contents and the parent directory entry.
Explicit `/model` choices and provider request payloads remain outside the selection loop.

## Routing transactions

The LiteLLM adapter reserves interactive capacity before weighted routes.
Each eligible engine supplies its serving base URL.
Every rendered entry has a unique backend ID, a weight, and a concurrency limit.

Promotion and rollback use the same guarded compare-and-swap adapter.
Apply preserves file ownership and mode.
Failure restores both disk and runtime state.

The receiver polls both controllers through mTLS.
It verifies trusted signatures and rejects equal-sequence split brain.
Observe-only mode reports an update without changing router state.
Apply mode requires an explicit configuration change outside the prepared package.

## Operator surface

The dashboard exposes read-only state and keeps its bearer token in memory.
The operator CLI prepares signed policy envelopes without network access by default.
Apply requires mTLS and the exact prepared digest.
Success means that at least one controller accepted the exact envelope.

## Deployment boundary

The public repository contains no host addresses, credentials, or live service configuration.
Private deployments can run the public contracts in observe-only mode.
Observe-only controllers accept signed telemetry but reject policy and promotion mutations.
Router apply still requires a separate private configuration change and approval.

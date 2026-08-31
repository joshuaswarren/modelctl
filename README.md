# modelctl

`modelctl` is a provider-neutral control plane for model workloads.

The public package defines portable domain contracts for workload classes,
request metadata, engine state, reservations, budgets, runway data, durable
events, and signed policy bundles.

## Status

The API is under active development. The public repository contains generic
contracts and synthetic fixtures only. Deployment configuration belongs in a
private environment.

## OMP extension

The installed OMP extension is observe-only by default. It records what budget
and loop-containment enforcement would do, but it does not block requests,
abort work, park transcripts, close budgets, escalate, or start recovery.

Set `observeOnly: false` for explicit enforcement. When enforcement parks a
transcript after repeated equivalent output, it forks one bounded recovery
agent from the parent session with `omp --fork`. The recovery agent cannot
start another recovery agent.

## Development

Use Python 3.12 or newer and `uv`.

```sh
uv sync --extra dev
uv run pytest
uv run mypy --strict src
```

## License

Apache-2.0. See [LICENSE](LICENSE).

"""Production command for one OMP event forwarding pass."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from modelctl.telemetry.event_forwarder import load_event_forwarder_config


def forward(config_path: Path) -> int:
    result = load_event_forwarder_config(config_path).forward()
    print(
        json.dumps(
            {
                "cursor": result.cursor,
                "failed": result.failed,
                "forwarded": result.forwarded,
                "pending": result.pending,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if result.failed == 0 and not result.pending else 3


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="modelctl-event-forwarder")
    parser.add_argument("command", choices=("forward",))
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        return forward(arguments.config)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"event forwarder failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Production command for one broker-side quota collection pass."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

import yaml

from modelctl.telemetry.collector_client import load_collector_config


def collect(config_path: Path) -> int:
    """Read current snapshots and publish every sanitized record."""

    client, records = load_collector_config(config_path)
    results = client.publish(records)
    output = {
        "records": len(results),
        "sequences": [result.envelope.sequence for result in results],
        "deliveries": [dict(result.deliveries) for result in results],
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0 if results and all(any(result.deliveries.values()) for result in results) else 3


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="modelctl-quota-collector")
    parser.add_argument("command", choices=("collect",))
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        return collect(arguments.config)
    except (OSError, RuntimeError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"quota collector failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

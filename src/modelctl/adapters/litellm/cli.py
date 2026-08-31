"""Generic public-fixture CLI for LiteLLM managed-region checks."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from modelctl.domain.policy import PolicyBundle

from .core import BEGIN_MARKER, END_MARKER, render_receipt

_GENERIC_CONFIG = (
    f"# public fixture\n{BEGIN_MARKER}\n{END_MARKER}\nmanual_model: preserve\n"
).encode()
_GENERIC_POLICY: dict[str, object] = {
    "engines": [
        {
            "id": "fixture-engine",
            "host": "fixture-engine.example.test",
            "baseUrl": "https://fixture-engine.example.test:8000/v1",
            "aliases": ["fixture-auto"],
            "residentModels": ["openai/generic-model"],
            "maxSlots": 2,
            "interactiveReserved": 1,
            "health": "healthy",
            "state": "active",
        }
    ]
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="modelctl-render")
    parser.add_argument("--check", action="store_true", help="render a config without side effects")
    parser.add_argument("--config", type=Path, help="generic LiteLLM config fixture")
    parser.add_argument("--policy", type=Path, help="generic modelctl policy fixture")
    arguments = parser.parse_args(argv)
    if not arguments.check:
        parser.error("only --check is supported by this entry point")
    try:
        source = arguments.config.read_bytes() if arguments.config is not None else _GENERIC_CONFIG
        policy = _load_policy(arguments.policy)
        receipt = render_receipt(source, policy)
        output = {"dryRun": True, **receipt.as_dict()}
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, UnicodeError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"LiteLLM check failed: {exc}", file=sys.stderr)
        return 2


def _load_policy(path: Path | None) -> PolicyBundle:
    if path is None:
        return PolicyBundle.model_validate(_GENERIC_POLICY)
    value: Any = json.loads(path.read_text(encoding="utf-8"))
    return PolicyBundle.model_validate(value)


if __name__ == "__main__":
    raise SystemExit(main())

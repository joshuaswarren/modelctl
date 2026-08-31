"""Run the modelctl privacy scanner from a source checkout."""
from __future__ import annotations

import sys
from pathlib import Path

from modelctl.cli.privacy import scan_paths


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    findings = scan_paths([Path(argument) for argument in arguments or ["."]])
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

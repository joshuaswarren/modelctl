"""Validate public policy documents and scan them for private values."""
from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from modelctl.cli.privacy import scan_paths
from modelctl.domain.policy import PolicyBundle

_DOCUMENT_SUFFIXES = {".json", ".yaml", ".yml"}


def _documents(paths: Iterable[Path]) -> list[Path]:
    documents: list[Path] = []
    for requested in paths:
        path = requested.resolve()
        if path.is_file() and path.suffix.lower() in _DOCUMENT_SUFFIXES:
            documents.append(path)
        elif path.is_dir():
            documents.extend(
                candidate
                for candidate in sorted(path.rglob("*"))
                if candidate.is_file() and candidate.suffix.lower() in _DOCUMENT_SUFFIXES
            )
    return documents


def _load_document(path: Path) -> Any:
    if path.suffix.lower() != ".json":
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("YAML validation requires PyYAML") from exc
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    return json.loads(path.read_text(encoding="utf-8"))


def validate_paths(paths: Iterable[Path]) -> list[str]:
    """Return privacy and schema errors for policy documents under paths."""

    requested = list(paths)
    errors = [f"{path.resolve()}: path does not exist" for path in requested if not path.resolve().exists()]
    errors.extend(scan_paths(requested))
    for path in _documents(requested):
        try:
            PolicyBundle.model_validate(_load_document(path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
        except ValidationError as exc:
            for issue in exc.errors():
                location = ".".join(str(part) for part in issue["loc"])
                errors.append(f"{path}: {location}: {issue['msg']}")
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    errors = validate_paths([Path(argument) for argument in arguments or ["."]])
    for error in errors:
        print(error)
    if errors:
        return 1
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

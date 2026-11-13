#!/usr/bin/env python3
"""Fail if any denylisted term appears in the repository.

Reads case-insensitive regular expressions from `denylist.txt` and scans every
text file in the working tree, skipping VCS metadata, editor state, caches, and
the denylist file itself. Prints `path:line: pattern` for each match and exits
1 if anything matched.

Usage:
    python scripts/check_denylist.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DENYLIST = REPO_ROOT / "denylist.txt"

SKIP_DIRS = {
    ".git",
    ".codegraph",
    ".terraform",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
}
SKIP_FILES = {DENYLIST.name}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".example",
    ".hcl",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".tf",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def load_patterns() -> list[tuple[str, re.Pattern[str]]]:
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for raw in DENYLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append((line, re.compile(line, re.IGNORECASE)))
    return patterns


def iter_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        yield path, rel


def main() -> int:
    patterns = load_patterns()
    hits = 0
    for path, rel in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for source, pattern in patterns:
                if pattern.search(line):
                    print(f"{rel}:{lineno}: {source}")
                    hits += 1
    if hits:
        print(f"\n{hits} denylisted match(es) found.", file=sys.stderr)
        return 1
    print("Denylist scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

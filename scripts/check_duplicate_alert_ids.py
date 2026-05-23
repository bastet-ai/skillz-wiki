#!/usr/bin/env python3
"""Warn when Skillz alert pages repeat CVE/GHSA identifiers.

By default this is a non-blocking editorial guard so the existing archive can keep
building while authors see likely duplicate-alert candidates in CI. Use --fail to
turn duplicate IDs into a non-zero exit once the archive is fully normalized.

Pages can opt out by declaring either front matter or an HTML comment such as:

<!-- duplicate_of: alerts/example-canonical-page.md -->
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)
FRONT_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)
DUP_OF_RE = re.compile(r"^duplicate_of:\s*(.+?)\s*$", re.M)
DUP_COMMENT_RE = re.compile(r"<!--\s*duplicate_of:\s*(.+?)\s*-->", re.I)


def duplicate_target(markdown: str) -> str | None:
    comment = DUP_COMMENT_RE.search(markdown)
    if comment:
        return comment.group(1).strip().strip('"\'')
    match = FRONT_RE.match(markdown)
    if not match:
        return None
    dup = DUP_OF_RE.search(match.group(1))
    return dup.group(1).strip().strip('"\'') if dup else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", default="docs", help="MkDocs docs directory")
    parser.add_argument("--fail", action="store_true", help="exit non-zero when duplicate IDs are found")
    args = parser.parse_args()

    docs = Path(args.docs)
    alerts = docs / "alerts"
    by_id: dict[str, list[Path]] = defaultdict(list)
    declared_duplicates: list[tuple[Path, str]] = []

    for path in sorted(alerts.glob("*.md")):
        if path.name == "index.md":
            continue
        markdown = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(docs)
        dup_of = duplicate_target(markdown)
        if dup_of:
            declared_duplicates.append((rel, dup_of))
            continue
        # Include filename so ID-bearing slugs are caught even when the body is terse.
        ids = {m.group(0).upper() for m in ID_RE.finditer(markdown + "\n" + path.name)}
        for ident in ids:
            by_id[ident].append(rel)

    problems = {ident: paths for ident, paths in by_id.items() if len(paths) > 1}

    for rel, target in declared_duplicates:
        target_path = docs / target
        if not target_path.exists():
            print(f"ERROR: {rel} declares duplicate_of={target}, but target does not exist", file=sys.stderr)
            return 2

    if not problems:
        print("No repeated CVE/GHSA identifiers found in canonical alert pages.")
        return 0

    max_items = 80
    print(f"Duplicate CVE/GHSA identifiers found in canonical alert pages ({len(problems)} IDs):", file=sys.stderr)
    for idx, (ident, paths) in enumerate(sorted(problems.items())):
        if idx >= max_items:
            print(f"  ... {len(problems) - max_items} more omitted; run locally for the full list", file=sys.stderr)
            break
        print(f"  {ident}", file=sys.stderr)
        for rel in paths:
            print(f"    - {rel}", file=sys.stderr)
    print("\nIf a page is only a compatibility pointer, add <!-- duplicate_of: alerts/<canonical>.md -->.", file=sys.stderr)
    return 1 if args.fail else 0


if __name__ == "__main__":
    raise SystemExit(main())

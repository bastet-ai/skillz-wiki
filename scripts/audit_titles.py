#!/usr/bin/env python3
"""Audit (and optionally fix) threat.wiki title style.

Rules enforced (per AGENTS.md "short, descriptive page titles" and the
editorial checklist, hard-gated 2026-11-10 after the sweep cron produced
1,000-character thesis-titles and em-dash soup):

  - nav titles in mkdocs.yml: <= 100 characters, no em-dashes
  - H1 titles in docs/**/*.md: <= 100 characters, no em-dashes

usage:
  python3 scripts/audit_titles.py            # report violations, exit 1 if any
  python3 scripts/audit_titles.py --check    # same as default (gate mode)
  python3 scripts/audit_titles.py --fix      # shorten/scrub titles in place
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
MKDOCS = ROOT / "mkdocs.yml"
MAX_LEN = 100
EM = "\u2014"  # —
EN = "\u2013"  # –


def visible_len(title: str) -> int:
    """Length excluding markdown backticks/bold markers."""
    return len(re.sub(r"[`*]", "", title))


def _truncate(t: str) -> str:
    """Cut a title at a word boundary once visible_len hits the limit."""
    out = []
    vis = 0
    for ch in t:
        if ch not in "`*":
            vis += 1
            if vis > MAX_LEN - 1:
                break
        out.append(ch)
    cut = "".join(out).rsplit(" ", 1)[0].rstrip(" ,;:-")
    if cut.count("`") % 2:
        cut = cut.rsplit("`", 1)[0].rstrip(" ,;:-")
    return cut + "…"


def first_clause(title: str) -> str:
    """Extract the leading subject clause of a thesis-title."""
    t = title.strip()
    # 1) cut at spaced em/en dash (the dominant separator in sweep titles).
    #    Prefer this head even when slightly over: truncate at word
    #    boundary rather than degrade to a one-word colon head.
    for sep in (" — ", " – "):
        if sep in t:
            head = t.split(sep, 1)[0].strip(" ,;:")
            if 3 <= visible_len(head) <= MAX_LEN:
                return head
            if 3 <= visible_len(head) <= MAX_LEN * 1.25:
                return _truncate(head)
    # 1b) no spaced dash but over limit: cut at first bare dash only if the
    #     head still reads as a phrase (>= 2 words)
    # 2) cut at the first top-level colon when the head looks like a name
    if ": " in t:
        head = t.split(": ", 1)[0].strip(" ,;:")
        if 8 <= visible_len(head) <= MAX_LEN and len(head) <= 0.6 * len(t):
            return head
    # 3) cut at the first parenthetical
    m = re.search(r" \((?:[^)]*)\)", t)
    if m and 8 <= visible_len(t[: m.start()].strip(" ,;:")) <= MAX_LEN:
        return t[: m.start()].strip(" ,;:")
    # 4) truncate at a word boundary
    if visible_len(t) > MAX_LEN:
        # work on a marker-stripped copy to find boundary, but keep markers
        # by walking chars until visible count hits MAX_LEN-1
        out = []
        vis = 0
        for ch in t:
            if ch not in "`*":
                vis += 1
                if vis > MAX_LEN - 1:
                    break
            out.append(ch)
        cut = "".join(out)
        cut = cut.rsplit(" ", 1)[0].rstrip(" ,;:-")
        # balance stray backticks from truncation
        if cut.count("`") % 2:
            cut = cut.rsplit("`", 1)[0].rstrip(" ,;:-")
        return cut + "…"
    return t


def scrub(title: str) -> str:
    """Shorten to first clause and remove em/en dashes."""
    t = first_clause(title)
    t = t.replace(EM, ",").replace(EN, "-")
    t = re.sub(r"\s+,", ",", t)
    t = re.sub(r",\s+", ", ", t)
    t = t.strip(" ,;:")
    # final guard
    if visible_len(t) > MAX_LEN:
        return first_clause(t)  # already-truncated path
    return t


def _yaml_scalar(raw):
    """Decode a double-quoted YAML scalar; tolerant loader for python/name tags."""
    import yaml as _yaml
    try:
        return _yaml.safe_load(f'"{raw}"')
    except Exception:
        return raw


NAV_LINE = re.compile(r'^(\s*(?:-\s+)?)"((?:[^"\\]|\\.)*)":\s*(\S.*)$')
H1_LINE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def iter_h1_files():
    for path in sorted(DOCS.rglob("*.md")):
        rel = path.relative_to(DOCS).as_posix()
        if rel.startswith(("drafts/",)):
            continue
        yield path


def audit() -> list[str]:
    problems: list[str] = []
    # nav
    for i, line in enumerate(MKDOCS.read_text(encoding="utf-8").splitlines(), 1):
        m = NAV_LINE.match(line)
        if m:
            title = m.group(2)
            if visible_len(title) > MAX_LEN:
                problems.append(f"mkdocs.yml:{i}: nav title {visible_len(title)} chars: {title[:70]}…")
            if EM in title:
                problems.append(f"mkdocs.yml:{i}: nav title contains em-dash: {title[:70]}…")
    # H1s
    for path in iter_h1_files():
        text = path.read_text(encoding="utf-8")
        m = H1_LINE.search(text)
        if m:
            title = m.group(1)
            if visible_len(title) > MAX_LEN:
                problems.append(f"{path.relative_to(ROOT)}: H1 {visible_len(title)} chars: {title[:70]}…")
            if EM in title:
                problems.append(f"{path.relative_to(ROOT)}: H1 contains em-dash")
    return problems


def fix() -> int:
    n = 0
    # nav titles (raw-line rewrite preserves everything else in the YAML)
    lines = MKDOCS.read_text(encoding="utf-8").splitlines(keepends=False)
    for i, line in enumerate(lines):
        m = NAV_LINE.match(line)
        if not m:
            continue
        raw = m.group(2)
        import yaml as _yaml
        try:
            title = _yaml.safe_load(f'"{raw}"')  # decode YAML escapes to the true title
        except Exception:
            continue
        if visible_len(title) <= MAX_LEN and EM not in title and EN not in title:
            continue
        new = scrub(title)
        if new == title:
            continue  # nothing changed; leave the original line untouched
        # re-encode as a valid double-quoted YAML scalar
        new_esc = _yaml.dump(new, allow_unicode=True, default_style='"', width=10**9).strip()
        lines[i] = f"{m.group(1)}{new_esc}: {m.group(3)}"
        n += 1
    MKDOCS.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # H1 lines
    for path in iter_h1_files():
        text = path.read_text(encoding="utf-8")
        m = H1_LINE.search(text)
        if not m:
            continue
        title = m.group(1)
        if visible_len(title) <= MAX_LEN and EM not in title and EN not in title:
            continue
        new = scrub(title)
        lines_md = text.split("\n")
        for li, ln in enumerate(lines_md):
            if H1_LINE.match(ln):
                lines_md[li] = f"# {new}"
                break
        path.write_text("\n".join(lines_md), encoding="utf-8")
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="gate mode (default behaviour)")
    ap.add_argument("--fix", action="store_true", help="rewrite offending titles in place")
    args = ap.parse_args()

    if args.fix:
        n = fix()
        print(f"audit_titles: fixed {n} titles")
        # re-audit after fixing
        problems = audit()
        for p in problems[:20]:
            print("  REMAINING:", p)
        return 1 if problems else 0

    problems = audit()
    if problems:
        print(f"audit_titles: {len(problems)} title violations (max {MAX_LEN} chars, no em-dashes)")
        for p in problems[:30]:
            print("  ", p)
        if len(problems) > 30:
            print(f"   … and {len(problems) - 30} more")
        return 1
    print("audit_titles: all titles within limits")
    return 0


if __name__ == "__main__":
    sys.exit(main())

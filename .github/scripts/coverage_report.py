#!/usr/bin/env python3
"""Render `cargo llvm-cov report --json` as Markdown.

`--summary-only` prints a fixed-width table meant for a terminal: a
`Filename … Regions … Cover` header and one row per file. Piped into a job
summary or a PR comment that is a wall of unaligned text, so this reads the
JSON instead and emits a totals table plus a collapsed per-file table sorted
worst-first, which is the order anyone acting on it wants.

Usage: coverage_report.py <coverage.json> [--title TITLE]
"""

import json
import sys
from pathlib import Path

# Files at or above this line coverage are folded away; the point of the
# per-file list is to show where the gaps are.
WELL_COVERED = 90.0
# A PR comment with 150 rows is not read. Cap the list and say so.
MAX_ROWS = 40


def pct(value: float | None) -> str:
    """Percentages, or an en dash when the metric was not collected."""
    return "—" if value is None else f"{value:.2f}%"


def bar(percent: float | None, width: int = 10) -> str:
    """A small text meter, so a column of numbers is scannable."""
    if percent is None:
        return ""
    filled = round(percent / 100 * width)
    return "█" * filled + "░" * (width - filled)


def metric(totals: dict, name: str) -> tuple[int, int, float | None]:
    """(covered, total, percent) for one metric; percent is None if unmeasured."""
    m = totals.get(name) or {}
    count = m.get("count", 0)
    covered = m.get("covered", 0)
    return covered, count, (m.get("percent") if count else None)


def totals_table(totals: dict) -> str:
    rows = []
    for name, label in (
        ("lines", "Lines"),
        ("functions", "Functions"),
        ("regions", "Regions"),
        ("branches", "Branches"),
    ):
        covered, count, percent = metric(totals, name)
        if not count and name == "branches":
            # llvm-cov reports 0/0 for branches unless the build asked for
            # branch coverage; an empty row is noise, a stated one is not.
            rows.append(f"| {label} | — | — | — | not instrumented |")
            continue
        rows.append(
            f"| {label} | {covered:,} | {count:,} | {pct(percent)} | `{bar(percent)}` |"
        )
    return "\n".join(
        ["| Metric | Covered | Total | Coverage | |", "|---|---:|---:|---:|:--|", *rows]
    )


def file_rows(files: list[dict]) -> tuple[list[str], int]:
    """Per-file rows, worst line coverage first. Returns (rows, hidden_count)."""
    scored = []
    for f in files:
        summary = f.get("summary") or {}
        _, count, percent = metric(summary, "lines")
        if not count:
            continue
        scored.append((percent, f.get("filename", "?"), summary))
    scored.sort(key=lambda r: (r[0], r[1]))

    gaps = [r for r in scored if r[0] < WELL_COVERED]
    hidden = len(scored) - len(gaps)
    shown = gaps[:MAX_ROWS]

    rows = []
    for percent, name, summary in shown:
        # Paths are repo-relative already; keep them whole so they are
        # clickable in a PR comment rather than truncated to ambiguity.
        lcov, ltot, lpct = metric(summary, "lines")
        _, _, fpct = metric(summary, "functions")
        rows.append(
            f"| `{name}` | {pct(lpct)} | {lcov:,}/{ltot:,} | {pct(fpct)} | `{bar(percent)}` |"
        )
    return rows, hidden + max(0, len(gaps) - MAX_ROWS)


def render(path: Path, title: str) -> str:
    data = json.loads(path.read_text())
    block = data["data"][0]
    totals = block["totals"]
    files = block.get("files") or []

    _, _, line_pct = metric(totals, "lines")
    out = [
        f"## {title}",
        "",
        f"**{pct(line_pct)}** of lines covered.",
        "",
        totals_table(totals),
        "",
    ]

    rows, hidden = file_rows(files)
    if rows:
        out += [
            f"<details><summary>{len(rows)} file(s) below {WELL_COVERED:.0f}% line coverage</summary>",
            "",
            "| File | Lines | Covered | Functions | |",
            "|---|---:|---:|---:|:--|",
            *rows,
            "",
        ]
        if hidden:
            out.append(f"_{hidden} further file(s) not shown._")
            out.append("")
        out.append("</details>")
    elif files:
        out.append(f"_Every file is at or above {WELL_COVERED:.0f}% line coverage._")

    out += [
        "",
        "<sub>Reported, not enforced. Out-of-process suites (devnet e2e, "
        "testcontainers) do not appear in these numbers.</sub>",
    ]
    return "\n".join(out)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:]]
    title = "Code coverage"
    if "--title" in args:
        i = args.index("--title")
        title = args[i + 1]
        del args[i : i + 2]
    if len(args) != 1:
        print(f"usage: {sys.argv[0]} <coverage.json> [--title TITLE]", file=sys.stderr)
        raise SystemExit(2)
    print(render(Path(args[0]), title))

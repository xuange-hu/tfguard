"""Text reports.

The text report is the one a human reads in a terminal, so it is organised the
way an incident is worked: worst first, and every entry carrying the line it
came from plus the source text of that line. A report that says "S3 bucket has
no encryption" without saying where is a report that gets closed and forgotten.
"""

from __future__ import annotations

from tfguard.model import SEVERITIES, Finding, Report
from tfguard.rules import BY_ID, CATEGORY_LABELS, RULES

BARS = {"critical": "!!!!", "high": "!!! ", "medium": "!!  ", "low": "!   ", "info": "·   "}


def _use_color(color: bool) -> bool:
    return color


def _wrap_text(text: str, width: int, indent: str) -> list[str]:
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    cur = indent
    first = True
    for w in words:
        candidate = (cur + " " + w) if not first else (indent + w)
        if len(candidate) > width and not first:
            lines.append(cur)
            cur = indent + w
        else:
            cur = candidate
        first = False
    if cur.strip():
        lines.append(cur)
    return lines


def render_finding(f: Finding, color: bool = False, width: int = 88, show_fix: bool = False) -> list[str]:
    rule = BY_ID.get(f.rule_id)
    out: list[str] = []
    bar = BARS.get(f.severity, "    ")
    head = f"[{f.severity.upper():<8}] {f.rule_id}  {f.title}"
    out.append(f"{bar}{head}")
    out.append(f"           {f.location()}")
    if f.evidence:
        out.append(f"           | {f.evidence}")
    if f.flow:
        out.append(f"           flow: {f.flow}")
    if f.note:
        out.append(f"           note: {f.note}")
    if show_fix and rule is not None:
        out.extend(_wrap_text(f"why: {rule.why}", width, "           "))
        out.extend(_wrap_text(f"fix: {rule.fix}", width, "           "))
    del color
    return out


def render_text(
    report: Report,
    color: bool = False,
    width: int = 88,
    show_fix: bool = False,
    include_suppressed: bool = False,
) -> str:
    findings = [f for f in report.sorted() if include_suppressed or not f.suppressed]
    lines: list[str] = []
    if not findings:
        lines.append("tfguard: no findings")
        if report.files_scanned:
            lines.append(f"          {report.files_scanned} file(s) scanned, {report.resources} resource(s)")
        return "\n".join(lines)

    counts = report.counts()
    summary = "  ".join(f"{n} {s}" for s, n in counts.items() if n)
    lines.append("=" * width)
    lines.append(f"tfguard · {summary} · {report.files_scanned} file(s), {report.resources} resource(s)")
    lines.append("=" * width)

    current_cat = None
    for f in findings:
        if f.category != current_cat:
            current_cat = f.category
            label = CATEGORY_LABELS.get(f.category, f.category)
            lines.append("")
            lines.append(f"── {label} " + "─" * max(0, width - len(label) - 5))
        lines.extend(render_finding(f, color=color, width=width, show_fix=show_fix))

    suppressed = sum(1 for f in report.findings if f.suppressed)
    lines.append("")
    lines.append("-" * width)
    lines.append(f"{len(findings)} finding(s) across {len(report.by_rule())} rule(s)")
    if suppressed:
        lines.append(f"{suppressed} suppressed by an inline # tfguard: ignore comment")
    if report.errors:
        for e in report.errors:
            lines.append(f"parse error: {e}")
    return "\n".join(lines)


def render_rules(color: bool = False, category: str | None = None) -> str:
    lines: list[str] = []
    rules = [r for r in RULES if category is None or r.category == category]
    if not rules:
        return f"tfguard: no rules in category {category!r}"
    for r in rules:
        lines.append(f"{r.id}  [{r.severity:<8}] {r.title}")
    del color
    return "\n".join(lines)


def render_explain(rule_id: str, color: bool = False) -> str:
    rule = BY_ID.get(rule_id.upper())
    if rule is None:
        return f"tfguard: unknown rule {rule_id!r}"
    lines = [
        f"{rule.id} · {rule.title}",
        f"severity : {rule.severity}",
        f"category : {CATEGORY_LABELS.get(rule.category, rule.category)}",
        "",
        "why:",
        *_wrap_text(rule.why, 88, "  "),
        "",
        "fix:",
        *_wrap_text(rule.fix, 88, "  "),
    ]
    del color
    return "\n".join(lines)


def severity_counts_text(counts: dict[str, int]) -> str:
    return " ".join(f"{counts.get(s, 0)} {s}" for s in SEVERITIES)

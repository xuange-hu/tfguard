"""Data types shared by the scanner.

Nothing in here imports anything outside the standard library, and nothing in
here knows how to read a file: the model is deliberately dumb so that the
rule engine, the renderers and the MCP server can all argue over the same
objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    why: str
    fix: str
    # "aws" marks a rule that reads AWS resource types. Kept explicit so a
    # future provider can be added without pretending the AWS ones are general.
    provider: str = "aws"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    line: int
    # The source line, quoted back so the reader can see the code, not a guess.
    evidence: str = ""
    # What spilled into what. Free-form: "var.db_password -> aws_db_instance.main.password"
    flow: str = ""
    note: str = ""
    category: str = "general"
    suppressed: bool = False

    def location(self) -> str:
        if self.line:
            return f"{self.path}:{self.line}"
        return self.path

    def sort_key(self) -> tuple[int, str, int, str, str]:
        # Severity first, then category so each group prints contiguously,
        # then line so a file reads top to bottom. Sorting by line before
        # category is what makes the text report jump between groups.
        return (SEVERITY_RANK[self.severity], self.category, self.line, self.rule_id, self.path)

    def as_dict(self) -> dict[str, Any]:
        out = {
            "rule": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "file": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "category": self.category,
        }
        if self.flow:
            out["flow"] = self.flow
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_failed: int = 0
    errors: list[str] = field(default_factory=list)
    resources: int = 0

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def worst(self) -> str | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def filtered(self, min_severity: str = "info", include_suppressed: bool = False) -> list[Finding]:
        floor = SEVERITY_RANK[min_severity]
        return [
            f
            for f in self.sorted()
            if SEVERITY_RANK[f.severity] <= floor and (include_suppressed or not f.suppressed)
        ]

    def by_rule(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.rule_id, []).append(f)
        return out


def severity_at_least(value: str, floor: str) -> bool:
    return SEVERITY_RANK[value] <= SEVERITY_RANK[floor]

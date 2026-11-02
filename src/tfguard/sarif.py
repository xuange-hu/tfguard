"""SARIF 2.1.0 output, so findings land in GitHub code scanning.

Hand-rolled because pulling in a SARIF library for one document shape is how a
"zero dependencies" project quietly becomes five. Every rule that fired is
described in ``runs[0].tool.driver.rules``, which is what makes the
code-scanning UI show a readable description instead of a bare id.
"""

from __future__ import annotations

import json
import os

from tfguard.model import Finding, Report
from tfguard.rules import BY_ID

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _uri(path: str) -> str:
    """A SARIF uri is a forward-slash path on every platform.

    Replacing only ``os.sep`` is right on Windows and wrong on Linux: a
    Windows path scanned on a Linux runner kept its backslashes and GitHub
    could not resolve the artifact.
    """
    return path.replace("\\", "/").replace(os.sep, "/")


def _message(f: Finding) -> str:
    base = f.title
    if f.note:
        base = f"{base} ({f.note})"
    if f.flow:
        base = f"{base} — {f.flow}"
    return base


def dumps(report: Report, version: str = "0.1.0", min_severity: str = "info") -> str:
    findings = report.filtered(min_severity)
    rules_seen = {f.rule_id: BY_ID[f.rule_id] for f in findings if f.rule_id in BY_ID}

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tfguard",
                        "version": version,
                        "informationUri": "https://github.com/xuange-hu/tfguard",
                        "rules": [
                            {
                                "id": rule.id,
                                "name": rule.id,
                                "shortDescription": {"text": rule.title},
                                "fullDescription": {"text": f"{rule.why}\n\nFix: {rule.fix}"},
                                "help": {
                                    "text": rule.fix,
                                    "markdown": (
                                        f"**{rule.title}**\n\n{rule.why}\n\n**Fix:** {rule.fix}"
                                    ),
                                },
                                "defaultConfiguration": {"level": _LEVEL[rule.severity]},
                                "properties": {
                                    "tags": ["terraform", "IaC", "security", rule.category],
                                    "precision": "high",
                                },
                            }
                            for rule in sorted(rules_seen.values(), key=lambda r: r.id)
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": _LEVEL[f.severity],
                        "message": {"text": _message(f)},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _uri(f.path)},
                                    "region": {
                                        "startLine": max(1, f.line),
                                        "snippet": {"text": f.evidence},
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "severity": f.severity,
                            "category": f.category,
                        },
                    }
                    for f in findings
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def counts(report: Report) -> dict[str, int]:
    return report.counts()

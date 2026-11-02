"""Shared test helpers.

Every rule test runs against a real file on disk rather than a string, because
that is the only way the scanner's file path, line number and evidence fields
are exercised at all.
"""

from __future__ import annotations

import os

import pytest

from tfguard.analyze import scan_documents
from tfguard.loader import load_file
from tfguard.model import Report


def write_files(tmp_path, files: dict[str, str]) -> str:
    base = os.path.join(str(tmp_path), "ws")
    os.makedirs(base, exist_ok=True)
    for name, text in files.items():
        path = os.path.join(base, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return base


def scan_dir(path: str) -> Report:
    from tfguard.loader import iter_tf_files

    files = [load_file(f, base=path) for f in iter_tf_files(path)]
    return scan_documents(files)


def scan_snippet(text: str, tmp_path, name: str = "main.tf") -> Report:
    base = write_files(tmp_path, {name: text})
    return scan_dir(base)


def rules_of(report: Report) -> set[str]:
    return {f.rule_id for f in report.findings if not f.suppressed}


def rule_lines(report: Report, rule_id: str) -> list[int]:
    return sorted(f.line for f in report.findings if f.rule_id == rule_id and not f.suppressed)


@pytest.fixture()
def scan(tmp_path):
    """``scan(text)`` / ``scan({...})`` returns a Report for that workspace."""

    def _scan(files, **kwargs):
        if isinstance(files, str):
            files = {"main.tf": files}
        base = write_files(tmp_path, files)
        del kwargs
        return scan_dir(base)

    return _scan


@pytest.fixture()
def rules(tmp_path):
    """``rules(text)`` returns the set of rule ids that fired."""

    def _rules(files):
        if isinstance(files, str):
            files = {"main.tf": files}
        base = write_files(tmp_path, files)
        return rules_of(scan_dir(base))

    return _rules

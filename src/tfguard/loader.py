"""Finding Terraform files and reading their suppression comments.

Suppression is deliberately local to a line, because that is the only place
the reader can see the reason: an ignore that silently blanks a whole file
makes the report look clean while the configuration is unchanged.
"""

from __future__ import annotations

import os
import re

from tfguard.hcl import Document, HclError, parse

TF_SUFFIXES = (".tf",)
IGNORE_RE = re.compile(r"#\s*tfguard:\s*ignore\s+([A-Za-z0-9_,\s]+)")
IGNORE_ANY_RE = re.compile(r"#\s*tfguard:\s*ignore\b")

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".terraform",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}

REASON_RE = re.compile(r"#\s*tfguard:\s*ignore\s+[A-Za-z0-9_,\s]*?--\s*(.+)$")


def iter_tf_files(path: str) -> list[str]:
    """Return every ``.tf`` file under ``path``, in a stable order."""
    if os.path.isfile(path):
        return [path] if path.endswith(TF_SUFFIXES) else []
    out: list[str] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(TF_SUFFIXES):
                out.append(os.path.join(root, name))
    return sorted(out)


def read_text(path: str) -> str:
    # Explicit encoding everywhere: on the Windows runner open() defaults to
    # cp1252 and a .tf file with a UTF-8 identifier in it would raise.
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def suppression_map(text: str) -> dict[int, set[str]]:
    """Map "line that a suppression covers" -> rule ids (empty = all rules).

    An ignore comment on its own line covers the line under it; an ignore
    comment trailing a definition covers that same line.
    """
    out: dict[int, set[str]] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        m = IGNORE_RE.search(line)
        if not m and IGNORE_ANY_RE.search(line):
            # Bare "# tfguard: ignore" with no ids: covers every rule there.
            j = i if _looks_like_definition(line) else i + 1
            out.setdefault(j, set())
            continue
        if not m:
            continue
        ids = {t.strip().upper() for t in m.group(1).split(",") if t.strip()}
        target = i if _looks_like_definition(line) else i + 1
        out.setdefault(target, set()).update(ids)
    return out


def _looks_like_definition(line: str) -> bool:
    """True when the line itself declares something, not just a bare comment."""
    before, _, _ = line.partition("#")
    return bool(before.strip())


def suppression_reasons(text: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for i, line in enumerate(text.splitlines(), start=1):
        m = REASON_RE.search(line)
        if m:
            out[i] = m.group(1).strip()
    return out


class LoadedFile:
    """A parsed Terraform file plus the metadata the scanner needs around it."""

    __slots__ = ("path", "text", "doc", "suppressions", "reasons", "error")

    def __init__(
        self,
        path: str,
        text: str,
        doc: Document | None,
        suppressions: dict[int, set[str]],
        reasons: dict[int, str],
        error: str | None = None,
    ):
        self.path = path
        self.text = text
        self.doc = doc
        self.suppressions = suppressions
        self.reasons = reasons
        self.error = error

    def is_suppressed(self, line: int, rule_id: str) -> bool:
        ids = self.suppressions.get(line)
        if ids is None:
            return False
        if not ids:
            return True
        return rule_id.upper() in ids

    def reason_for(self, line: int) -> str:
        return self.reasons.get(line, "") or self.reasons.get(line - 1, "")

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""


def load_file(path: str, base: str = "") -> LoadedFile:
    text = read_text(path)
    sup = suppression_map(text)
    reasons = suppression_reasons(text)
    try:
        doc = parse(text)
    except HclError as exc:
        return LoadedFile(path, text, None, sup, reasons, f"{exc.message} (line {exc.line})")
    doc.path = _display_path(path, base)
    return LoadedFile(path, text, doc, sup, reasons)


def load_path(path: str, base: str = "") -> list[LoadedFile]:
    return [load_file(f, base) for f in iter_tf_files(path)]


def _display_path(path: str, base: str) -> str:
    if base:
        try:
            rel = os.path.relpath(path, base)
            if not rel.startswith(".."):
                return rel.replace(os.sep, "/")
        except ValueError:  # pragma: no cover - different drives on Windows
            pass
    return path.replace(os.sep, "/")

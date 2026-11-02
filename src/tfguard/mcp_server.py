"""MCP server: the same scanner as six tools.

The MCP extra is optional on purpose. ``pip install tfguard`` gives a working
CLI; ``pip install "tfguard[mcp]"`` additionally lets Claude Code, Cursor or
Cline call the scanner as a tool. Nothing in the core imports ``mcp``.
"""

from __future__ import annotations

from tfguard import __version__
from tfguard import analyze as _analyze
from tfguard import demo as _demo
from tfguard import sarif as _sarif
from tfguard.loader import load_path
from tfguard.model import SEVERITIES
from tfguard.rules import BY_ID, RULES


def _scan_report(path: str):
    files = load_path(path, base=path)
    if not files:
        raise FileNotFoundError(f"no .tf files under {path}")
    return _analyze.scan_documents(files)


def tool_manifest() -> list[dict]:
    """Every tool with a non-empty description, for tests and for docs."""
    return [
        {
            "name": "tfguard_scan",
            "description": (
                "Audit a Terraform or OpenTofu workspace (a directory or one .tf file) and return "
                "findings with file, line and the source line that caused them. Optionally emit SARIF."
            ),
        },
        {
            "name": "tfguard_rules",
            "description": "List the rule set, optionally filtered to one category.",
        },
        {
            "name": "tfguard_explain",
            "description": "Explain one rule: what it detects, why it matters and the fix.",
        },
        {
            "name": "tfguard_parse",
            "description": "Parse a .tf file and return its blocks, attributes and resolved values as JSON.",
        },
        {
            "name": "tfguard_taint",
            "description": (
                "Follow credential-shaped values backwards through variables and locals to the literal "
                "they come from, so a secret is reported where it is declared."
            ),
        },
        {
            "name": "tfguard_demo",
            "description": "Write a deliberately hostile Terraform workspace and report on it.",
        },
    ]


def tfguard_scan_tool(
    path: str,
    min_severity: str = "info",
    category: str | None = None,
    fmt: str = "text",
) -> str:
    report = _scan_report(path)
    if min_severity not in SEVERITIES:
        raise ValueError(f"min_severity must be one of {SEVERITIES}")
    rows = [f for f in report.filtered(min_severity) if category is None or f.category == category]
    if fmt == "sarif":
        return _sarif.dumps(report, version=__version__, min_severity=min_severity)
    if fmt == "json":
        import json

        return json.dumps(
            {
                "counts": report.counts(),
                "files_scanned": report.files_scanned,
                "resources": report.resources,
                "findings": [f.as_dict() for f in rows],
            },
            indent=2,
            ensure_ascii=False,
        )
    lines = [f"{r.severity.upper():<8} {r.rule_id}  {r.location()}  {r.title}" for r in rows]
    return "\n".join(lines) if lines else "tfguard: no findings"


def tfguard_rules_tool(category: str | None = None) -> str:
    rows = [r for r in RULES if category is None or r.category == category]
    return "\n".join(f"{r.id}  [{r.severity:<8}] {r.title}" for r in rows)


def tfguard_explain_tool(rule: str) -> str:
    r = BY_ID.get(rule.upper())
    if r is None:
        raise ValueError(f"unknown rule {rule!r}")
    return f"{r.id} [{r.severity}] {r.title}\n\nwhy: {r.why}\n\nfix: {r.fix}"


def tfguard_parse_tool(path: str) -> str:
    import json

    from tfguard.hcl import parse
    from tfguard.loader import read_text

    doc = parse(read_text(path), path=path)
    return json.dumps(_dump(doc.body), indent=2, ensure_ascii=False)


def _dump(body) -> list[dict]:
    from tfguard.hcl import Attribute

    out = []
    for item in body.items:
        if isinstance(item, Attribute):
            out.append({"attr": item.name, "line": item.line, "value": _py(item.value.as_py())})
        else:
            out.append(
                {
                    "block": item.kind,
                    "labels": item.labels,
                    "line": item.line,
                    "body": _dump(item.body),
                }
            )
    return out


def _py(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_py(v) for v in value]
    if isinstance(value, dict):
        return {k: _py(v) for k, v in value.items()}
    return str(value)


def tfguard_taint_tool(path: str) -> str:
    """Where every credential-shaped value actually comes from."""
    files = load_path(path, base=path)
    parsed = [f for f in files if f.doc is not None]
    scope = _analyze._build_scope(parsed)
    lines: list[str] = []
    for name, entry in sorted(scope.vars.items()):
        if not _analyze._is_secret_name(name):
            continue
        got = scope.literal_behind(entry["default"]) if entry["default"] is not None else None
        origin = "literal default" if got and not got[1] else ("through " + " -> ".join(got[1]) if got else "no literal")
        lines.append(
            f"var.{name} ({entry['loaded'].doc.path}:{entry['line']}) sensitive={entry['sensitive']} origin={origin}"
        )
    for loaded in parsed:
        for block in loaded.doc.all_blocks():
            if block.kind != "resource":
                continue
            for a in block.body.attrs():
                if not _analyze._is_secret_name(a.name):
                    continue
                got = scope.literal_behind(a.value)
                if got:
                    lines.append(
                        f"{block.address}.{a.name} ({loaded.doc.path}:{a.line}) <- "
                        + (" -> ".join(got[1]) if got[1] else "literal")
                    )
    return "\n".join(lines) if lines else "tfguard: no credential-shaped values"


def tfguard_demo_tool(directory: str = "demo-workspace") -> str:
    _demo.write_demo(directory)
    report = _scan_report(directory)
    return "\n".join(
        f"{f.severity.upper():<8} {f.rule_id}  {f.location()}  {f.title}" for f in report.sorted()
    )


def build_server():
    """Build the MCP server. Requires the ``mcp`` extra."""
    from mcp.server.fastmcp import FastMCP  # noqa: PLC0415 - optional dependency

    mcp = FastMCP("tfguard")
    manifest = {t["name"] for t in tool_manifest()}

    @mcp.tool(name="tfguard_scan")
    def scan(
        path: str,
        min_severity: str = "info",
        category: str = "",
        fmt: str = "text",
    ) -> str:
        return tfguard_scan_tool(path, min_severity, category or None, fmt)

    @mcp.tool(name="tfguard_rules")
    def rules(category: str = "") -> str:
        return tfguard_rules_tool(category or None)

    @mcp.tool(name="tfguard_explain")
    def explain(rule: str) -> str:
        return tfguard_explain_tool(rule)

    @mcp.tool(name="tfguard_parse")
    def parse(path: str) -> str:
        return tfguard_parse_tool(path)

    @mcp.tool(name="tfguard_taint")
    def taint(path: str) -> str:
        return tfguard_taint_tool(path)

    @mcp.tool(name="tfguard_demo")
    def demo(directory: str = "demo-workspace") -> str:
        return tfguard_demo_tool(directory)

    assert manifest, "the manifest is what tests assert against"
    return mcp


def main() -> None:
    server = build_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover
    main()

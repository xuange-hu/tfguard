"""Command line entry point.

Every subcommand is a thin wrapper over the same scanner, so `tfguard scan`
and the MCP tool `.tfguard_scan` cannot disagree about what a workspace means.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys

from tfguard import __version__
from tfguard import analyze as _analyze
from tfguard import demo as _demo
from tfguard import render as _render
from tfguard import sarif as _sarif
from tfguard.loader import load_path
from tfguard.model import SEVERITIES, Report
from tfguard.rules import BY_ID

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tfguard",
        description="Zero-dependency Terraform / OpenTofu configuration audit.",
    )
    parser.add_argument("--version", action="version", version=f"tfguard {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a directory or a single .tf file")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p_scan.add_argument("--output", help="write the report to a file instead of stdout")
    p_scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        help="exit 1 when a finding at or above this severity is present",
    )
    p_scan.add_argument("--min-severity", choices=SEVERITIES, default="info", dest="min_severity")
    p_scan.add_argument("--category", help="only report rules in this category")
    p_scan.add_argument("--rule", action="append", dest="rules", help="only report this rule (repeatable)")
    p_scan.add_argument("--explain", action="store_true", help="print why/fix under each finding")
    p_scan.add_argument("--show-suppressed", action="store_true", dest="show_suppressed")
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser("rules", help="list the rule set")
    p_rules.add_argument("--category")
    p_rules.set_defaults(func=cmd_rules)

    p_explain = sub.add_parser("explain", help="explain one rule")
    p_explain.add_argument("rule")
    p_explain.set_defaults(func=cmd_explain)

    p_demo = sub.add_parser("demo", help="write a deliberately hostile workspace and show its report")
    p_demo.add_argument("--dir", default="demo-workspace")
    p_demo.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p_demo.set_defaults(func=cmd_demo)

    p_parse = sub.add_parser("parse", help="print the parsed structure of a .tf file")
    p_parse.add_argument("path")
    p_parse.set_defaults(func=cmd_parse)

    p_graph = sub.add_parser("graph", help="print the relationships between blocks")
    p_graph.add_argument("path")
    p_graph.set_defaults(func=cmd_graph)

    return parser


def _report_for(path: str) -> Report:
    files = load_path(path, base=path)
    if not files:
        raise SystemExit(f"tfguard: no .tf files under {path}")
    return _analyze.scan_documents(files)


def _filtered(report: Report, min_severity: str, category: str | None, rules: list[str] | None) -> Report:
    if min_severity == "info" and not category and not rules:
        return report
    wanted = {r.upper() for r in rules} if rules else None
    keep = []
    for f in report.findings:
        if f.suppressed:
            continue
        if _rank(f.severity) > _rank(min_severity):
            continue
        if category and f.category != category:
            continue
        if wanted and f.rule_id.upper() not in wanted:
            continue
        keep.append(f)
    report.findings = keep
    return report


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def _use_utf8_stdout() -> None:
    """Make the console tolerate the report's non-ASCII.

    The Windows runner's console codepage is cp1252, and the text report
    carries box-drawing characters and a middle dot. Without this, printing
    it raises UnicodeEncodeError before a single finding reaches the reader.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(ValueError, OSError):  # a closed or unusual stream
            reconfigure(encoding="utf-8", errors="replace")


def _emit(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        return
    payload = text + "\n"
    try:
        sys.stdout.write(payload)
    except UnicodeEncodeError:
        # Still the narrow-console case when reconfigure was unavailable, for
        # example under a test that captured stdout before this ran.
        buffer = getattr(sys.stdout, "buffer", None)
        if buffer is not None:
            buffer.write(payload.encode("utf-8", "replace"))
            buffer.flush()
        else:
            sys.stdout.write(payload.encode("ascii", "replace").decode("ascii"))


def cmd_scan(args: argparse.Namespace) -> int:
    report = _report_for(args.path)
    report = _filtered(report, args.min_severity, args.category, args.rules)
    findings = [f for f in report.findings if args.show_suppressed or not f.suppressed]

    if args.format == "json":
        payload = {
            "tool": "tfguard",
            "version": __version__,
            "files_scanned": report.files_scanned,
            "resources": report.resources,
            "counts": report.counts(),
            "findings": [
                f.as_dict() for f in report.sorted() if args.show_suppressed or not f.suppressed
            ],
            "errors": report.errors,
        }
        _emit(json.dumps(payload, indent=2, ensure_ascii=False), args.output)
    elif args.format == "sarif":
        _emit(_sarif.dumps(report, version=__version__, min_severity=args.min_severity), args.output)
    else:
        _emit(
            _render.render_text(
                report,
                show_fix=args.explain,
                include_suppressed=args.show_suppressed,
            ),
            args.output,
        )

    if args.fail_on:
        floor = _rank(args.fail_on)
        if any(_rank(f.severity) <= floor for f in findings):
            return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_rules(args: argparse.Namespace) -> int:
    _emit(_render.render_rules(category=args.category), None)
    return EXIT_CLEAN


def cmd_explain(args: argparse.Namespace) -> int:
    if args.rule.upper() not in BY_ID:
        sys.stderr.write(f"tfguard: unknown rule {args.rule!r}\n")
        return EXIT_USAGE
    _emit(_render.render_explain(args.rule), None)
    return EXIT_CLEAN


def cmd_demo(args: argparse.Namespace) -> int:
    _demo.write_demo(args.dir)
    report = _report_for(args.dir)
    if args.format == "json":
        payload = {
            "files_scanned": report.files_scanned,
            "resources": report.resources,
            "counts": report.counts(),
            "findings": [f.as_dict() for f in report.sorted()],
        }
        _emit(json.dumps(payload, indent=2, ensure_ascii=False), None)
    elif args.format == "sarif":
        _emit(_sarif.dumps(report, version=__version__), None)
    else:
        _emit(_render.render_text(report), None)
    return EXIT_CLEAN


def cmd_parse(args: argparse.Namespace) -> int:
    from tfguard.hcl import parse
    from tfguard.loader import read_text

    doc = parse(read_text(args.path), path=args.path)
    _emit(_describe(doc.body, 0), None)
    return EXIT_CLEAN


def _describe(body, depth: int) -> str:
    from tfguard.hcl import Attribute  # noqa: PLC0415 - only needed for the describe view

    pad = "  " * depth
    lines = []
    for item in body.items:
        if isinstance(item, Attribute):
            lines.append(f"{pad}{item.name} = {item.value.as_py()!r}")
        else:
            labels = " ".join(f'"{label}"' for label in item.labels)
            head = f"{item.kind} {labels}".strip()
            lines.append(f"{pad}{head} {{   # line {item.line}")
            lines.append(_describe(item.body, depth + 1))
            lines.append(f"{pad}}}")
    return "\n".join(lines)


def cmd_graph(args: argparse.Namespace) -> int:
    from tfguard.analyze import _refs_to  # noqa: PLC0415 - the private helper is the graph
    from tfguard.loader import load_path

    files = load_path(args.path, base=args.path)
    edges: list[tuple[str, str, str]] = []
    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.all_blocks():
            for attr in block.body.attrs():
                for prefix in ("aws_security_group", "aws_vpc", "aws_iam_role"):
                    for target in _refs_to(attr.value, prefix):
                        edges.append((block.address, attr.name, target))
    lines = [f"{src} .{attr} -> {dst}" for src, attr, dst in edges]
    _emit("\n".join(lines) if lines else "tfguard: no references between blocks", None)
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    _use_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return args.func(args)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

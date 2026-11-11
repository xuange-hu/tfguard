"""Command line behaviour, driven by calling main() in process."""

from __future__ import annotations

import json
import os

import pytest

from tfguard.cli import main


def _run(capsys, argv) -> tuple[int, str]:
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out + out.err


def test_scan_clean_workspace_exits_zero(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "clean")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('locals {\n  a = 1\n}\n')
    code, out = _run(capsys, ["scan", path])
    assert code == 0
    assert "no findings" in out


def test_scan_json_shape(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('resource "aws_vpc" "v" {}\n')
    code, out = _run(capsys, ["scan", path, "--format", "json"])
    assert code == 0
    data = json.loads(out)
    assert data["files_scanned"] == 1
    assert data["findings"]
    assert all(f["line"] >= 1 for f in data["findings"])


def test_fail_on_high_exits_one(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(
            'resource "aws_security_group" "web" {\n'
            "  ingress {\n"
            "    from_port   = 22\n"
            "    to_port     = 22\n"
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
            "}\n"
        )
    code, _ = _run(capsys, ["scan", path, "--fail-on", "high"])
    assert code == 1


def test_fail_on_critical_passes_when_only_medium_is_present(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n')
    code, _ = _run(capsys, ["scan", path, "--fail-on", "critical"])
    assert code == 0


def test_fail_on_none_never_fails(capsys, tmp_path):
    """`none` is the report-only gate: an open 0.0.0.0/0 ingress exits 1 at
    high, and 0 when the operator asked not to gate on it."""
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(
            'resource "aws_security_group" "web" {\n'
            "  ingress {\n"
            "    from_port   = 22\n"
            "    to_port     = 22\n"
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            "  }\n"
            "}\n"
        )
    assert _run(capsys, ["scan", path, "--fail-on", "high"])[0] == 1
    assert _run(capsys, ["scan", path, "--fail-on", "none"])[0] == 0


def test_min_severity_filters(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(
            'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
            'resource "aws_security_group" "s" {\n'
            "  ingress {\n    from_port = 22\n    to_port = 22\n"
            '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        )
    _code, out = _run(capsys, ["scan", path, "--format", "json", "--min-severity", "critical"])
    data = json.loads(out)
    assert [f["rule"] for f in data["findings"]] == ["TFG001"]


def test_rule_filter(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
    _code, out = _run(capsys, ["scan", path, "--format", "json", "--rule", "TFG010"])
    data = json.loads(out)
    assert {f["rule"] for f in data["findings"]} == {"TFG010"}


def test_rules_lists_every_rule(capsys):
    code, out = _run(capsys, ["rules"])
    assert code == 0
    assert len(out.strip().splitlines()) == 40


def test_rules_by_category(capsys):
    code, out = _run(capsys, ["rules", "--category", "identity"])
    assert code == 0
    assert all("TFG03" in line for line in out.strip().splitlines())


def test_explain_prints_why_and_fix(capsys):
    code, out = _run(capsys, ["explain", "TFG001"])
    assert code == 0
    assert "why:" in out and "fix:" in out


def test_explain_unknown_rule_exits_two(capsys):
    code, out = _run(capsys, ["explain", "TFG999"])
    assert code == 2
    assert "unknown rule" in out


def test_parse_prints_structure(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "main.tf")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
    code, out = _run(capsys, ["parse", path])
    assert code == 0
    assert 'resource "aws_s3_bucket" "b"' in out
    assert "bucket" in out


def test_graph_prints_references(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(
            'resource "aws_security_group" "web" {}\n'
            'resource "aws_instance" "i" {\n  vpc_security_group_ids = [aws_security_group.web.id]\n}\n'
        )
    code, out = _run(capsys, ["graph", path])
    assert code == 0
    assert "aws_security_group.web" in out


def test_graph_without_references(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write("locals {\n  a = 1\n}\n")
    code, out = _run(capsys, ["graph", path])
    assert code == 0
    assert "no references" in out


def test_scan_missing_path_exits(capsys, tmp_path):
    with pytest.raises(SystemExit):
        main(["scan", os.path.join(str(tmp_path), "nope")])


def test_output_writes_a_file(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('resource "aws_vpc" "v" {}\n')
    out_file = os.path.join(str(tmp_path), "report.sarif")
    code, _ = _run(capsys, ["scan", path, "--format", "sarif", "--output", out_file])
    assert code == 0
    with open(out_file, encoding="utf-8") as fh:
        text = fh.read()
    assert '"version": "2.1.0"' in text


def test_demo_writes_and_reports(capsys, tmp_path):
    target = os.path.join(str(tmp_path), "demo")
    code, out = _run(capsys, ["demo", "--dir", target])
    assert code == 0
    assert os.path.isfile(os.path.join(target, "versions.tf"))
    assert "TFG001" in out


def test_no_subcommand_prints_help(capsys):
    code, out = _run(capsys, [])
    assert code == 2
    assert "usage" in out.lower()


def test_explain_flag_adds_why_and_fix(capsys, tmp_path):
    path = os.path.join(str(tmp_path), "ws")
    os.makedirs(path)
    with open(os.path.join(path, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('resource "aws_vpc" "v" {}\n')
    code, out = _run(capsys, ["scan", path, "--explain"])
    assert code == 0
    assert "why:" in out
    assert "fix:" in out


def test_emit_falls_back_to_the_buffer_when_the_console_is_narrow(monkeypatch):
    """The Windows runner's console is cp1252; the report is not ASCII.

    Without the buffer fallback the report dies with UnicodeEncodeError before
    a single finding reaches the reader.
    """
    import io

    import tfguard.cli as cli

    class _Narrow:
        encoding = "cp1252"

        def __init__(self):
            self.buffer = io.BytesIO()

        def write(self, text):
            # A console that cannot encode the report's separators.
            self.buffer.write(text.encode(self.encoding))

    narrow = _Narrow()
    monkeypatch.setattr("sys.stdout", narrow)
    cli._emit("tfguard · ─── → 3 critical", None)
    assert narrow.buffer.getvalue(), "the report must reach the reader, not die"
    assert "critical" in narrow.buffer.getvalue().decode("utf-8", "replace")

"""MCP surface.

``mcp`` is an extra, so these tests assert the parts that must work without it
(manifest, tool functions) and guard the parts that need it.
"""

from __future__ import annotations

import importlib.util

import pytest

from tfguard import mcp_server


def test_manifest_has_six_tools_with_descriptions():
    manifest = mcp_server.tool_manifest()
    assert len(manifest) == 6
    for tool in manifest:
        assert tool["name"].startswith("tfguard_")
        assert tool["description"].strip()


def test_scan_tool_text_output(tmp_path):
    base = tmp_path / "ws"
    base.mkdir()
    (base / "main.tf").write_text('resource "aws_vpc" "v" {}\n', encoding="utf-8")
    out = mcp_server.tfguard_scan_tool(str(base))
    assert "TFG023" in out


def test_scan_tool_json_output(tmp_path):
    import json

    base = tmp_path / "ws"
    base.mkdir()
    (base / "main.tf").write_text('resource "aws_vpc" "v" {}\n', encoding="utf-8")
    out = mcp_server.tfguard_scan_tool(str(base), fmt="json")
    data = json.loads(out)
    assert data["findings"]


def test_scan_tool_sarif_output(tmp_path):
    base = tmp_path / "ws"
    base.mkdir()
    (base / "main.tf").write_text('resource "aws_vpc" "v" {}\n', encoding="utf-8")
    out = mcp_server.tfguard_scan_tool(str(base), fmt="sarif")
    assert '"version": "2.1.0"' in out


def test_scan_tool_rejects_a_bad_severity(tmp_path):
    base = tmp_path / "ws"
    base.mkdir()
    (base / "main.tf").write_text("locals { a = 1 }\n", encoding="utf-8")
    with pytest.raises(ValueError):
        mcp_server.tfguard_scan_tool(str(base), min_severity="urgent")


def test_scan_tool_raises_when_there_is_nothing_to_scan(tmp_path):
    with pytest.raises(FileNotFoundError):
        mcp_server.tfguard_scan_tool(str(tmp_path))


def test_rules_tool_lists_every_rule():
    out = mcp_server.tfguard_rules_tool()
    assert len(out.splitlines()) == 40


def test_rules_tool_filters_by_category():
    out = mcp_server.tfguard_rules_tool("identity")
    assert out
    assert all("TFG03" in line for line in out.splitlines())


def test_explain_tool(tmp_path):
    out = mcp_server.tfguard_explain_tool("TFG001")
    assert "why:" in out and "fix:" in out


def test_explain_tool_unknown():
    with pytest.raises(ValueError):
        mcp_server.tfguard_explain_tool("TFG999")


def test_parse_tool_returns_json(tmp_path):
    import json

    path = tmp_path / "main.tf"
    path.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n', encoding="utf-8")
    data = json.loads(mcp_server.tfguard_parse_tool(str(path)))
    assert data[0]["block"] == "resource"
    assert data[0]["body"][0]["attr"] == "bucket"


def test_taint_tool_traces_the_origin(tmp_path):
    base = tmp_path / "ws"
    base.mkdir()
    (base / "v.tf").write_text('variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n', encoding="utf-8")
    (base / "r.tf").write_text('resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n', encoding="utf-8")
    out = mcp_server.tfguard_taint_tool(str(base))
    assert "var.db_password" in out
    assert "aws_db_instance.d.password" in out


def test_taint_tool_without_credentials(tmp_path):
    base = tmp_path / "ws"
    base.mkdir()
    (base / "main.tf").write_text('locals {\n  name = "plain"\n}\n', encoding="utf-8")
    assert "no credential-shaped values" in mcp_server.tfguard_taint_tool(str(base))


def test_demo_tool(tmp_path):
    out = mcp_server.tfguard_demo_tool(str(tmp_path / "d"))
    assert "TFG001" in out


def test_build_server_is_guarded_by_the_extra():
    """Without the extra, building the server must fail loudly, not silently."""
    if importlib.util.find_spec("mcp") is None:
        with pytest.raises((ImportError, ModuleNotFoundError)):
            mcp_server.build_server()
    else:  # pragma: no cover - only when the extra is installed
        server = mcp_server.build_server()
        names = [t.name for t in _sync_list(server)]
        assert len(names) == 6
        for expected in ("tfguard_scan", "tfguard_rules", "tfguard_explain", "tfguard_parse", "tfguard_taint", "tfguard_demo"):
            assert expected in names


def _sync_list(server):  # pragma: no cover - only used with the extra
    import asyncio

    return asyncio.run(server.list_tools())

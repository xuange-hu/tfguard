"""The demo workspace.

TFG060 (no remote backend) and TFG061 (remote backend that is not encrypted)
cannot both fire in one workspace, which is why the demo ships its backend in
its own file: deleting that file is what surfaces the other rule.
"""

from __future__ import annotations

import os

import pytest

from tfguard.analyze import scan_documents
from tfguard.demo import FILES, write_demo
from tfguard.loader import iter_tf_files, load_file
from tfguard.rules import RULES

DEMO_RULES = [r.id for r in RULES if r.id != "TFG060"]


def _scan_demo(path) -> list[str]:
    files = [load_file(f, base=path) for f in iter_tf_files(path)]
    return scan_documents(files)


@pytest.fixture(scope="module")
def demo_dir(tmp_path_factory):
    path = os.path.join(str(tmp_path_factory.mktemp("demo")), "demo-workspace")
    write_demo(path)
    return path


def test_demo_writes_every_file(demo_dir):
    for name in FILES:
        assert os.path.isfile(os.path.join(demo_dir, name))


def test_demo_reports_every_rule_that_can_fire_here(demo_dir):
    report = _scan_demo(demo_dir)
    fired = {f.rule_id for f in report.findings if not f.suppressed}
    missing = [r for r in DEMO_RULES if r not in fired]
    assert not missing, f"the demo does not exercise {missing}"


def test_demo_never_crashes_the_parser(demo_dir):
    report = _scan_demo(demo_dir)
    assert report.errors == [], report.errors
    assert report.files_failed == 0


def test_removing_the_backend_surfaces_the_other_rule(demo_dir, tmp_path):
    path = os.path.join(str(tmp_path), "nobackend")
    os.makedirs(path, exist_ok=True)
    for name, text in FILES.items():
        if name == "state.tf":
            continue
        with open(os.path.join(path, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    report = _scan_demo(path)
    fired = {f.rule_id for f in report.findings if not f.suppressed}
    assert "TFG060" in fired
    assert "TFG061" not in fired


def test_demo_finding_count_is_stable(demo_dir):
    report = _scan_demo(demo_dir)
    assert report.counts()["critical"] >= 5
    assert report.resources > 10


def test_demo_has_no_unparsed_files(demo_dir):
    report = _scan_demo(demo_dir)
    assert report.files_scanned == len(FILES)


def test_demo_evidence_is_never_empty(demo_dir):
    report = _scan_demo(demo_dir)
    for f in report.findings:
        assert f.evidence.strip(), f"{f.rule_id} at {f.location()} has no evidence"


def test_demo_lines_point_at_the_declared_file(demo_dir):
    report = _scan_demo(demo_dir)
    for f in report.findings:
        assert f.line >= 1
        assert f.path in FILES or f.path in ("state.tf", "versions.tf")


def test_a_hardened_workspace_passes_the_high_gate(tmp_path):
    good = {
        "versions.tf": 'terraform {\n  required_version = ">= 1.5"\n  backend "s3" {\n    bucket  = "st"\n    encrypt = true\n  }\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n  }\n}\n',
        "main.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  server_side_encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "aws:kms"\n      }\n    }\n  }\n  versioning {\n    enabled = true\n  }\n  logging {\n    target_bucket = "logs"\n  }\n}\n',
        "sg.tf": 'resource "aws_security_group" "app" {\n  name = "app"\n  egress = []\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n',
        "db.tf": 'resource "aws_db_instance" "d" {\n  storage_encrypted     = true\n  publicly_accessible   = false\n  vpc_security_group_ids = [aws_security_group.app.id]\n}\n',
        "iam.tf": 'data "aws_iam_policy_document" "read" {\n  statement {\n    actions   = ["s3:GetObject"]\n    resources = ["arn:aws:s3:::b/*"]\n  }\n}\n',
        "vpc.tf": 'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\nresource "aws_flow_log" "f" {\n  vpc_id = aws_vpc.v.id\n}\n',
    }
    base = os.path.join(str(tmp_path), "good")
    os.makedirs(base)
    for name, text in good.items():
        with open(os.path.join(base, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    report = _scan_demo(base)
    blocking = [f for f in report.findings if f.severity in ("critical", "high") and not f.suppressed]
    assert blocking == [], [f"{f.rule_id} at {f.location()}" for f in blocking]

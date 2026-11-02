"""SARIF output.

The two things that break SARIF in practice are both covered here: a uri that
still contains backslashes (which GitHub cannot resolve) and a rule that fired
without being described in the tool driver.
"""

from __future__ import annotations

import json
import os

from tfguard import sarif


def _write(tmp_path, text, name="main.tf") -> str:
    base = os.path.join(str(tmp_path), "ws")
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, name), "w", encoding="utf-8") as fh:
        fh.write(text)
    return base


def _scan(tmp_path, text):
    from tfguard.loader import iter_tf_files, load_file

    base = _write(tmp_path, text)
    files = [load_file(f, base=base) for f in iter_tf_files(base)]
    from tfguard.analyze import scan_documents

    return scan_documents(files)


def test_document_shape(tmp_path):
    report = _scan(
        tmp_path,
        'resource "aws_vpc" "v" {}\nresource "aws_ebs_volume" "e" {\n  encrypted = false\n}\n',
    )
    data = json.loads(sarif.dumps(report))
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-2.1.0.json")
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "tfguard"
    assert data["runs"][0]["results"]


def test_every_fired_rule_is_described(tmp_path):
    report = _scan(
        tmp_path,
        'resource "aws_vpc" "v" {}\nresource "aws_ebs_volume" "e" {\n  encrypted = false\n}\n',
    )
    data = json.loads(sarif.dumps(report))
    described = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
    fired = {res["ruleId"] for res in data["runs"][0]["results"]}
    assert fired <= described


def test_uris_use_forward_slashes_on_every_platform(tmp_path):
    report = _scan(tmp_path, 'resource "aws_vpc" "v" {}\n')
    data = json.loads(sarif.dumps(report))
    for res in data["runs"][0]["results"]:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri, uri


def test_a_windows_path_is_normalised_when_scanned_on_linux(tmp_path):
    # The bug this catches: replacing only os.sep is a no-op on Linux, so a
    # Windows path kept its backslashes and the artifact could not resolve.
    assert sarif._uri("infra\\vpc\\main.tf") == "infra/vpc/main.tf"
    assert sarif._uri("infra/vpc/main.tf") == "infra/vpc/main.tf"


def test_levels_follow_severity(tmp_path):
    report = _scan(
        tmp_path,
        'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        'resource "aws_ebs_volume" "e" {\n  encrypted = false\n}\n',
    )
    data = json.loads(sarif.dumps(report))
    levels = {res["ruleId"]: res["level"] for res in data["runs"][0]["results"]}
    assert levels["TFG001"] == "error"
    assert levels["TFG012"] == "warning"


def test_min_severity_filters_results(tmp_path):
    report = _scan(
        tmp_path,
        'resource "aws_vpc" "v" {}\nresource "aws_ebs_volume" "e" {\n  encrypted = false\n}\n',
    )
    data = json.loads(sarif.dumps(report, min_severity="high"))
    assert data["runs"][0]["results"] == []


def test_snippet_carries_the_source_line(tmp_path):
    report = _scan(tmp_path, 'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')
    data = json.loads(sarif.dumps(report))
    res = data["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_suppressed_findings_are_not_in_sarif(tmp_path):
    from tfguard.analyze import scan_documents
    from tfguard.loader import iter_tf_files, load_file

    base = _write(tmp_path, '# tfguard: ignore TFG023\nresource "aws_vpc" "v" {}\n')
    files = [load_file(f, base=base) for f in iter_tf_files(base)]
    report = scan_documents(files)
    data = json.loads(sarif.dumps(report))
    assert [r for r in data["runs"][0]["results"] if r["ruleId"] == "TFG023"] == []


def test_counts_helper(tmp_path):
    report = _scan(tmp_path, 'resource "aws_vpc" "v" {}\n')
    assert sarif.counts(report)["medium"] >= 1

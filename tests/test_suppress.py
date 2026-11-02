"""Inline suppression.

An ignore that blanks a whole file would make the report clean while the
configuration is unchanged, so suppression is tied to one line and one rule.
"""

from __future__ import annotations

from tfguard.loader import suppression_map


def test_bare_ignore_covers_the_line_under_it():
    text = "# tfguard: ignore\nresource \"aws_vpc\" \"v\" {}\n"
    assert 2 in suppression_map(text)


def test_trailing_ignore_covers_its_own_line():
    text = 'resource "aws_vpc" "v" {} # tfguard: ignore\n'
    assert 1 in suppression_map(text)


def test_ignore_with_ids_records_them():
    text = "# tfguard: ignore TFG010, TFG014\nresource \"x\" \"y\" {}\n"
    got = suppression_map(text)
    assert got[2] == {"TFG010", "TFG014"}


def test_reason_is_captured():
    from tfguard.loader import suppression_reasons

    text = "# tfguard: ignore TFG060 -- state is local on purpose\nresource \"x\" \"y\" {}\n"
    assert suppression_reasons(text)[1] == "state is local on purpose"


def test_is_suppressed_matches_one_rule_only(rules):
    # The natural place for an ignore is above the block it applies to, which
    # is where tfsec users already look for it.
    got = rules(
        '# tfguard: ignore TFG010\nresource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
    )
    assert "TFG010" not in got
    assert "TFG014" in got


def test_trailing_ignore_suppresses_a_line_level_finding(rules):
    got = rules('resource "aws_s3_bucket" "b" {\n  acl = "public-read"  # tfguard: ignore TFG011\n}\n')
    assert "TFG011" not in got


def test_a_suppressed_finding_is_still_in_the_report(scan):
    from tfguard.model import Report

    report: Report = scan(
        '# tfguard: ignore TFG010\nresource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
    )
    assert any(f.rule_id == "TFG010" and f.suppressed for f in report.findings)


def test_suppression_is_scoped_to_its_own_file(scan):
    got = scan(
        {
            "a.tf": '# tfguard: ignore TFG010\nresource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n',
            "b.tf": 'resource "aws_s3_bucket" "c" {\n  bucket = "c"\n}\n',
        }
    )
    unsuppressed = [f for f in got.findings if f.rule_id == "TFG010" and not f.suppressed]
    assert unsuppressed, "an ignore in one file must not silence another"

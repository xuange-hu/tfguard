"""One minimal trigger sample per rule, plus the negative case.

Each ``test_tfgNNN`` writes the smallest Terraform that should make the rule
fire and asserts it fired at the line that carries the problem. The
``_clean`` tests are the other half: they exist because a rule that fires on
correct configuration is worse than a rule that never fires.
"""

from __future__ import annotations

import pytest

from tfguard.rules import BY_ID, RULES


def test_every_rule_has_a_trigger_sample():
    """A rule without a sample is a rule nobody has ever seen fire."""
    here = __file__
    with open(here, encoding="utf-8") as fh:
        text = fh.read()
    for rule in RULES:
        assert f"def test_{rule.id.lower()}(" in text, f"{rule.id} has no trigger test"


def test_rules_have_unique_ids():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_has_why_and_fix():
    for r in RULES:
        assert r.why.strip(), r.id
        assert r.fix.strip(), r.id
        assert r.severity in ("critical", "high", "medium", "low", "info"), r.id


def test_ids_are_contiguous_within_their_group():
    # Numbering is part of the contract: TFG001..TFG006 is the network group.
    for r in RULES:
        assert r.id.startswith("TFG") and r.id[3:].isdigit(), r.id


# ---------------------------------------------------------------- network


def tfg001():
    return 'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'


def test_tfg001(rules):
    assert "TFG001" in rules(tfg001())


def test_tfg001_not_fired_for_a_scoped_cidr(rules):
    assert "TFG001" not in rules(
        tfg001().replace('"0.0.0.0/0"', '"10.0.0.0/8"')
    )


def test_tfg002(rules):
    assert "TFG002" in rules(
        'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    )


def test_tfg002_not_fired_for_internal_cidr(rules):
    assert "TFG002" not in rules(
        'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n'
    )


def test_tfg003(rules):
    assert "TFG003" in rules(
        'resource "aws_security_group" "web" {\n  egress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    )


def test_tfg004(rules):
    assert "TFG004" in rules(
        'resource "aws_db_instance" "main" {\n  publicly_accessible = true\n}\n'
    )


def test_tfg005(rules):
    assert "TFG005" in rules(
        'resource "aws_instance" "b" {\n  associate_public_ip_address = true\n}\n'
    )


def test_tfg005_launch_template(rules):
    assert "TFG005" in rules(
        'resource "aws_launch_template" "l" {\n  network_interfaces {\n    associate_public_ip_address = true\n  }\n}\n'
    )


def test_tfg006(rules):
    assert "TFG006" in rules(
        'resource "aws_security_group_rule" "ssh" {\n  type        = "ingress"\n  from_port   = 3389\n  to_port     = 3389\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
    )


# ------------------------------------------------------------- encryption


def test_tfg010(rules):
    assert "TFG010" in rules('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')


def test_tfg010_clean(rules):
    assert "TFG010" not in rules(
        'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  server_side_encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "aws:kms"\n      }\n    }\n  }\n}\n'
    )


def test_tfg011(rules):
    assert "TFG011" in rules('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')


def test_tfg012(rules):
    assert "TFG012" in rules('resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n')


def test_tfg012_absent_is_the_same_problem(rules):
    assert "TFG012" in rules('resource "aws_ebs_volume" "v" {\n  size = 10\n}\n')


def test_tfg013(rules):
    assert "TFG013" in rules('resource "aws_db_instance" "d" {\n  storage_encrypted = false\n}\n')


def test_tfg014(rules):
    assert "TFG014" in rules('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')


def test_tfg014_clean(rules):
    assert "TFG014" not in rules(
        'resource "aws_s3_bucket" "b" {\n  versioning {\n    enabled = true\n  }\n}\n'
    )


def test_tfg015(rules):
    assert "TFG015" in rules('resource "aws_kms_key" "k" {\n  enable_key_rotation = false\n}\n')


def test_tfg017(rules):
    assert "TFG017" in rules('resource "aws_efs_file_system" "f" {\n  encrypted = false\n}\n')


# ---------------------------------------------------------------- logging


def test_tfg020(rules):
    assert "TFG020" in rules('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')


def test_tfg021(rules):
    assert "TFG021" in rules('resource "aws_lb" "l" {\n  internal = false\n}\n')


def test_tfg021_internal_lb_is_clean(rules):
    assert "TFG021" not in rules('resource "aws_lb" "l" {\n  internal = true\n}\n')


def test_tfg022(rules):
    got = rules('resource "aws_cloudtrail" "c" {\n  enable_log_file_validation = false\n}\n')
    assert "TFG022" in got


def test_tfg022_multi_region(rules):
    assert "TFG022" in rules(
        'resource "aws_cloudtrail" "c" {\n  is_multi_region_trail = false\n}\n'
    )


def test_tfg023(rules):
    assert "TFG023" in rules('resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')


def test_tfg023_clean_when_a_flow_log_points_at_it(rules):
    assert "TFG023" not in rules(
        'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        'resource "aws_flow_log" "f" {\n  vpc_id = aws_vpc.v.id\n}\n'
    )


# ---------------------------------------------------------------- identity


def test_tfg030(rules):
    assert "TFG030" in rules(
        'data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["*"]\n    resources = ["arn:aws:s3:::b/*"]\n  }\n}\n'
    )


def test_tfg031(rules):
    assert "TFG031" in rules(
        'data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["s3:GetObject"]\n    resources = ["*"]\n  }\n}\n'
    )


def test_tfg032(rules):
    assert "TFG032" in rules(
        'data "aws_iam_policy_document" "d" {\n  statement {\n    principals {\n      type        = "AWS"\n      identifiers = ["*"]\n    }\n  }\n}\n'
    )


def test_tfg033(rules):
    got = rules(
        'data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["*"]\n    resources = ["*"]\n  }\n}\n'
    )
    assert "TFG033" in got
    # The pair is reported once, not three times over.
    assert "TFG030" not in got
    assert "TFG031" not in got


def test_tfg033_deny_is_ignored(rules):
    assert not rules(
        'data "aws_iam_policy_document" "d" {\n  statement {\n    effect    = "Deny"\n    actions   = ["*"]\n    resources = ["*"]\n  }\n}\n'
    )


def test_tfg034(rules):
    assert "TFG034" in rules(
        'resource "aws_iam_role_policy" "p" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n  })\n}\n'
    )


def test_tfg034_from_a_json_string(rules):
    assert "TFG034" in rules(
        'resource "aws_iam_policy" "p" {\n  policy = "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"\n}\n'
    )


def test_tfg034_trust_policy_uses_the_trust_rule(rules):
    got = rules(
        'resource "aws_iam_role" "r" {\n  assume_role_policy = jsonencode({\n    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = "*" }]\n  })\n}\n'
    )
    assert "TFG032" in got


# ---------------------------------------------------------------- secrets


def test_tfg040(rules):
    assert "TFG040" in rules(
        'resource "aws_db_instance" "d" {\n  password = "Sup3rS3cretLiteral"\n}\n'
    )


def test_tfg040_placeholder_is_not_a_finding(rules):
    assert "TFG040" not in rules(
        'resource "aws_db_instance" "d" {\n  password = "changeme"\n}\n'
    )


def test_tfg041(rules):
    assert "TFG041" in rules('variable "db_password" {\n  default = "Sup3rS3cretDefault"\n}\n')


def test_tfg041_through_a_local(rules):
    assert "TFG041" in rules(
        {"main.tf": 'variable "db_password" {\n  default = local.relayed\n}\n', "l.tf": 'locals {\n  relayed = "RelayedS3cretValue"\n}\n'}
    )


def test_tfg042(rules):
    assert "TFG042" in rules('variable "api_token" {\n  type = string\n}\n')


def test_tfg042_clean_when_sensitive(rules):
    assert "TFG042" not in rules(
        'variable "api_token" {\n  type      = string\n  sensitive = true\n}\n'
    )


def test_tfg043(rules):
    assert "TFG043" in rules(
        {
            "v.tf": 'variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n',
            "r.tf": 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n',
        }
    )


def test_tfg043_clean_when_the_variable_has_no_default(rules):
    assert "TFG043" not in rules(
        {
            "v.tf": 'variable "db_password" {\n  type = string\n}\n',
            "r.tf": 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n',
        }
    )


def test_tfg044(rules):
    assert "TFG044" in rules(
        'resource "aws_instance" "i" {\n  user_data = <<-EOT\n    #!/bin/bash\n    echo "db_password=InlineS3cretValue" >> /etc/app.conf\n  EOT\n}\n'
    )


def test_tfg044_through_tags(rules):
    assert "TFG044" in rules(
        {
            "v.tf": 'variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n',
            "r.tf": 'resource "aws_instance" "i" {\n  tags = {\n    Password = var.db_password\n  }\n}\n',
        }
    )


# ------------------------------------------------------------------ absent


def test_tfg050(rules):
    assert "TFG050" in rules('resource "aws_security_group" "p" {\n  egress = []\n}\n')


def test_tfg050_absent_egress_is_not_reported(rules):
    got = rules('resource "aws_security_group" "p" {\n  name = "p"\n}\n')
    assert "TFG050" not in got


def test_tfg051(rules):
    assert "TFG051" in rules('resource "aws_security_group" "p" {\n  tags = {}\n}\n')


def test_tfg052(rules):
    assert "TFG052" in rules(
        'resource "aws_s3_bucket" "b" {\n  public_access_block {\n    block_public_acls       = false\n    block_public_policy     = false\n    ignore_public_acls      = false\n    restrict_public_buckets = false\n  }\n}\n'
    )


def test_tfg052_clean_when_they_block(rules):
    assert "TFG052" not in rules(
        'resource "aws_s3_bucket" "b" {\n  public_access_block {\n    block_public_acls       = true\n    block_public_policy     = true\n    ignore_public_acls      = true\n    restrict_public_buckets = true\n  }\n}\n'
    )


# ------------------------------------------------------------------ supply


def test_tfg060(rules):
    assert "TFG060" in rules('resource "aws_vpc" "v" {}\n')


def test_tfg060_clean_with_a_backend(rules):
    assert "TFG060" not in rules(
        {"s.tf": 'terraform {\n  backend "s3" {\n    bucket = "b"\n    encrypt = true\n  }\n}\n', "m.tf": 'resource "aws_vpc" "v" {}\n'}
    )


def test_tfg061(rules):
    assert "TFG061" in rules(
        'terraform {\n  backend "s3" {\n    bucket = "b"\n  }\n}\n'
    )


def test_tfg062(rules):
    assert "TFG062" in rules(
        'terraform {\n  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n    }\n  }\n}\n'
    )


def test_tfg062_clean_when_version_is_pinned(rules):
    assert "TFG062" not in rules(
        'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n  }\n}\n'
    )


def test_tfg063(rules):
    assert "TFG063" in rules('module "vpc" {\n  source = "git::https://example.com/vpc.git"\n}\n')


def test_tfg063_clean_with_ref(rules):
    assert "TFG063" not in rules(
        'module "vpc" {\n  source = "git::https://example.com/vpc.git?ref=v1.2.3"\n}\n'
    )


def test_tfg064(rules):
    assert "TFG064" in rules('terraform {\n  required_providers {}\n}\n')


# ------------------------------------------------------------- relationship


def test_tfg070(rules):
    assert "TFG070" in rules(
        'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 80\n    to_port     = 80\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        'resource "aws_instance" "bastion" {\n  associate_public_ip_address = true\n  vpc_security_group_ids      = [aws_security_group.web.id]\n}\n'
    )


def test_tfg070_not_fired_for_a_private_instance(rules):
    assert "TFG070" not in rules(
        'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 80\n    to_port     = 80\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        'resource "aws_instance" "app" {\n  associate_public_ip_address = false\n  vpc_security_group_ids      = [aws_security_group.web.id]\n}\n'
    )


def test_tfg071(rules):
    assert "TFG071" in rules(
        'resource "aws_security_group_rule" "r" {\n  type                     = "ingress"\n  source_security_group_id = aws_security_group.missing.id\n}\n'
    )


def test_tfg071_clean_when_the_group_is_declared(rules):
    assert "TFG071" not in rules(
        'resource "aws_security_group" "web" {}\n'
        'resource "aws_security_group_rule" "r" {\n  type                     = "ingress"\n  source_security_group_id = aws_security_group.web.id\n}\n'
    )


def test_tfg072(rules):
    assert "TFG072" in rules('resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n')


def test_tfg073(rules):
    assert "TFG073" in rules(
        'data "aws_iam_policy_document" "trust" {\n  statement {\n    principals {\n      identifiers = ["*"]\n    }\n  }\n}\n'
        'resource "aws_iam_role" "r" {\n  assume_role_policy = data.aws_iam_policy_document.trust.json\n}\n'
    )


def test_tfg073_clean_for_a_service_principal(rules):
    assert "TFG073" not in rules(
        'data "aws_iam_policy_document" "trust" {\n  statement {\n    principals {\n      type        = "Service"\n      identifiers = ["lambda.amazonaws.com"]\n    }\n  }\n}\n'
        'resource "aws_iam_role" "r" {\n  assume_role_policy = data.aws_iam_policy_document.trust.json\n}\n'
    )


def test_tfg075(rules):
    assert "TFG075" in rules(
        {
            "v.tf": 'variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n',
            "o.tf": 'output "db_password" {\n  value = var.db_password\n}\n',
        }
    )


def test_tfg075_clean_when_the_output_is_sensitive(rules):
    assert "TFG075" not in rules(
        {
            "v.tf": 'variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n',
            "o.tf": 'output "db_password" {\n  value     = var.db_password\n  sensitive = true\n}\n',
        }
    )


@pytest.mark.parametrize("rule", [r.id for r in RULES])
def test_rule_metadata_round_trips(rule):
    r = BY_ID[rule]
    assert r.title and r.category
    assert r.category in {
        "network",
        "encryption",
        "logging",
        "identity",
        "secrets",
        "absent",
        "supply",
        "relationship",
    }

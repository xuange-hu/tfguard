"""The relationship and credential passes.

These are the two things tfguard does that a pattern-matching scanner does not,
so they get their own tests rather than being folded into the rule samples.
"""

from __future__ import annotations

from tfguard.analyze import _build_scope, _is_secret_name


def _files(tmp_path, mapping):
    from tfguard.loader import iter_tf_files, load_file

    base = tmp_path / "ws"
    base.mkdir(exist_ok=True)
    for name, text in mapping.items():
        (base / name).write_text(text, encoding="utf-8")
    return [load_file(f, base=str(base)) for f in iter_tf_files(str(base))]


def test_a_credential_is_reported_at_the_variable_not_the_use(tmp_path, tmp_path_factory):
    files = _files(
        tmp_path,
        {
            "v.tf": 'variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n',
            "r.tf": 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    taint = [f for f in report.findings if f.rule_id == "TFG043"]
    assert len(taint) == 1
    assert taint[0].flow == "var.db_password -> aws_db_instance.d.password"
    assert "not on this line" in taint[0].note


def test_a_two_hop_credential_still_resolves(tmp_path):
    files = _files(
        tmp_path,
        {
            "v.tf": 'variable "api_secret" {\n  default = local.carried\n}\n',
            "r.tf": 'resource "aws_db_instance" "d" {\n  password = var.api_secret\n}\n',
            "l.tf": 'locals {\n  carried = "CarriedS3cretLiteral"\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    taint = [f for f in report.findings if f.rule_id == "TFG043"]
    assert taint
    assert taint[0].flow.startswith("var.api_secret")


def test_a_credential_that_comes_from_nowhere_is_not_reported(tmp_path):
    files = _files(
        tmp_path,
        {
            "v.tf": 'variable "db_password" {\n  type = string\n}\n',
            "r.tf": 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    assert not [f for f in report.findings if f.rule_id == "TFG043"]


def test_scope_resolves_a_local_chain(tmp_path):
    files = _files(
        tmp_path,
        {
            "v.tf": 'variable "a" {\n  default = local.b\n}\n',
            "l.tf": 'locals {\n  b = local.c\n  c = "deeply_nested_value"\n}\n',
        },
    )
    scope = _build_scope([f for f in files if f.doc is not None])
    got = scope.literal_behind(scope.vars["a"]["default"])
    assert got is not None
    assert got[0] == "deeply_nested_value"
    assert got[1] == ["local.b", "local.c"]


def test_a_cycle_does_not_hang(tmp_path):
    files = _files(
        tmp_path,
        {
            "v.tf": 'variable "a" {\n  default = local.b\n}\n',
            "l.tf": 'locals {\n  b = local.b\n}\n',
        },
    )
    scope = _build_scope([f for f in files if f.doc is not None])
    assert scope.literal_behind(scope.vars["a"]["default"]) is None


def test_secret_names_are_matched_across_spellings():
    for name in ("password", "db_password", "apiKey", "api_key", "secret", "access_token", "AWS_SECRET_KEY"):
        assert _is_secret_name(name)
    assert not _is_secret_name("instance_type")
    assert not _is_secret_name("bucket")


def test_credential_does_not_follow_a_call(tmp_path):
    files = _files(
        tmp_path,
        {
            "v.tf": 'variable "db_password" {\n  default = "Sup3rS3cretValue"\n}\n',
            "r.tf": 'resource "aws_db_instance" "d" {\n  password = random_password.generated.result\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    assert not [f for f in report.findings if f.rule_id == "TFG043"]


def test_an_open_group_alone_is_reported_by_the_block_rule(tmp_path):
    files = _files(
        tmp_path,
        {
            "sg.tf": 'resource "aws_security_group" "web" {\n  ingress {\n    from_port = 22\n'
            '    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    ids = {f.rule_id for f in report.findings}
    assert "TFG001" in ids
    assert "TFG070" not in ids, "without a consumer there is no relationship to report"


def test_the_relationship_rule_names_both_ends(tmp_path):
    files = _files(
        tmp_path,
        {
            "sg.tf": 'resource "aws_security_group" "web" {\n  ingress {\n    from_port = 80\n'
            '    to_port = 80\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
            "i.tf": 'resource "aws_instance" "bastion" {\n  associate_public_ip_address = true\n'
            "  vpc_security_group_ids      = [aws_security_group.web.id]\n}\n",
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    rel = [f for f in report.findings if f.rule_id == "TFG070"]
    assert rel
    assert rel[0].flow == "aws_security_group.web -> resource.aws_instance.bastion"


def test_a_load_balancer_counts_as_internet_facing(tmp_path):
    files = _files(
        tmp_path,
        {
            "sg.tf": 'resource "aws_security_group" "web" {\n  ingress {\n    from_port = 80\n'
            '    to_port = 80\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
            "l.tf": 'resource "aws_lb" "pub" {\n  internal = false\n  security_groups = [aws_security_group.web.id]\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    assert [f for f in report.findings if f.rule_id == "TFG070"]


def test_cross_file_relationships_work(tmp_path):
    # The whole point of the relationship pass: neither file alone is enough.
    files = _files(
        tmp_path,
        {
            "sg.tf": 'resource "aws_security_group" "web" {\n  ingress {\n    from_port = 80\n'
            '    to_port = 80\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
            "i.tf": 'resource "aws_instance" "bastion" {\n  associate_public_ip_address = true\n'
            "  vpc_security_group_ids      = [aws_security_group.web.id]\n}\n",
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    rel = [f for f in report.findings if f.rule_id == "TFG070"]
    assert rel[0].path == "sg.tf", "the exposure belongs to the group, not the instance"


def test_a_dangling_reference_is_found_across_files(tmp_path):
    files = _files(
        tmp_path,
        {
            "i.tf": 'resource "aws_instance" "app" {\n  vpc_security_group_ids = [aws_security_group.elsewhere.id]\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    dangling = [f for f in report.findings if f.rule_id == "TFG071"]
    assert dangling
    assert dangling[0].flow.endswith("aws_security_group.elsewhere")


def test_a_data_source_group_is_not_dangling(tmp_path):
    files = _files(
        tmp_path,
        {
            "d.tf": 'data "aws_security_group" "shared" {\n  name = "shared"\n}\n',
            "i.tf": 'resource "aws_instance" "app" {\n  vpc_security_group_ids = [data.aws_security_group.shared.id]\n}\n',
        },
    )
    from tfguard.analyze import scan_documents

    report = scan_documents(files)
    assert not [f for f in report.findings if f.rule_id == "TFG071"]

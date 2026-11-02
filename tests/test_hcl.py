"""Tests for the HCL2 parser.

The parser is the part everything else stands on, so these tests are about
shapes that actually appear in Terraform files rather than about the grammar
in the abstract: heredocs, interpolation, nested blocks, object constructors
written with and without commas.
"""

from __future__ import annotations

import pytest

from tfguard.hcl import (
    Body,
    Call,
    Document,
    HclError,
    List_,
    Literal,
    Map_,
    Ref,
    Splat,
    Template,
    parse,
)


def test_empty_document():
    doc = parse("")
    assert doc.body.items == []


def test_top_level_attributes():
    doc = parse('a = 1\nb = "two"\nc = true\nd = null\n')
    values = {a.name: a.value.as_py() for a in doc.body.attrs()}
    assert values == {"a": 1, "b": "two", "c": True, "d": None}


def test_block_with_two_labels():
    doc = parse('resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n')
    block = doc.body.blocks()[0]
    assert block.kind == "resource"
    assert block.labels == ["aws_s3_bucket", "logs"]
    assert block.type == "aws_s3_bucket"
    assert block.name == "logs"
    assert block.address == "resource.aws_s3_bucket.logs"


def test_data_block_address():
    doc = parse('data "aws_iam_policy_document" "assume" {\n  statement {}\n}\n')
    block = doc.body.blocks()[0]
    assert block.kind == "data"
    assert block.address == "data.aws_iam_policy_document.assume"
    assert block.type == "aws_iam_policy_document"


def test_nested_block():
    doc = parse('resource "aws_security_group" "web" {\n  ingress {\n    from_port = 22\n  }\n}\n')
    sg = doc.body.blocks()[0]
    ingress = sg.body.block("ingress")
    assert ingress is not None
    assert ingress.attr("from_port").value.as_py() == 22


def test_nested_block_is_not_an_attribute():
    doc = parse('resource "r" "n" {\n  versioning {\n    enabled = true\n  }\n}\n')
    assert doc.body.blocks()[0].body.attr("versioning") is None
    assert doc.body.blocks()[0].body.block("versioning") is not None


def test_list_literal():
    doc = parse('locals {\n  cidr = ["10.0.0.0/8", "0.0.0.0/0"]\n}\n')
    value = doc.body.block("locals").attr("cidr").value
    assert isinstance(value, List_)
    assert value.as_py() == ["10.0.0.0/8", "0.0.0.0/0"]


def test_empty_list_is_a_list_not_a_missing_attribute():
    doc = parse('resource "r" "n" {\n  egress = []\n}\n')
    attr = doc.body.blocks()[0].body.attr("egress")
    assert attr is not None
    assert attr.value.as_py() == []


def test_object_with_commas():
    doc = parse('locals {\n  m = { a = 1, b = "two" }\n}\n')
    value = doc.body.block("locals").attr("m").value
    assert isinstance(value, Map_)
    assert value.as_py() == {"a": 1, "b": "two"}


def test_object_with_newline_separated_entries():
    # HCL allows this, and it is how tags blocks are usually written.
    doc = parse('locals {\n  m = {\n    Name = "web"\n    Env  = "prod"\n  }\n}\n')
    value = doc.body.block("locals").attr("m").value
    assert value.as_py() == {"Name": "web", "Env": "prod"}


def test_object_as_block_bodies():
    doc = parse('resource "r" "n" {\n  rule {\n    enabled = true\n  }\n}\n')
    rule = doc.body.blocks()[0].body.get("rule")
    assert isinstance(rule, Body)
    assert rule.attr("enabled").value.as_py() is True


def test_plain_string_is_a_literal():
    doc = parse('locals {\n  s = "plain"\n}\n')
    assert isinstance(doc.body.block("locals").attr("s").value, Literal)


def test_interpolated_string_is_a_template_with_refs():
    doc = parse('locals {\n  s = "${var.env}-logs"\n}\n')
    value = doc.body.block("locals").attr("s").value
    assert isinstance(value, Template)
    assert [r.path for r in value.refs()] == ["var.env"]
    assert value.as_py() == "${...}-logs"


def test_reference_with_attribute_access():
    doc = parse('resource "r" "n" {\n  v = aws_s3_bucket.logs.id\n}\n')
    value = doc.body.blocks()[0].attr("v").value
    assert isinstance(value, Ref)
    assert value.path == "aws_s3_bucket.logs.id"


def test_function_call():
    doc = parse('resource "r" "n" {\n  v = jsonencode({ a = 1 })\n}\n')
    value = doc.body.blocks()[0].attr("v").value
    assert isinstance(value, Call)
    assert value.name == "jsonencode"
    assert value.args[0].as_py() == {"a": 1}


def test_heredoc():
    doc = parse('resource "r" "n" {\n  user_data = <<-EOT\n    #!/bin/bash\n    echo hi\n  EOT\n}\n')
    value = doc.body.blocks()[0].attr("user_data").value
    assert isinstance(value, Template)
    assert "#!/bin/bash" in value.as_py()
    assert "echo hi" in value.as_py()


def test_heredoc_does_not_swallow_the_next_attribute():
    doc = parse('resource "r" "n" {\n  a = <<-EOT\n    line\n  EOT\n  b = 2\n}\n')
    attrs = {a.name: a.value.as_py() for a in doc.body.blocks()[0].body.attrs()}
    assert attrs["b"] == 2


def test_comments_are_ignored():
    doc = parse('# leading\n// double slash\n/* block\n   comment */\nlocals {\n  a = 1  # trailing\n}\n')
    assert doc.body.block("locals").attr("a").value.as_py() == 1


def test_conditional_expression():
    doc = parse('resource "r" "n" {\n  count = var.env == "prod" ? 2 : 1\n}\n')
    value = doc.body.blocks()[0].attr("count").value
    assert value.as_py() == "<cond>"
    assert [r.path for r in value.refs()] == ["var.env"]


def test_for_expression_list():
    doc = parse('locals {\n  xs = [for s in var.names : upper(s)]\n}\n')
    value = doc.body.block("locals").attr("xs").value
    assert [r.path for r in value.refs()] == ["var.names"]


def test_for_expression_object():
    doc = parse('locals {\n  m = { for k, v in var.tags : k => v }\n}\n')
    value = doc.body.block("locals").attr("m").value
    assert [r.path for r in value.refs()] == ["var.tags"]


def test_splat_expression():
    doc = parse('locals {\n  ids = aws_instance.web[*].id\n}\n')
    value = doc.body.block("locals").attr("ids").value
    assert isinstance(value, Splat)


def test_line_numbers_are_one_based_and_exact():
    src = 'resource "r" "n" {\n  a = 1\n  b = 2\n}\n'
    doc = parse(src)
    block = doc.body.blocks()[0]
    assert block.line == 1
    assert block.attr("a").line == 2
    assert block.attr("b").line == 3
    assert doc.line_text(2) == "a = 1"


def test_negative_number():
    doc = parse('locals {\n  n = -1\n}\n')
    assert doc.body.block("locals").attr("n").value.as_py() == -1


def test_float_number():
    doc = parse('locals {\n  n = 1.5\n}\n')
    assert doc.body.block("locals").attr("n").value.as_py() == 1.5


def test_boolean_and_null_keywords():
    doc = parse('locals {\n  a = true\n  b = false\n  c = null\n}\n')
    values = {a.name: a.value.as_py() for a in doc.body.block("locals").body.attrs()}
    assert values == {"a": True, "b": False, "c": None}


def test_arithmetic_precedence():
    # 1 + 2 * 3 groups as 1 + (2 * 3): multiplication binds tighter.
    doc = parse('locals {\n  n = 1 + 2 * 3\n}\n')
    value = doc.body.block("locals").attr("n").value
    assert value.as_py() == "<+>"
    assert value.left.as_py() == 1
    assert value.right.as_py() == "<*>"


def test_comparison_operators():
    doc = parse('locals {\n  a = var.x == 1\n  b = var.y != 2\n}\n')
    value = doc.body.block("locals").attr("a").value
    assert value.as_py() == "<==>"
    assert [r.path for r in value.refs()] == ["var.x"]
    other = doc.body.block("locals").attr("b").value
    assert other.as_py() == "<!=>"


def test_unclosed_block_raises():
    with pytest.raises(HclError):
        parse('resource "r" "n" {\n  a = 1\n')


def test_unexpected_character_raises():
    with pytest.raises(HclError):
        parse("locals {\n  a = `\n}\n")


def test_block_missing_brace_raises():
    with pytest.raises(HclError):
        parse('resource "r" "n"\n')


def test_two_attributes_on_consecutive_lines_do_not_merge():
    doc = parse('resource "r" "n" {\n  a = 1\n  b = 2\n  c = "x"\n}\n')
    names = [a.name for a in doc.body.blocks()[0].body.attrs()]
    assert names == ["a", "b", "c"]


def test_all_blocks_walks_nested_blocks():
    doc = parse('resource "r" "n" {\n  nested {\n    deeper {}\n  }\n}\n')
    kinds = [b.kind for b in doc.all_blocks()]
    assert kinds == ["resource", "nested", "deeper"]


def test_document_path_is_settable():
    doc = parse('locals { a = 1 }\n')
    assert isinstance(doc, Document)
    doc.path = "main.tf"
    assert doc.path == "main.tf"


def test_resources_property():
    doc = parse('resource "a" "one" {}\nresource "b" "two" {}\nlocals {}\n')
    assert [b.address for b in doc.resources] == ["resource.a.one", "resource.b.two"]


def test_index_access():
    doc = parse('locals {\n  first = var.list[0]\n}\n')
    value = doc.body.block("locals").attr("first").value
    assert [r.path for r in value.refs()] == ["var.list"]


def test_string_with_escaped_quote():
    doc = parse('locals {\n  s = "say \\"hi\\""\n}\n')
    assert doc.body.block("locals").attr("s").value.as_py() == 'say "hi"'


def test_dynamic_block_parses():
    doc = parse(
        'resource "aws_security_group" "x" {\n'
        "  dynamic \"ingress\" {\n"
        "    for_each = var.ports\n"
        "    content {\n"
        "      from_port = ingress.value\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    sg = doc.body.blocks()[0]
    # A dynamic block keeps its own kind and carries the target name as a label.
    dyn = sg.body.block("dynamic")
    assert dyn is not None
    assert dyn.labels == ["ingress"]
    assert dyn.attr("for_each").value.as_py() == "var.ports"


def test_provider_and_module_blocks():
    doc = parse('provider "aws" {\n  region = "us-east-1"\n}\nmodule "vpc" {\n  source = "./vpc"\n}\n')
    kinds = [b.kind for b in doc.body.blocks()]
    assert kinds == ["provider", "module"]
    assert doc.body.block("provider").labels == ["aws"]


def test_expression_does_not_eat_the_next_attribute():
    # A binary expression followed by a new attribute on the next line.
    doc = parse('locals {\n  a = 1 + 2\n  b = 3\n}\n')
    names = [a.name for a in doc.body.block("locals").body.attrs()]
    assert names == ["a", "b"]


def test_list_requires_commas_so_it_does_not_swallow_next_attribute():
    doc = parse('locals {\n  a = [1]\n  b = 2\n}\n')
    values = {a.name: a.value.as_py() for a in doc.body.block("locals").body.attrs()}
    assert values == {"a": [1], "b": 2}

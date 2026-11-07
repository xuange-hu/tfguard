# tfguard

[中文说明 / Chinese README](README_CN.md)

**Terraform / OpenTofu configuration audit. 40 rules, an HCL2 parser written
from scratch, credential tracing and cross-block relationships — with zero
dependencies.**

[![tests](https://img.shields.io/badge/tests-262%20passing-2ea44f)](https://github.com/xuange-hu/tfguard/actions)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776ab)](https://pypi.org/project/tfguard/)
[![dependencies](https://img.shields.io/badge/dependencies-0-2ea44f)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)

```console
$ tfguard demo --dir demo && tfguard scan demo
========================================================================================
tfguard · 8 critical  16 high  23 medium  5 low  2 info · 11 file(s), 23 resource(s)
========================================================================================

── identity and access ────────────────────────────────────────────────────────────────
!!!![CRITICAL] TFG030  Policy allows every action
           iam.tf:2
           | statement {
           note: actions = ['*']
!!!![CRITICAL] TFG032  Trust policy trusts everyone
           iam.tf:25
           | principals {

── network exposure ───────────────────────────────────────────────────────────────────
!!!![CRITICAL] TFG001  Security group opens a remote-admin port to the internet
           security_groups.tf:4
           | ingress {
           note: ports 22-22 cover 22 (SSH)

── credential handling ────────────────────────────────────────────────────────────────
!!!![CRITICAL] TFG041  A credential is the default value of a variable
           variables.tf:3
           | default = "Sup3rS3cretDbValue"
           note: variable 'db_password' default resolves to a literal
!!!![CRITICAL] TFG040  A credential is written into the configuration
           data.tf:5
           | password         = "DirectLiteralDatabasePassword"
           note: aws_db_instance.main.password
!!!![CRITICAL] TFG041  A credential is the default value of a variable
           variables.tf:12
           | default = local.relayed
           note: variable 'relay_secret' default resolves to a literal through local.relayed
```

---

## Why another IaC scanner

The established tools are good and they are not small: `checkov` pulls a
dependency tree with it, `tfsec` and `terrascan` are Go. There is no
zero-dependency Python entry, and there are three things they structurally do
not do.

### 1. It reads HCL2 itself

`hcl.py` is a lexer and a recursive-descent parser for the subset real Terraform
files use — heredocs, `<<-` indented forms, interpolation, for-expressions,
splats, `dynamic` blocks, objects written with or without commas. Every node
carries its line, which is why every finding can quote the source line back.

```console
$ tfguard parse main.tf
resource "aws_s3_bucket" "logs" {   # line 1
  bucket = 'my-logs'
  tags = {'Name': 'logs'}
}
```

### 2. Credentials are traced to their origin, not matched where they land

A password in a `variable` default is a committed credential even though the
line that uses it says only `var.db_password`. tfguard follows `var` and `local`
references backwards until it finds the literal, then reports the literal's
location and the chain that carried it.

```
!!!![CRITICAL] TFG041  A credential is the default value of a variable
           variables.tf:12
           | default = local.relayed
           note: variable 'relay_secret' default resolves to a literal through local.relayed

!!! [HIGH    ] TFG043  A credential reaches a plain argument through a variable
           data.tf:14
           | password         = var.db_password
           flow: var.db_password -> aws_db_instance.second.password
```

A cycle (`local.b = local.b`) terminates instead of hanging: it is tested.

### 3. A third pass reads the relationships

Neither of these blocks is wrong on its own:

```hcl
resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "bastion" {
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id]
}
```

Together they say the group that is open to the internet is the one protecting
a host that answers the internet. `TFG070` reports it at the group, names both
ends, and does not fire when the consumer is private.

### 4. Absent is not the same as empty

```hcl
egress = []   # a decision: you wrote it, Terraform will not add the default
              # -> TFG050, severity info

# (no egress at all) -> nothing. On a custom group that is the safe case.
```

```hcl
public_access_block {
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}   # TFG052, severity high: it looks like protection and behaves like nothing
```

Two different rules, two different severities, two different fixes.

---

## Install

```bash
pip install tfguard          # no dependencies
pip install "tfguard[mcp]"   # + the MCP server
```

> **PyPI status.** The `Publish` job is red for one known reason: PyPI Trusted
> Publishing has to be registered once in the PyPI UI before the first upload
> can succeed, and that step is still pending. The tool itself is unaffected —
> install from the repo instead:
>
> ```bash
> pip install "git+https://github.com/xuange-hu/tfguard.git"
> pip install "tfguard[mcp] @ git+https://github.com/xuange-hu/tfguard.git"
> ```
>
> Once the trusted publisher is registered the same job publishes to PyPI and
> the two commands above work as written.

## Three steps

```bash
# 1. install
pip install tfguard

# 2. see it work on a workspace that is wrong in 39 different ways
tfguard demo --dir demo-workspace

# 3. scan your own
tfguard scan .
```

## Use it as a gate

```bash
tfguard scan . --fail-on high          # exit 1 on anything at or above high
tfguard scan . --min-severity high
tfguard scan . --category identity
tfguard scan . --rule TFG001 --rule TFG002
tfguard scan . --format sarif --output results.sarif
tfguard scan . --explain               # print why + fix under each finding
tfguard explain TFG070
tfguard rules --category relationship
```

Every rule states the fix, not the concept:

```console
$ tfguard explain TFG070
TFG070 · An internet-facing resource sits in a group that is open to the internet
severity : high
category : cross-block relationships

why:
Neither block is wrong alone. Together they say the open group is the one
protecting a resource that answers the internet, which is the exposure the
two rules separately would not show.

fix:
Attach a group that only admits the load balancer, and keep the open one off
public workloads.
```

## Suppress with a reason

```hcl
# tfguard: ignore TFG060 -- this workspace is a workshop, state is local
resource "aws_vpc" "teaching" {
  cidr_block = "10.0.0.0/16"
}
```

An ignore covers one line (or the block under it) and one rule. It never blanks
a whole file, so a clean report still means something.

## GitHub Actions

```yaml
- run: pip install tfguard
- run: tfguard scan . --fail-on high --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Clade: six MCP tools

```bash
pip install "tfguard[mcp]"
tfguard-mcp
```

| tool | what it does |
|---|---|
| `tfguard_scan` | audit a workspace, text / JSON / SARIF |
| `tfguard_rules` | list the 40 rules, optionally by category |
| `tfguard_explain` | why + fix for one rule |
| `tfguard_parse` | the parsed structure of a `.tf` file as JSON |
| `tfguard_taint` | where each credential-shaped value comes from |
| `tfguard_demo` | write the hostile workspace and report on it |

---

## The rules

40 rules. Each is a separate function, each has a minimal trigger sample in
`tests/test_rules.py`, and CI asserts the demo fires all of them.

| id | severity | what it catches |
|---|---|---|
| **network exposure** | | |
| TFG001 | critical | security group opens 22 or 3389 to `0.0.0.0/0` |
| TFG002 | high | security group opens any port to `0.0.0.0/0` |
| TFG003 | low | egress unrestricted |
| TFG004 | high | RDS `publicly_accessible = true` |
| TFG005 | medium | instance or launch template takes a public IP |
| TFG006 | high | standalone SG rule opens 22/3389 to the internet |
| **encryption at rest** | | |
| TFG010 | medium | S3 bucket without server-side encryption |
| TFG011 | high | S3 bucket with a public ACL |
| TFG012 | medium | EBS volume unencrypted |
| TFG013 | high | RDS storage unencrypted |
| TFG014 | medium | S3 bucket without versioning |
| TFG015 | medium | KMS key will not rotate |
| TFG017 | medium | EFS unencrypted |
| **logging and forensics** | | |
| TFG020 | low | S3 bucket without access logging |
| TFG021 | medium | internet-facing load balancer without access logs |
| TFG022 | medium | CloudTrail validation off or single-region |
| TFG023 | medium | VPC with no flow log attached |
| **identity and access** | | |
| TFG030 | critical | policy `Action "*"` |
| TFG031 | high | policy `Resource "*"` |
| TFG032 | critical | trust policy `Principal "*"` |
| TFG033 | high | wildcard action **and** wildcard resource together |
| TFG034 | high | wildcard inside an inline policy string or `jsonencode()` |
| **credential handling** | | |
| TFG040 | critical | a literal credential in a resource argument |
| TFG041 | critical | a literal credential as a variable default |
| TFG042 | medium | credential-shaped variable not marked `sensitive` |
| TFG043 | high | a credential arriving through a variable |
| TFG044 | high | a credential rendered into `user_data` or `tags` |
| **absent vs empty** | | |
| TFG050 | info | `egress = []` — a decision, recorded |
| TFG051 | info | `tags = {}` — a decision, recorded |
| TFG052 | high | `public_access_block` that blocks nothing |
| **state and supply chain** | | |
| TFG060 | medium | no remote backend |
| TFG061 | medium | S3 backend without `encrypt` |
| TFG062 | medium | provider version unconstrained |
| TFG063 | medium | module source not pinned |
| TFG064 | low | `required_version` missing |
| **cross-block relationships** | | |
| TFG070 | high | internet-facing resource in an open group |
| TFG071 | medium | SG rule naming a group not declared here |
| TFG072 | medium | RDS relying on the default security group |
| TFG073 | high | role trusting a document that trusts everyone |
| TFG075 | high | credential-shaped variable published by an output |

TFG060 and TFG061 are mutually exclusive by construction: the demo ships its
backend in `state.tf`, and deleting that file is what surfaces the other rule.
Both halves are asserted in `tests/test_demo.py`.

---

## What it does not do

- **No `terraform init`, no provider download, no plan evaluation.** It reads
  the files you committed and nothing else. Values that only exist at apply
  time are reported as references, never guessed at.
- **No `.tf.json`.** HCL2 native syntax only.
- **AWS resource types only** in 0.1.0. The parser is provider-agnostic; the
  rules are not.
- **No auto-fix.** A tool that rewrites your security groups is a tool you
  have to review more carefully than the group.
- **No network calls at all**, at any point.

## Development

```bash
git clone https://github.com/xuange-hu/tfguard
cd tfguard
pip install -e ".[mcp]" pytest ruff
pytest                 # 262 tests
ruff check src tests
```

## Related

Sibling tools with the same zero-dependency, evidence-first contract:
[`kubeguard`](https://github.com/xuange-hu/kubeguard) (Kubernetes manifests),
[`specvet`](https://github.com/xuange-hu/specvet) (OpenAPI),
[`civet`](https://github.com/xuange-hu/civet) (GitHub Actions),
[`sbomkit`](https://github.com/xuange-hu/sbomkit) (lockfiles),
[`secretsweep`](https://github.com/xuange-hu/secretsweep) (credentials).

## License

MIT

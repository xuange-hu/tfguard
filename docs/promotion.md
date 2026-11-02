# tfguard — promotion drafts

> 状态：**待轩哥确认后再发**。自动化不代发。确认后按下面的顺序逐条贴。

---

## 1. Show HN（英文，Hacker News）

标题：`Show HN: tfguard – a zero-dependency Terraform/OpenTofu auditor`

正文：

```
I wrote tfguard, a static analyzer for Terraform and OpenTofu that runs on a
bare Python 3.10+ interpreter — no pip install of a parser, no ply, no
python-hcl2. The HCL2 lexer and recursive-descent parser are in the repo.

Why: every IaC scanner I tried either pulls in a dependency tree larger than
the tool, or treats "missing" and "empty" as the same thing. tfguard keeps
them apart: `egress` absent from a security group and `egress = []` are
different findings at different severities, because one is an oversight and
the other is a deliberate lockdown.

What it does differently:

1. Three passes. Per-block rules first, then credential tracing that follows
   `var.x` / `local.y` back to the originating literal and reports the flow
   ("var.db_password -> aws_db_instance.main.password"), then a cross-block
   relationship pass (open security group that actually fronts an
   internet-facing resource, output publishing a secret-shaped variable).
2. Evidence, not conclusions. Every finding quotes the source line and the
   offset. You can check the claim instead of trusting it.
3. Registry-aware. Scanning terraform-aws-vpc (the flagship AWS module) does
   not fire on the encryption/versioning/logging rules, because since provider
   v4 those live in `aws_s3_bucket_*` companion resources. Verified against 12
   real files / 527 blocks from the registry: 0 parse failures, 1 true positive.
4. Absence is not evidence. A flow log whose `vpc_id = var.vpc_id` cannot be
   tied to an address, so a VPC is not reported as unlogged just because the
   proof lives in a child module.

Output: text, JSON, SARIF 2.1.0 (drop straight into GitHub code scanning).
Optional MCP server: `pip install "tfguard[mcp]"` → 6 tools.

262 tests, CI matrix 3.10–3.13 × ubuntu/windows, plus a fresh-clone job that
proves the src/ layout boots from a cold checkout.

Repo: https://github.com/xuange-hu/tfguard
`pip install tfguard` · `tfguard scan .` · `tfguard demo` (a hostile workspace
that fires almost every rule)

Happy to answer anything about the parser — the interesting bugs were all in
`${...}` interpolation, `for` expressions with an `if` filter, and `merge(...)`
argument expansion.
```

---

## 2. Reddit r/Terraform（英文，标题更工程向）

标题：`tfguard: a Terraform auditor that distinguishes "absent" from "empty" — 40 rules, zero dependencies, SARIF out`

正文：

```
Shipped a thing this weekend that I wish existed when I inherited my first
Terraform estate: tfguard, a static auditor for Terraform/OpenTofu with no
runtime dependencies beyond the Python standard library.

The design decisions that matter to anyone running this on real code:

* `absent` != `empty`. A security group with no `egress` block and one with
  `egress = []` are different problems. tfguard reports them as different rules
  with different severities.
* Credential taint through `var`/`local`. Finding a hard-coded secret is table
  stakes; finding the variable that reaches `aws_db_instance.password` and
  following it back to the literal in `terraform.tfvars` is what actually lets
  you fix the leak.
* Companion-resource aware. Since AWS provider v4, S3 encryption/versioning/
  logging live in separate `aws_s3_bucket_*` resources. tfguard looks at the
  workspace as a whole before it claims a bucket is unencrypted — otherwise
  every modern config lights up red on rules nobody can act on.
* Evidence on every finding: file:line plus the source line, so you can audit
  the auditor.

40 rules across network exposure, encryption, logging, identity, secrets,
absent-blocks, supply chain and cross-block relationships. Text, JSON and
SARIF 2.1.0 output; a GitHub Action for CI; an optional MCP server if you want
to drive it from an agent.

I validated it against real registry code rather than my own tests: 12 files /
527 blocks from terraform-aws-modules, 0 parse failures, and the only finding
left is the true one.

Repo: https://github.com/xuange-hu/tfguard

Criticism welcome — the rule set is the part I expect to be wrong about.
```

---

## 3. X / 推特（中文线程，5 条）

```
1/ 用了两天把 tfguard 发了：一个零依赖的 Terraform / OpenTofu 静态审计器。
   HCL2 的词法分析和递归下降解析器是自己写的，不引 python-hcl2 也不引 ply，
   python3.10+ 裸解释器直接跑。
   https://github.com/xuange-hu/tfguard

2/ 40 条规则里我最在意的是「absent ≠ empty」：
   security group 不写 egress 和写 egress = [] 是两回事，
   前者是漏配、后者是刻意收紧。别的扫描器把它们报成同一条，
   于是每次都是同一个告警，你永远不知道哪条该动手。

3/ 真正省时间的是污点追踪：找到写死的密钥只是及格，
   顺着 var.db_password 一路追到 aws_db_instance.password，
   报出「变量 → 落点」这条流向，才知道该改哪个 tfvars。
   同理还有跨块关系：安全组开 0.0.0.0/0 不算事，
   开 0.0.0.0/0 且挡在一个 internet-facing 资源前面才是事。

4/ 最大的坑在 AWS provider v4：S3 的加密/版本/日志都搬去了
   aws_s3_bucket_* 伴生资源。不看整个 workspace 就报「桶没加密」
   的话，现代配置会整片红，而每一条都是误报。
   同理 aws_flow_log 的 vpc_id = var.vpc_id —— 追不到地址就别断言 VPC 没开日志。

5/ 验证方式：拿 terraform-aws-modules 的 12 个真实文件（527 个块）跑，
   解析失败 0，剩下的告警是 1 条真阳性（没有 backend）。
   262 个测试，CI 3.10–3.13 × ubuntu/windows 全绿，输出支持 SARIF 2.1.0
   直接进 GitHub code scanning。可选装 MCP server 当 agent 工具用。
```

---

## 发布顺序建议

1. Show HN（最短窗口是美东时间周二/周三上午，中国时间周二晚 21:00 前后）
2. r/Terraform（HN 之后 1–2 天，标题换成工程向，避免被当广告折叠）
3. X 线程（配合前两条的时间点，中文圈的曝光独立于 HN）

## 待确认项

- [ ] 三条是否都发，还是先只发 Show HN
- [ ] 仓库链接用 `xuange-hu/tfguard` 是否要换成带 demo 短链
- [ ] Show HN 的 Self-promotion 需要首次发帖后 30 分钟内自己回一条评论（说明实现取舍），我可以起草

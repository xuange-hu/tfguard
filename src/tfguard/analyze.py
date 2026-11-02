"""The rule engine.

Three passes, in this order:

1. **Block pass.** Every rule that can be answered by reading one block with
   its arguments. This is what most IaC scanners do and where most of them
   stop.
2. **Credential pass.** Follows ``var`` / ``local`` references backwards until
   it finds a literal, so a credential can be reported at the line that
   declares it instead of at every line that happens to mention its name.
3. **Relationship pass.** Reads across blocks. A security group that is open
   to the internet is a finding; a security group that is open to the internet
   *and is the one protecting your internet-facing load balancer* is the one
   that matters.

Nothing here opens a file: it works on documents the loader already read.
"""

from __future__ import annotations

import json
import re

from tfguard.hcl import Attribute, Block, Call, List_, Literal, Map_, Ref, Template
from tfguard.loader import LoadedFile
from tfguard.model import Finding, Report
from tfguard.rules import BY_ID, RULES

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
WILDCARD_V4 = {"0.0.0.0/0"}
WILDCARD_V6 = {"::/0"}

SECRET_NAME_RE = re.compile(
    r"(password|passwd|secret|api_?key|access_?key|secret_?key|private_?key|credential|token|pwd)",
    re.IGNORECASE,
)

PLACEHOLDER_RE = re.compile(
    r"(example|changeme|change_me|placeholder|redacted|dummy|sample|<[^>]*>|\byour\b|\bxxx+\b|"
    r"\btodo\b|\bfixme\b|\bnull\b|\bnone\b|\btest\b|placeholder)",
    re.IGNORECASE,
)

PUBLIC_ACLS = {"public-read", "public-read-write"}
PUBLIC_BLOCK_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _is_true(expr) -> bool:
    if expr is None:
        return False
    value = expr.as_py()
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _is_false(expr) -> bool:
    if expr is None:
        return False
    value = expr.as_py()
    return value is False or (isinstance(value, str) and value.lower() == "false")


def _absent(block: Block, name: str) -> bool:
    return block.body.attr(name) is None and block.body.block(name) is None


class _Ctx:
    """What the whole workspace contains, so a block can be read in context.

    Provider v4 split several bucket settings into resources of their own.
    Reading one block at a time cannot tell "no encryption configured" from
    "configured in the resource next door", so the types present are collected
    up front.
    """

    __slots__ = ("types",)

    def __init__(self, types: set[str]):
        self.types = types

    def has(self, resource_type: str) -> bool:
        return resource_type in self.types


def _add(
    report: Report,
    loaded: LoadedFile,
    rule_id: str,
    line: int,
    flow: str = "",
    note: str = "",
    evidence: str | None = None,
) -> None:
    rule = BY_ID[rule_id]
    report.findings.append(
        Finding(
            rule_id=rule.id,
            severity=rule.severity,
            title=rule.title,
            path=loaded.doc.path if loaded.doc is not None else loaded.path,
            line=line,
            evidence=evidence if evidence is not None else loaded.line_text(line),
            flow=flow,
            note=note,
            category=rule.category,
        )
    )


def _numbers(value) -> list[int]:
    """Coerce an int, a list of ints, or a list of int-strings to ints."""
    if value is None:
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return out
    try:
        return [int(value)]
    except (TypeError, ValueError):
        return []


def _strings(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _port_range(from_port, to_port) -> tuple[int, int]:
    f = _numbers(from_port)
    t = _numbers(to_port)
    lo = f[0] if f else 0
    hi = t[0] if t else 0
    if lo == 0 and hi == 0:
        return (0, 65535)
    if hi == 0:
        hi = 65535
    return (lo, hi)


def _covers_admin(lo: int, hi: int) -> list[str]:
    hits = []
    for port, label in ADMIN_PORTS.items():
        if lo <= port <= hi:
            hits.append(f"{port} ({label})")
    return hits


# --------------------------------------------------------------------------
# ingress / egress extraction
# --------------------------------------------------------------------------


def _rule_records(block: Block, kind: str) -> list[dict]:
    """Collect the ingress/egress rules of a security group.

    Both shapes are real and both appear in the wild: nested blocks and the
    ``ingress = [{ ... }]`` list form.
    """
    out: list[dict] = []
    for nested in block.body.blocks(kind):
        out.append(
            {
                "from_port": nested.attr("from_port").value.as_py() if nested.attr("from_port") else 0,
                "to_port": nested.attr("to_port").value.as_py() if nested.attr("to_port") else 0,
                "cidrs": _strings(
                    nested.attr("cidr_blocks").value.as_py() if nested.attr("cidr_blocks") else None
                ),
                "v6": _strings(
                    nested.attr("ipv6_cidr_blocks").value.as_py()
                    if nested.attr("ipv6_cidr_blocks")
                    else None
                ),
                "line": nested.line,
                "kind": kind,
            }
        )
    attr = block.body.attr(kind)
    if attr is not None and isinstance(attr.value, Map_):
        # A single object written as ingress = { ... }
        entries = {k: v.as_py() for k, v in attr.value.entries if hasattr(v, "as_py")}
        out.append(
            {
                "from_port": entries.get("from_port", 0),
                "to_port": entries.get("to_port", 0),
                "cidrs": _strings(entries.get("cidr_blocks")),
                "v6": _strings(entries.get("ipv6_cidr_blocks")),
                "line": attr.line,
                "kind": kind,
            }
        )
    elif attr is not None and isinstance(attr.value, List_):
        # A list of objects; `egress = []` matches here too and yields nothing,
        # which is exactly the difference between "empty" and "absent".
        for item in attr.value.items:
            entries = item.as_py() if hasattr(item, "as_py") else {}
            if not isinstance(entries, dict):
                continue
            out.append(
                {
                    "from_port": entries.get("from_port", 0),
                    "to_port": entries.get("to_port", 0),
                    "cidrs": _strings(entries.get("cidr_blocks")),
                    "v6": _strings(entries.get("ipv6_cidr_blocks")),
                    "line": attr.line,
                    "kind": kind,
                }
            )
    return out


def _sg_rule_block(block: Block) -> dict | None:
    """A standalone ``aws_security_group_rule``, which stores its direction in type."""
    if block.type != "aws_security_group_rule":
        return None
    kind = block.attr("type").value.as_py() if block.attr("type") else "ingress"
    return {
        "from_port": block.attr("from_port").value.as_py() if block.attr("from_port") else 0,
        "to_port": block.attr("to_port").value.as_py() if block.attr("to_port") else 0,
        "cidrs": _strings(block.attr("cidr_blocks").value.as_py() if block.attr("cidr_blocks") else None),
        "v6": _strings(
            block.attr("ipv6_cidr_blocks").value.as_py() if block.attr("ipv6_cidr_blocks") else None
        ),
        "line": block.line,
        "kind": "ingress" if str(kind).lower() == "ingress" else "egress",
    }


def _is_public_cidr(cidr: str) -> bool:
    return cidr.strip() in WILDCARD_V4 or cidr.strip() in WILDCARD_V6


# --------------------------------------------------------------------------
# literal detection for credentials
# --------------------------------------------------------------------------


def _looks_like_secret_value(text: str) -> bool:
    if not isinstance(text, str):
        return False
    value = text.strip()
    if len(value) < 6:
        return False
    if PLACEHOLDER_RE.search(value):
        return False
    if value.startswith("${") or value.startswith("var.") or value.startswith("local."):
        return False
    # A value made only of punctuation or a single repeated character is a
    # stored-as-config placeholder, not a credential.
    if len(set(value)) <= 2:
        return False
    return not value.isdigit()


def _literal_text(expr) -> str | None:
    if isinstance(expr, Literal) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, Template) and expr.is_plain():
        return expr.parts[0]
    return None


def _is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME_RE.search(name or ""))


# --------------------------------------------------------------------------
# pass 1: one block at a time
# --------------------------------------------------------------------------


def _check_security_group(report: Report, loaded: LoadedFile, block: Block) -> None:
    for rec in _rule_records(block, "ingress"):
        if not any(_is_public_cidr(c) for c in rec["cidrs"] + rec["v6"]):
            continue
        lo, hi = _port_range(rec["from_port"], rec["to_port"])
        hits = _covers_admin(lo, hi)
        if hits:
            _add(
                report,
                loaded,
                "TFG001",
                rec["line"],
                note=f"ports {lo}-{hi} cover {', '.join(hits)}",
            )
        else:
            _add(report, loaded, "TFG002", rec["line"], note=f"ports {lo}-{hi}")
    for rec in _rule_records(block, "egress"):
        if any(_is_public_cidr(c) for c in rec["cidrs"] + rec["v6"]):
            _add(report, loaded, "TFG003", rec["line"])

    egress = block.body.attr("egress")
    if egress is not None and hasattr(egress.value, "items") and egress.value.items == []:
        _add(report, loaded, "TFG050", egress.line)

    tags = block.body.attr("tags")
    if tags is not None and hasattr(tags.value, "entries") and not tags.value.entries:
        _add(report, loaded, "TFG051", tags.line)


def _check_standalone_sg_rule(report: Report, loaded: LoadedFile, block: Block) -> None:
    rec = _sg_rule_block(block)
    if rec is None or rec["kind"] != "ingress":
        return
    if not any(_is_public_cidr(c) for c in rec["cidrs"] + rec["v6"]):
        return
    lo, hi = _port_range(rec["from_port"], rec["to_port"])
    if _covers_admin(lo, hi):
        _add(
            report,
            loaded,
            "TFG006",
            rec["line"],
            note=f"ports {lo}-{hi}",
        )
    else:
        _add(report, loaded, "TFG002", rec["line"], note=f"ports {lo}-{hi}")


def _check_s3(report: Report, loaded: LoadedFile, block: Block, ctx: _Ctx) -> None:
    # Since provider v4 the bucket settings can live in their own resources:
    # aws_s3_bucket_server_side_encryption_configuration and friends. A bucket
    # that configures encryption that way has no inline block to find, so
    # reporting it would be a false positive on every modern configuration.
    if "aws_s3_bucket_server_side_encryption_configuration" not in ctx.types and _absent(
        block, "server_side_encryption_configuration"
    ):
        _add(report, loaded, "TFG010", block.line)
    acl = block.attr("acl")
    if acl is not None:
        value = acl.value.as_py()
        if isinstance(value, str) and value.lower() in PUBLIC_ACLS:
            _add(report, loaded, "TFG011", acl.line)
    if "aws_s3_bucket_versioning" not in ctx.types:
        ver = block.body.block("versioning")
        if ver is None:
            _add(report, loaded, "TFG014", block.line)
        else:
            enabled = ver.attr("enabled")
            if enabled is None or _is_false(enabled.value):
                _add(report, loaded, "TFG014", ver.line)
    if "aws_s3_bucket_logging" not in ctx.types and _absent(block, "logging"):
        _add(report, loaded, "TFG020", block.line)

    pab = block.body.block("public_access_block")
    if pab is not None:
        _check_public_access_flags(report, loaded, pab.body.attrs(), pab.line)


def _check_public_access_flags(report: Report, loaded: LoadedFile, attrs: list[Attribute], line: int) -> None:
    """A public access block that sets nothing is not protection."""
    given = {a.name for a in attrs}
    off = [n for n in PUBLIC_BLOCK_FLAGS if n not in given]
    for a in attrs:
        if a.name in PUBLIC_BLOCK_FLAGS and _is_false(a.value):
            off.append(a.name)
    if len(set(off)) == len(PUBLIC_BLOCK_FLAGS):
        _add(report, loaded, "TFG052", line)


def _check_storage(report: Report, loaded: LoadedFile, block: Block) -> None:
    t = block.type
    if t == "aws_ebs_volume":
        enc = block.attr("encrypted")
        if enc is None or _is_false(enc.value):
            _add(report, loaded, "TFG012", (enc or block).line)
    elif t == "aws_db_instance":
        enc = block.attr("storage_encrypted")
        if enc is None or _is_false(enc.value):
            _add(report, loaded, "TFG013", (enc or block).line)
        pub = block.attr("publicly_accessible")
        if pub is not None and _is_true(pub.value):
            _add(report, loaded, "TFG004", pub.line)
    elif t == "aws_efs_file_system":
        enc = block.attr("encrypted")
        if enc is None or _is_false(enc.value):
            _add(report, loaded, "TFG017", (enc or block).line)
    elif t in ("aws_kms_key", "aws_kms_customer_master_key"):
        rot = block.attr("enable_key_rotation")
        if rot is None or _is_false(rot.value):
            _add(report, loaded, "TFG015", (rot or block).line)
    elif t == "aws_lb":
        internal = block.attr("internal")
        if internal is not None and _is_false(internal.value):
            logs = block.body.block("access_logs")
            enabled = logs.attr("enabled") if logs is not None else None
            if enabled is None or _is_false(enabled.value):
                _add(report, loaded, "TFG021", (logs or internal).line)
    elif t == "aws_cloudtrail":
        v = block.attr("enable_log_file_validation")
        if v is None or _is_false(v.value):
            _add(report, loaded, "TFG022", (v or block).line)
        m = block.attr("is_multi_region_trail")
        if m is not None and _is_false(m.value):
            _add(report, loaded, "TFG022", m.line)
    elif t == "aws_instance":
        pub = block.attr("associate_public_ip_address")
        if pub is not None and _is_true(pub.value):
            _add(report, loaded, "TFG005", pub.line)
    elif t == "aws_launch_template":
        for net in block.body.blocks("network_interfaces"):
            pub = net.attr("associate_public_ip_address")
            if pub is not None and _is_true(pub.value):
                _add(report, loaded, "TFG005", pub.line)


# --------------------------------------------------------------------------
# pass 1b: IAM
# --------------------------------------------------------------------------


def _check_iam_document(report: Report, loaded: LoadedFile, block: Block) -> None:
    """A data.aws_iam_policy_document, which is where the wildcards actually live."""
    for st in block.body.blocks("statement"):
        _check_statement(report, loaded, st, origin="document")


def _check_statement(report: Report, loaded: LoadedFile, st: Block, origin: str) -> None:
    effect = st.attr("effect")
    if effect is not None and str(effect.value.as_py()).lower() != "allow":
        return
    actions = _strings(st.attr("actions").value.as_py() if st.attr("actions") else None)
    resources = _strings(st.attr("resources").value.as_py() if st.attr("resources") else None)
    wildcard_action = any(a.strip() == "*" for a in actions)
    wildcard_resource = any(r.strip() == "*" for r in resources)

    # One report per statement, not three: the pair is a different problem
    # from either half of it, and stacking all three just makes the same line
    # appear three times in the output.
    if wildcard_action and wildcard_resource:
        _add(report, loaded, "TFG033", st.line)
    elif wildcard_action:
        _add(report, loaded, "TFG030", st.line, note=f"actions = {actions}")
    elif wildcard_resource:
        _add(report, loaded, "TFG031", st.line, note=f"resources = {resources}")

    for p in st.body.blocks("principals"):
        ids = _strings(p.attr("identifiers").value.as_py() if p.attr("identifiers") else None)
        if any(i.strip() == "*" for i in ids):
            _add(report, loaded, "TFG032", p.line)


def _check_iam_resource(report: Report, loaded: LoadedFile, block: Block) -> None:
    t = block.type
    if t == "aws_iam_role":
        arp = block.attr("assume_role_policy")
        if arp is not None:
            _scan_inline_policy(report, loaded, arp, trust=True)
    if t in ("aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy"):
        pol = block.attr("policy")
        if pol is not None:
            _scan_inline_policy(report, loaded, pol)
    for st in block.body.blocks("statement"):
        _check_statement(report, loaded, st, origin="inline")


def _policy_dict(expr) -> dict | None:
    """Read a policy written as an HCL object, or as ``jsonencode({...})``.

    ``jsonencode`` is the ordinary way to write a policy in HCL, so reading
    only a JSON-looking string would miss most of the policies in circulation.
    """
    if isinstance(expr, Map_):
        return expr.as_py()
    if isinstance(expr, Call) and expr.name == "jsonencode":
        for arg in expr.args:
            got = _policy_dict(arg)
            if got is not None:
                return got
    return None


def _scan_inline_policy(report: Report, loaded: LoadedFile, attr: Attribute, trust: bool = False) -> None:
    """Read a policy carried as a JSON string, an HCL object, or jsonencode()."""
    data: dict | None = None
    text = _literal_text(attr.value)
    if text and text.strip().startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    if data is None:
        # A reference resolves at apply time; guessing at it would produce a
        # report the reader cannot check.
        data = _policy_dict(attr.value)
    if not data:
        return
    statements = data.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if not isinstance(st, dict):
            continue
        if str(st.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = st.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = st.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        wild = []
        if any(a == "*" for a in actions):
            wild.append("Action")
        if any(r == "*" for r in resources):
            wild.append("Resource")
        if wild:
            _add(report, loaded, "TFG034", attr.line, note="policy carries " + " and ".join(wild) + " '*'")
        principal = st.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
            rule = "TFG032" if trust else "TFG034"
            _add(report, loaded, rule, attr.line, note="policy carries Principal '*'")


# --------------------------------------------------------------------------
# pass 2: credentials and where they come from
# --------------------------------------------------------------------------


class _Scope:
    """The variables and locals of one workspace, resolved to literals."""

    def __init__(self):
        self.vars: dict[str, dict] = {}
        self.locals: dict[str, dict] = {}

    def add_var(self, name: str, block: Block, loaded: LoadedFile) -> None:
        default = block.attr("default")
        sensitive = block.attr("sensitive")
        self.vars[name] = {
            "default": default.value if default else None,
            "default_line": default.line if default else block.line,
            "sensitive": _is_true(sensitive.value) if sensitive else False,
            "line": block.line,
            "loaded": loaded,
            "block": block,
        }

    def add_local(self, name: str, expr, line: int, loaded: LoadedFile) -> None:
        self.locals[name] = {"expr": expr, "line": line, "loaded": loaded}

    def literal_behind(self, expr, seen: set | None = None) -> tuple[str, list[str]] | None:
        """Return (literal text, chain) if a literal sits behind this expression."""
        if seen is None:
            seen = set()
        text = _literal_text(expr)
        if text is not None:
            return (text, [])
        if isinstance(expr, Ref):
            head = expr.path.split(".")[0]
            rest = expr.path.split(".")[1:]
            if head == "var" and rest:
                name = rest[0]
                if name in seen:
                    return None
                entry = self.vars.get(name)
                if entry is None or entry["default"] is None:
                    return None
                got = self.literal_behind(entry["default"], seen | {name})
                if got is None:
                    return None
                return (got[0], [f"var.{name}"] + got[1])
            if head == "local" and rest:
                name = rest[0]
                if name in seen:
                    return None
                entry = self.locals.get(name)
                if entry is None:
                    return None
                got = self.literal_behind(entry["expr"], seen | {name})
                if got is None:
                    return None
                return (got[0], [f"local.{name}"] + got[1])
        return None


def _build_scope(files: list[LoadedFile]) -> _Scope:
    scope = _Scope()
    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.body.blocks("variable"):
            if block.labels:
                scope.add_var(block.labels[0], block, loaded)
        for block in loaded.doc.body.blocks("locals"):
            for a in block.body.attrs():
                scope.add_local(a.name, a.value, a.line, loaded)
    return scope


def _check_variables(report: Report, scope: _Scope) -> None:
    for name, entry in sorted(scope.vars.items()):
        if not _is_secret_name(name):
            continue
        # Follow the default through locals: `default = local.db_password`
        # is the same committed credential as `default = "..."`, just one
        # hop further away from the line that has to be changed.
        got = scope.literal_behind(entry["default"]) if entry["default"] is not None else None
        if got and _looks_like_secret_value(got[0]):
            _add(
                report,
                entry["loaded"],
                "TFG041",
                entry["default_line"],
                note=f"variable {name!r} default resolves to a literal"
                + (f" through {' -> '.join(got[1])}" if got[1] else ""),
            )
        if not entry["sensitive"]:
            _add(
                report,
                entry["loaded"],
                "TFG042",
                entry["line"],
                note=f"variable {name!r} has no sensitive = true",
            )


def _check_credentials(report: Report, loaded: LoadedFile, block: Block, scope: _Scope) -> None:
    for a in block.body.attrs():
        if not _is_secret_name(a.name):
            continue
        text = _literal_text(a.value)
        if text is not None and _looks_like_secret_value(text):
            _add(
                report,
                loaded,
                "TFG040",
                a.line,
                note=f"{block.type}.{block.name}.{a.name}",
            )
            continue
        got = scope.literal_behind(a.value)
        if got and _looks_like_secret_value(got[0]):
            chain = " -> ".join(got[1] + [f"{block.type}.{block.name}.{a.name}"])
            _add(
                report,
                loaded,
                "TFG043",
                a.line,
                flow=chain,
                note="the literal is in a variable default, not on this line",
            )

    # Values rendered into places that are readable outside the state file.
    for target in ("user_data", "user_data_base64", "tags", "metadata", "metadata_options"):
        a = block.attr(target)
        if a is None:
            continue
        refs = a.value.refs()
        for r in refs:
            parts = r.path.split(".")
            if parts[0] == "var" and len(parts) > 1:
                name = parts[1]
                entry = scope.vars.get(name)
                if entry and _is_secret_name(name):
                    _add(
                        report,
                        loaded,
                        "TFG044",
                        a.line,
                        flow=f"var.{name} -> {block.type}.{block.name}.{target}",
                    )
        text = _literal_text(a.value)
        if text and target in ("user_data", "user_data_base64") and _secretish_in_text(text):
            _add(report, loaded, "TFG044", a.line, note=f"literal inside {target}")


def _secretish_in_text(text: str) -> bool:
    return bool(SECRET_NAME_RE.search(text)) and len(text.strip()) > 20


# --------------------------------------------------------------------------
# pass 3: relationships
# --------------------------------------------------------------------------


def _refs_to(value, prefix: str) -> list[str]:
    """Addresses of the form ``aws_security_group.name`` inside an expression."""
    out = []
    if value is None:
        return out
    for r in value.refs():
        parts = r.path.split(".")
        if parts[0] == prefix and len(parts) >= 2:
            out.append(f"{parts[0]}.{parts[1]}")
    return out


def _internet_facing(block: Block) -> bool:
    t = block.type
    if t == "aws_instance":
        a = block.attr("associate_public_ip_address")
        return a is not None and _is_true(a.value)
    if t == "aws_lb":
        a = block.attr("internal")
        return a is not None and _is_false(a.value)
    if t == "aws_db_instance":
        a = block.attr("publicly_accessible")
        return a is not None and _is_true(a.value)
    return False


def _check_relationships(report: Report, files: list[LoadedFile]) -> None:
    open_groups: dict[str, dict] = {}
    defined_sgs: set[str] = set()
    sg_consumers: dict[str, list[tuple[Block, LoadedFile]]] = {}
    policy_docs: dict[str, dict] = {}
    roles: list[tuple[Block, LoadedFile]] = []
    outputs: list[tuple[Block, LoadedFile]] = []
    vpcs: list[tuple[Block, LoadedFile]] = []
    flow_log_targets: set[str] = set()

    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.all_blocks():
            t = block.type
            if t == "aws_security_group":
                addr = f"aws_security_group.{block.name}"
                defined_sgs.add(addr)
                for rec in _rule_records(block, "ingress"):
                    if any(_is_public_cidr(c) for c in rec["cidrs"] + rec["v6"]):
                        open_groups.setdefault(addr, {"block": block, "loaded": loaded, "line": rec["line"]})
            elif block.kind == "data" and block.labels and block.labels[0] == "aws_iam_policy_document":
                policy_docs[f"data.aws_iam_policy_document.{block.name}"] = {"block": block, "loaded": loaded}
            elif t == "aws_iam_role":
                roles.append((block, loaded))
            elif t == "aws_vpc":
                vpcs.append((block, loaded))
            elif t == "aws_flow_log":
                a = block.attr("vpc_id")
                for r in _refs_to(a.value if a else None, "aws_vpc"):
                    flow_log_targets.add(r)
            elif t == "output":
                outputs.append((block, loaded))

            # Anything that names a security group is a consumer of it.
            for key in ("vpc_security_group_ids", "security_groups", "source_security_group_id", "security_group_id"):
                a = block.attr(key)
                for addr in _refs_to(a.value if a else None, "aws_security_group"):
                    sg_consumers.setdefault(addr, []).append((block, loaded))

    # TFG070: an open group that is what protects an internet-facing resource.
    for addr, info in open_groups.items():
        for consumer, _loaded in sg_consumers.get(addr, []):
            if consumer.address == addr:
                continue
            if _internet_facing(consumer):
                _add(
                    report,
                    info["loaded"],
                    "TFG070",
                    info["line"],
                    flow=f"{addr} -> {consumer.address}",
                    note=f"{consumer.type} is reachable from the internet",
                )
                break

    # TFG071: a rule naming a group this workspace does not declare.
    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.all_blocks():
            if block.type not in ("aws_security_group_rule", "aws_instance", "aws_network_interface"):
                continue
            for key in ("source_security_group_id", "vpc_security_group_ids", "security_groups", "security_group_id"):
                a = block.attr(key)
                if a is None:
                    continue
                for addr in _refs_to(a.value, "aws_security_group"):
                    if addr not in defined_sgs:
                        _add(
                            report,
                            loaded,
                            "TFG071",
                            a.line,
                            flow=f"{block.address}.{key} -> {addr}",
                        )

    # TFG072: RDS with no explicit security groups.
    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.all_blocks():
            if block.type == "aws_db_instance" and _absent(block, "vpc_security_group_ids"):
                _add(report, loaded, "TFG072", block.line)

    # TFG073: a role whose trust document trusts everyone.
    for block, loaded in roles:
        arp = block.attr("assume_role_policy")
        if arp is None:
            continue
        for r in arp.value.refs():
            path = r.path
            if path.startswith("data.aws_iam_policy_document."):
                doc = policy_docs.get(".".join(path.split(".")[:3]))
                if doc is None:
                    continue
                for st in doc["block"].body.blocks("statement"):
                    for p in st.body.blocks("principals"):
                        ids = _strings(p.attr("identifiers").value.as_py() if p.attr("identifiers") else None)
                        if any(i.strip() == "*" for i in ids):
                            _add(
                                report,
                                loaded,
                                "TFG073",
                                arp.line,
                                flow=f"{'.'.join(path.split('.')[:3])} -> {block.address}",
                            )

    # TFG023: a VPC nobody attached a flow log to.
    for block, loaded in vpcs:
        if f"aws_vpc.{block.name}" not in flow_log_targets:
            _add(report, loaded, "TFG023", block.line)

    # TFG075: an output publishing a credential-shaped variable.
    for block, loaded in outputs:
        v = block.attr("value")
        if v is None:
            continue
        sensitive = block.attr("sensitive")
        if sensitive is not None and _is_true(sensitive.value):
            continue
        for r in v.value.refs():
            parts = r.path.split(".")
            if parts[0] == "var" and len(parts) > 1 and _is_secret_name(parts[1]):
                _add(
                    report,
                    loaded,
                    "TFG075",
                    v.line,
                    flow=f"var.{parts[1]} -> output.{block.name}",
                )


# --------------------------------------------------------------------------
# pass 4: the workspace itself
# --------------------------------------------------------------------------


def _check_workspace(report: Report, files: list[LoadedFile]) -> None:
    terraform_blocks: list[tuple[Block, LoadedFile]] = []
    has_backend = False
    backend_blocks: list[tuple[Block, LoadedFile]] = []
    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.body.blocks("terraform"):
            terraform_blocks.append((block, loaded))
            for b in block.body.blocks("backend"):
                has_backend = True
                backend_blocks.append((b, loaded))

    if not has_backend:
        # Only meaningful when there is actually something to store, and it
        # belongs at the terraform block that would have carried the backend,
        # not at whatever file happens to be first.
        total = sum(len(loaded.doc.resources) for loaded in files if loaded.doc is not None)
        if total:
            target = terraform_blocks[0] if terraform_blocks else None
            if target is not None:
                block, loaded = target
                _add(
                    report,
                    loaded,
                    "TFG060",
                    block.line,
                    evidence="workspace has no backend block",
                )
            else:
                first = next(
                    (loaded for loaded in files if loaded.doc is not None and loaded.doc.resources), None
                )
                _add(report, first, "TFG060", 1, evidence="workspace has no backend block")
    for b, loaded in backend_blocks:
        if b.labels and b.labels[0] == "s3":
            enc = b.attr("encrypt")
            if enc is None or _is_false(enc.value):
                _add(report, loaded, "TFG061", (enc or b).line)

    for block, loaded in terraform_blocks:
        rp = block.body.block("required_providers")
        if rp is not None:
            for a in rp.body.attrs():
                if isinstance(a.value, Map_) and a.value.get("version") is None:
                    _add(report, loaded, "TFG062", a.line, note=f"provider {a.name}")
        if block.attr("required_version") is None:
            _add(report, loaded, "TFG064", block.line)

    for loaded in files:
        if loaded.doc is None:
            continue
        for block in loaded.doc.body.blocks("module"):
            src = block.attr("source")
            if src is None:
                continue
            value = src.value.as_py()
            if not isinstance(value, str):
                continue
            if value.startswith("git::") or value.startswith("github.com/") or value.startswith("git@"):
                if "ref=" not in value:
                    _add(report, loaded, "TFG063", src.line, note="git source without ref=")
            elif value.startswith("./") or value.startswith("../") or value.startswith("/"):
                pass  # a local path is pinned by the commit it sits in
            elif block.attr("version") is None:
                # A registry source pins with a version argument, not with a
                # path segment: "namespace/name/provider" plus version = "4.0.0".
                _add(report, loaded, "TFG063", src.line, note="registry source without a version")


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------


def scan_documents(files: list[LoadedFile]) -> Report:
    report = Report()
    parsed = [f for f in files if f.doc is not None]
    for f in files:
        if f.doc is None:
            report.files_failed += 1
            report.errors.append(f"{f.path}: {f.error}")
    report.files_scanned = len(files)

    scope = _build_scope(parsed)
    _check_variables(report, scope)

    types: set[str] = set()
    for loaded in parsed:
        for block in loaded.doc.all_blocks():
            if block.kind == "resource":
                types.add(block.type)
    ctx = _Ctx(types)

    for loaded in parsed:
        for block in loaded.doc.all_blocks():
            # A data block's `type` is the provider type it reads, so it has to
            # be matched on `kind` before the resource types are considered.
            if block.kind == "data" and block.labels and block.labels[0] == "aws_iam_policy_document":
                _check_iam_document(report, loaded, block)
                continue
            t = block.type
            if t == "aws_security_group":
                _check_security_group(report, loaded, block)
            elif t == "aws_security_group_rule":
                _check_standalone_sg_rule(report, loaded, block)
            elif t == "aws_s3_bucket":
                _check_s3(report, loaded, block, ctx)
            elif t == "aws_s3_bucket_public_access_block":
                # A standalone config resource, not a bucket: it has no
                # encryption, versioning or logging of its own to be missing.
                _check_public_access_flags(report, loaded, block.body.attrs(), block.line)
            elif t in (
                "aws_ebs_volume",
                "aws_db_instance",
                "aws_efs_file_system",
                "aws_kms_key",
                "aws_kms_customer_master_key",
                "aws_lb",
                "aws_cloudtrail",
                "aws_instance",
                "aws_launch_template",
            ):
                _check_storage(report, loaded, block)
            elif t.startswith("aws_iam"):
                _check_iam_resource(report, loaded, block)
            if block.kind == "resource":
                _check_credentials(report, loaded, block, scope)
        report.resources += len(loaded.doc.resources)

    _check_relationships(report, parsed)
    _check_workspace(report, parsed)

    # Suppression happens last so the report can still be rendered with it.
    for f in report.findings:
        loaded = _loaded_for(files, f.path)
        if loaded is None:
            continue
        if loaded.is_suppressed(f.line, f.rule_id):
            f.suppressed = True
    return report


def _loaded_for(files: list[LoadedFile], path: str) -> LoadedFile | None:
    for f in files:
        display = f.doc.path if f.doc is not None else f.path
        if display == path or f.path == path:
            return f
    return None


def scan(path: str) -> Report:
    from tfguard.loader import load_path

    files = load_path(path, base=path)
    return scan_documents(files)


def all_rule_ids() -> list[str]:
    return [r.id for r in RULES]

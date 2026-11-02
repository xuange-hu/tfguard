"""A zero-dependency HCL2 subset parser.

Terraform's native syntax (HCL2) is what every ``.tf`` file is written in. The
canonical Python readers pull a dependency tree with them: ``python-hcl2``
needs ``ply``, and checkov pulls ``bc-python-hcl2`` plus a dozen more. This
module reads the subset that real Terraform files are actually made of with
nothing but the standard library.

What it handles, because real files use it:

* blocks with labels: ``resource "aws_s3_bucket" "logs" { ... }``;
* block bodies and object-as-block: ``server_side_encryption_configuration { rule { ... } }``;
* attributes, lists, objects, function calls, references, index access;
* template interpolation: ``"${var.env}-logs"``;
* heredocs (both plain and the indented ``<<-`` form);
* conditionals, for-expressions, splats and ordinary operators;
* ``#``, ``//`` and ``/* */`` comments.

Every node carries the 1-based line it started on, which is what lets the
reporter quote the offending line back at the reader instead of asking them to
go hunting for it.
"""

from __future__ import annotations

import bisect
from typing import Any

# --------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------

PUNCT = (
    ("<<", "HEREDOC"),
    # Argument expansion: "merge(a, b)...". It has to be matched before the
    # single dot, or "..." lexes as three attribute accesses.
    ("...", "ELLIPSIS"),
    ("&&", "AND"),
    ("||", "OR"),
    ("==", "EQ"),
    ("!=", "NE"),
    ("<=", "LE"),
    (">=", "GE"),
    ("=>", "FATARROW"),
    ("=", "ASSIGN"),
    ("{", "LBRACE"),
    ("}", "RBRACE"),
    ("[", "LBRACK"),
    ("]", "RBRACK"),
    ("(", "LPAREN"),
    (")", "RPAREN"),
    (",", "COMMA"),
    ("+", "PLUS"),
    ("-", "MINUS"),
    ("*", "STAR"),
    ("/", "SLASH"),
    ("%", "PERCENT"),
    ("<", "LT"),
    (">", "GT"),
    ("!", "BANG"),
    ("?", "QUESTION"),
    (":", "COLON"),
    (".", "DOT"),
)

KEYWORDS = {"true": "BOOL", "false": "BOOL", "null": "NULL", "for": "FOR"}

ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "$": "$", "%": "%"}

# Binary precedence, lowest first. Keyed by token kind, because the operator
# text ("&&") and the token kind ("AND") are not the same thing.
BINPREC = {
    "OR": 1,
    "AND": 2,
    "EQ": 3,
    "NE": 3,
    "LT": 4,
    "LE": 4,
    "GT": 4,
    "GE": 4,
    "PLUS": 5,
    "MINUS": 5,
    "STAR": 6,
    "SLASH": 6,
    "PERCENT": 6,
}

IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
# Deliberately no "." here: a dotted path is assembled in the parser's
# postfix loop, where "a.b" can be told apart from the "..." expansion
# marker. Lexing the dot into the identifier swallowed "local.b..." whole.
IDENT_BODY = IDENT_START | set("0123456789-")
DIGITS = set("0123456789")


class HclError(Exception):
    """Raised for input this parser decided not to guess at."""

    def __init__(self, message: str, line: int = 0):
        super().__init__(message)
        self.message = message
        self.line = line


class Tok:
    __slots__ = ("kind", "value", "line", "parts")

    def __init__(self, kind: str, value: Any, line: int, parts: Any = None):
        self.kind = kind
        self.value = value
        self.line = line
        self.parts = parts

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Tok({self.kind}, {self.value!r}, line={self.line})"


class LineIndex:
    """Offset -> 1-based line, so line numbers never fall out of sync."""

    def __init__(self, src: str):
        self._starts = [0]
        pos = 0
        for raw in src.splitlines(keepends=True):
            pos += len(raw)
            self._starts.append(pos)

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self._starts, pos)


def _skip_string(src: str, i: int) -> int:
    """Return the index just past the string literal starting at ``src[i]``."""
    i += 1
    while i < len(src):
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == '"':
            return i + 1
        i += 1
    return len(src)


def _lex_template_inner(src: str, i: int) -> int:
    """Return the index just past ``${...}`` starting at ``src[i] == '$'``."""
    depth = 0
    while i < len(src):
        c = src[i]
        if c == '"':
            i = _skip_string(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(src)


def _lex_string(src: str, i: int, line: int) -> tuple[Tok, int]:
    """Lex a quoted string, splitting out ``${...}`` interpolations.

    The parts are kept because the rule engine needs to tell
    ``"hunter2"`` (a literal credential) from ``"${var.pw}"`` (a reference).
    """
    i += 1
    parts: list[tuple[str, Any]] = []
    buf: list[str] = []
    while i < len(src):
        c = src[i]
        if c == "\\":
            nxt = src[i + 1] if i + 1 < len(src) else ""
            buf.append(ESCAPES.get(nxt, nxt or "\\"))
            i += 2
            continue
        if c == '"':
            i += 1
            break
        if c == "\n":
            break
        if c == "$" and i + 1 < len(src) and src[i + 1] == "{":
            if buf:
                parts.append(("lit", "".join(buf)))
                buf = []
            inner_end = _lex_template_inner(src, i + 1)
            parts.append(("interp", src[i + 2 : inner_end - 1]))
            i = inner_end
            continue
        buf.append(c)
        i += 1
    if buf:
        parts.append(("lit", "".join(buf)))
    # The token's value has to carry the rendered text as well as the parts:
    # block labels come straight from STRING tokens, and a label that renders
    # as "" would silently turn every resource into the same unnamed resource.
    plain = "".join(text if kind == "lit" else "${" + text + "}" for kind, text in parts)
    return Tok("STRING", plain, line, parts), i


def _lex_heredoc(src: str, i: int, line: int) -> tuple[Tok, int]:
    j = i + 2
    indented = False
    if j < len(src) and src[j] == "-":
        indented = True
        j += 1
    marker_end = j
    while marker_end < len(src) and src[marker_end] not in "\r\n":
        marker_end += 1
    marker = src[j:marker_end].strip()
    i = marker_end
    # The newline that closes the opening marker.
    while i < len(src) and src[i] in "\r":
        i += 1
    if i < len(src) and src[i] == "\n":
        i += 1

    body_start = i
    out: list[str] = []
    while i < len(src):
        # Candidate terminator lines only: gather the raw line.
        eol = src.find("\n", i)
        raw = src[i : eol if eol != -1 else len(src)]
        candidate = raw.strip()
        if candidate == marker or candidate == marker + "\r":
            i = (eol + 1) if eol != -1 else len(src)
            break
        piece = raw
        if indented:
            piece = piece.lstrip("\t ") if piece.strip() else piece
        out.append(piece.rstrip("\r"))
        if eol == -1:
            i = len(src)
            break
        i = eol + 1
        out.append("\n")
    text = "".join(out)
    del body_start
    return Tok("HEREDOC", text, line, [("lit", text)]), i


def tokenize(src: str) -> list[Tok]:
    idx = LineIndex(src)
    toks: list[Tok] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "#" or src.startswith("//", i):
            eol = src.find("\n", i)
            i = n if eol == -1 else eol + 1
            continue
        if src.startswith("/*", i):
            end = src.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue

        line = idx.line_of(i)

        if src.startswith("<<", i):
            tok, i = _lex_heredoc(src, i, line)
            toks.append(tok)
            continue
        if c == '"':
            tok, i = _lex_string(src, i, line)
            toks.append(tok)
            continue
        if c in DIGITS or (c == "-" and i + 1 < n and src[i + 1] in DIGITS):
            j = i + 1
            seen_dot = False
            while j < n and (src[j] in DIGITS or (src[j] == "." and not seen_dot)):
                if src[j] == ".":
                    seen_dot = True
                j += 1
            # 1e9 style exponents are legal in HCL and appear in size values
            if j < n and src[j] in "eE":
                k = j + 1
                if k < n and src[k] in "+-":
                    k += 1
                if k < n and src[k] in DIGITS:
                    while k < n and src[k] in DIGITS:
                        k += 1
                    j = k
            raw = src[i:j]
            toks.append(Tok("NUMBER", float(raw) if seen_dot or "e" in raw.lower() else int(raw), line))
            i = j
            continue
        if c in IDENT_START:
            j = i
            while j < n and src[j] in IDENT_BODY:
                j += 1
            raw = src[i:j]
            toks.append(Tok(KEYWORDS.get(raw, "IDENT"), raw, line))
            i = j
            continue

        matched = False
        for text, kind in PUNCT:
            if src.startswith(text, i):
                # A lone "-" is a binary minus far more often than heredoc
                if text == "<<" and not (i + 2 < n and src[i + 2] in IDENT_START):
                    continue
                toks.append(Tok(kind, text, line))
                i += len(text)
                matched = True
                break
        if matched:
            continue

        raise HclError(f"unexpected character {c!r}", line)

    toks.append(Tok("EOF", "", idx.line_of(n)))
    return toks


# --------------------------------------------------------------------------
# expression nodes
# --------------------------------------------------------------------------


class Expr:
    __slots__ = ("line",)

    def refs(self) -> list[Ref]:
        return []

    def as_py(self) -> Any:
        return None


class Literal(Expr):
    __slots__ = ("value",)

    def __init__(self, value: Any, line: int):
        self.value = value
        self.line = line

    def as_py(self) -> Any:
        return self.value

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Literal({self.value!r})"


class Template(Expr):
    """A string with zero or more ``${...}`` interpolations."""

    __slots__ = ("parts",)

    def __init__(self, parts: list[Any], line: int):
        self.parts = parts
        self.line = line

    def is_plain(self) -> bool:
        return len(self.parts) == 1 and isinstance(self.parts[0], str)

    def as_py(self) -> Any:
        return "".join(p if isinstance(p, str) else "${...}" for p in self.parts)

    def refs(self) -> list[Ref]:
        out: list[Ref] = []
        for p in self.parts:
            if not isinstance(p, str):
                out.extend(p.refs())
        return out


class Ref(Expr):
    __slots__ = ("path",)

    def __init__(self, path: str, line: int):
        self.path = path
        self.line = line

    def head(self) -> str:
        return self.path.split(".")[0]

    def as_py(self) -> Any:
        return self.path

    def refs(self) -> list[Ref]:
        return [self]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Ref({self.path})"


class List_(Expr):
    __slots__ = ("items",)

    def __init__(self, items: list[Expr], line: int):
        self.items = items
        self.line = line

    def as_py(self) -> Any:
        return [it.as_py() for it in self.items]

    def refs(self) -> list[Ref]:
        out: list[Ref] = []
        for it in self.items:
            out.extend(it.refs())
        return out


class Map_(Expr):
    """An object constructor. ``entries`` holds (key, Expr) pairs.

    Keys backed by a nested block (``rule { ... }``) carry a ``Body`` instead.
    """

    __slots__ = ("entries",)

    def __init__(self, entries: list[tuple[str, Any]], line: int):
        self.entries = entries
        self.line = line

    def get(self, key: str) -> Any:
        for k, v in self.entries:
            if k == key:
                return v
        return None

    def as_dict_scalars(self) -> dict[str, Any]:
        return {k: v.as_py() for k, v in self.entries if isinstance(v, Expr)}

    def as_py(self) -> Any:
        return {k: (v.as_py() if isinstance(v, Expr) else "{...}") for k, v in self.entries}

    def refs(self) -> list[Ref]:
        out: list[Ref] = []
        for _, v in self.entries:
            if isinstance(v, Expr):
                out.extend(v.refs())
            else:
                for item in v:
                    if isinstance(item, Attribute):
                        out.extend(item.value.refs())
        return out


class Call(Expr):
    __slots__ = ("name", "args")

    def __init__(self, name: str, args: list[Expr], line: int):
        self.name = name
        self.args = args
        self.line = line

    def as_py(self) -> Any:
        return f"{self.name}(...)"

    def refs(self) -> list[Ref]:
        out: list[Ref] = []
        for a in self.args:
            out.extend(a.refs())
        return out


class Index(Expr):
    __slots__ = ("target", "key")

    def __init__(self, target: Expr, key: Any, line: int):
        self.target = target
        self.key = key
        self.line = line

    def as_py(self) -> Any:
        return self.target.as_py()

    def refs(self) -> list[Ref]:
        return self.target.refs()


class For_(Expr):
    __slots__ = ("kind", "inner", "binds")

    def __init__(self, kind: str, inner: list[Expr], line: int, binds: tuple[str, ...] = ()):
        self.kind = kind
        self.inner = inner
        self.line = line
        # The loop variables. They are local bindings, so they must not show
        # up as references into the workspace.
        self.binds = binds

    def as_py(self) -> Any:
        return f"<for {self.kind}>"

    def refs(self) -> list[Ref]:
        out: list[Ref] = []
        for e in self.inner:
            for r in e.refs():
                if r.head() not in self.binds:
                    out.append(r)
        return out


class Cond(Expr):
    __slots__ = ("cond", "true_", "false_")

    def __init__(self, cond: Expr, true_: Expr, false_: Expr, line: int):
        self.cond = cond
        self.true_ = true_
        self.false_ = false_
        self.line = line

    def as_py(self) -> Any:
        # Deliberately symbolic: a rule must not conclude "encrypted" just
        # because one branch of a conditional happens to say true.
        return "<cond>"

    def refs(self) -> list[Ref]:
        out = list(self.cond.refs())
        out.extend(self.true_.refs())
        out.extend(self.false_.refs())
        return out


class Unary(Expr):
    __slots__ = ("op", "operand")

    def __init__(self, op: str, operand: Expr, line: int):
        self.op = op
        self.operand = operand
        self.line = line

    def as_py(self) -> Any:
        if self.op == "-" and isinstance(self.operand.as_py(), (int, float)):
            return -self.operand.as_py()
        return self.operand.as_py()

    def refs(self) -> list[Ref]:
        return self.operand.refs()


class Binary(Expr):
    __slots__ = ("op", "left", "right")

    def __init__(self, op: str, left: Expr, right: Expr, line: int):
        self.op = op
        self.left = left
        self.right = right
        self.line = line

    def as_py(self) -> Any:
        return f"<{self.op}>"

    def refs(self) -> list[Ref]:
        return list(self.left.refs()) + list(self.right.refs())


class Splat(Expr):
    """``aws_instance.web[*].id`` — the ``*`` form of index access."""

    __slots__ = ("target", "attr")

    def __init__(self, target: Expr, attr: str, line: int):
        self.target = target
        self.attr = attr
        self.line = line

    def as_py(self) -> Any:
        return f"<splat {self.attr}>"

    def refs(self) -> list[Ref]:
        return self.target.refs()


# --------------------------------------------------------------------------
# body nodes
# --------------------------------------------------------------------------


class Attribute:
    __slots__ = ("name", "value", "line")

    def __init__(self, name: str, value: Expr, line: int):
        self.name = name
        self.value = value
        self.line = line

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Attribute({self.name})"


class Block:
    __slots__ = ("kind", "labels", "body", "line")

    def __init__(self, kind: str, labels: list[str], body: Body, line: int):
        self.kind = kind
        self.labels = labels
        self.body = body
        self.line = line

    @property
    def type(self) -> str:
        if self.kind == "resource" and len(self.labels) == 2:
            return self.labels[0]
        if self.kind == "data" and len(self.labels) == 2:
            return self.labels[0]
        return self.kind

    @property
    def name(self) -> str:
        if self.kind in ("resource", "data") and len(self.labels) == 2:
            return self.labels[1]
        if self.labels:
            return self.labels[0]
        return self.kind

    @property
    def address(self) -> str:
        if self.kind in ("resource", "data"):
            return ".".join([self.kind, *self.labels])
        if self.kind == "variable" and self.labels:
            return f"var.{self.labels[0]}"
        if self.kind == "locals":
            return "local"
        if self.labels:
            return ".".join([self.kind, *self.labels])
        return self.kind

    def get(self, key: str) -> Any:
        return self.body.get(key)

    def attr(self, key: str) -> Attribute | None:
        return self.body.attr(key)

    def blocks(self, kind: str | None = None) -> list[Block]:
        return self.body.blocks(kind)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Block({self.address}, line={self.line})"


class Body:
    __slots__ = ("items",)

    def __init__(self, items: list[Any]):
        self.items = items

    def attrs(self) -> list[Attribute]:
        return [i for i in self.items if isinstance(i, Attribute)]

    def blocks(self, kind: str | None = None) -> list[Block]:
        out = [i for i in self.items if isinstance(i, Block)]
        if kind is None:
            return out
        return [b for b in out if b.kind == kind]

    def attr(self, key: str) -> Attribute | None:
        for i in self.items:
            if isinstance(i, Attribute) and i.name == key:
                return i
        return None

    def get(self, key: str) -> Any:
        a = self.attr(key)
        if a is not None:
            return a.value
        b = self.block(key)
        if b is not None:
            return b.body
        return None

    def block(self, kind: str) -> Block | None:
        for i in self.items:
            if isinstance(i, Block) and i.kind == kind:
                return i
        return None

    def has(self, key: str) -> bool:
        return self.attr(key) is not None or self.block(key) is not None


class Document:
    __slots__ = ("body", "src", "path", "index")

    def __init__(self, body: Body, src: str, path: str = "", index: LineIndex | None = None):
        self.body = body
        self.src = src
        self.path = path
        self.index = index or LineIndex(src)

    def line_text(self, line: int) -> str:
        lines = self.src.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""

    @property
    def resources(self) -> list[Block]:
        return self.body.blocks("resource")

    @property
    def data_blocks(self) -> list[Block]:
        return self.body.blocks("data")

    def all_blocks(self) -> list[Block]:
        out: list[Block] = []
        stack = list(self.body.items)
        while stack:
            item = stack.pop()
            if isinstance(item, Block):
                out.append(item)
                stack.extend(item.body.items)
        return out


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


class Parser:
    def __init__(self, src: str):
        self.src = src
        self.toks = tokenize(src)
        self.pos = 0

    # -- token helpers -----------------------------------------------------
    def peek(self, k: int = 0) -> Tok:
        j = self.pos + k
        if j >= len(self.toks):
            return self.toks[-1]
        return self.toks[j]

    def at(self, kind: str) -> bool:
        return self.peek().kind == kind

    def next(self) -> Tok:
        t = self.toks[self.pos]
        if t.kind != "EOF":
            self.pos += 1
        return t

    def accept(self, kind: str) -> Tok | None:
        if self.at(kind):
            return self.next()
        return None

    def expect(self, kind: str) -> Tok:
        t = self.peek()
        if t.kind != kind:
            raise HclError(f"expected {kind} but found {t.kind} ({t.value!r})", t.line)
        return self.next()

    def error(self, msg: str, line: int = 0) -> HclError:
        return HclError(msg, line or self.peek().line)

    # -- entry -------------------------------------------------------------
    def parse(self) -> Document:
        body = self.parse_body(top=True)
        return Document(body, self.src)

    def parse_body(self, top: bool = False) -> Body:
        items: list[Any] = []
        while not self.at("EOF"):
            if self.at("RBRACE"):
                break
            item = self.parse_item()
            if item is not None:
                items.append(item)
            else:  # pragma: no cover - defensive: guarantees progress
                self.next()
        if top and not self.at("EOF"):
            raise self.error("unbalanced closing brace")
        return Body(items)

    def parse_item(self) -> Any:
        t = self.peek()
        if t.kind not in ("IDENT", "NULL", "BOOL", "FOR"):
            raise self.error(f"unexpected {t.kind} at body level", t.line)
        if t.kind in ("NULL", "BOOL", "FOR") or t.kind == "IDENT" and t.value in ("for", "true", "false", "null"):
            raise self.error(f"unexpected token {t.value!r} at body level", t.line)
        name = self.next().value
        # block: label(s) then {
        if self.at("ASSIGN"):
            self.next()
            value = self.parse_expr()
            return Attribute(name, value, t.line)
        labels: list[str] = []
        while self.at("STRING") or (self.at("IDENT") and self.peek(1).kind in ("IDENT", "STRING", "LBRACE", "DOT")):
            # A block label; stop if this is actually the next attribute name
            if self.at("IDENT") and self.peek(1).kind == "ASSIGN":
                if not labels:
                    # it was an attribute after all -> hand it back
                    self.pos -= 1
                    raise self.error(f"attribute {name!r} has no value", t.line)
                break
            nx = self.next()
            labels.append(nx.value)
        if not self.at("LBRACE"):
            raise self.error(f"block {name!r} has no opening brace", t.line)
        self.next()
        body = self.parse_body()
        if not self.at("RBRACE"):
            raise self.error(f"block {name!r} is never closed", t.line)
        self.next()
        return Block(name, labels, body, t.line)

    # -- expressions -------------------------------------------------------
    def parse_expr(self, prec: int = 0) -> Expr:
        left = self.parse_unary()
        while True:
            t = self.peek()
            if t.kind not in BINPREC or BINPREC[t.kind] < prec:
                break
            self.next()
            right = self.parse_expr(BINPREC[t.kind] + 1)
            left = Binary(t.value, left, right, t.line)
        # The conditional binds loosest of all, so it can only be taken at the
        # outermost level; nested conditions come through parentheses.
        if prec == 0 and self.at("QUESTION"):
            q = self.next()
            a = self.parse_expr()
            self.expect("COLON")
            b = self.parse_expr()
            return Cond(left, a, b, q.line)
        return left

    def parse_unary(self) -> Expr:
        t = self.peek()
        if t.kind in ("MINUS", "BANG"):
            self.next()
            operand = self.parse_unary()
            return Unary(t.kind, operand, t.line)
        return self.parse_postfix()

    def parse_postfix(self) -> Expr:
        node = self.parse_primary()
        while True:
            t = self.peek()
            if t.kind == "DOT":
                self.next()
                nx = self.peek()
                if nx.kind == "STAR":
                    self.next()
                    self.expect("RBRACK")
                    nxt2 = self.peek()
                    if nxt2.kind == "DOT":
                        self.next()
                        attr = self.next().value
                    else:
                        attr = "*"
                    node = Splat(node, attr, t.line)
                    continue
                if nx.kind in ("IDENT", "NUMBER"):
                    self.next()
                    if isinstance(node, Ref):
                        node = Ref(f"{node.path}.{nx.value}", node.line)
                    else:
                        node = Index(node, nx.value, t.line)
                    continue
                break
            if t.kind == "LBRACK":
                self.next()
                if self.at("STAR"):
                    self.next()
                    self.expect("RBRACK")
                    if self.at("DOT"):
                        self.next()
                        attr = self.next().value
                    else:
                        attr = "*"
                    node = Splat(node, attr, t.line)
                    continue
                inner = self.parse_expr()
                self.expect("RBRACK")
                node = Index(node, inner, t.line)
                continue
            if t.kind == "LPAREN" and isinstance(node, Ref):
                # Only a bare name can be called; `a.b(...)` is not HCL.
                self.next()
                args: list[Expr] = []
                while not self.at("RPAREN") and not self.at("EOF"):
                    args.append(self.parse_expr())
                    # "merge(one, two)...": the expansion marker belongs to the
                    # argument before it, and it is not an expression.
                    self.accept("ELLIPSIS")
                    self.accept("COMMA")
                self.expect("RPAREN")
                node = Call(node.path, args, node.line)
                continue
            break
        return node

    def parse_primary(self) -> Expr:
        t = self.peek()
        if t.kind == "LPAREN":
            self.next()
            inner = self.parse_expr()
            self.expect("RPAREN")
            return inner
        if t.kind == "LBRACK":
            return self.parse_collection("[")
        if t.kind == "LBRACE":
            return self.parse_collection("{")
        if t.kind == "NUMBER":
            self.next()
            return Literal(t.value, t.line)
        if t.kind == "BOOL":
            self.next()
            return Literal(t.value == "true", t.line)
        if t.kind == "NULL":
            self.next()
            return Literal(None, t.line)
        if t.kind == "STRING":
            self.next()
            return self.build_template(t.parts or [], t.line)
        if t.kind == "HEREDOC":
            self.next()
            return Template([t.value], t.line)
        if t.kind == "BANG":
            self.next()
            return Unary("!", self.parse_primary(), t.line)
        if t.kind == "IDENT":
            self.next()
            return Ref(t.value, t.line)
        if t.kind == "QUESTION":
            # nothing sensible on the left; treat as a plain reference
            raise self.error("expression starts with '?'", t.line)
        raise self.error(f"unexpected {t.kind} ({t.value!r}) in expression", t.line)

    def build_template(self, parts: list[tuple[str, Any]], line: int) -> Expr:
        if len(parts) == 1 and parts[0][0] == "lit":
            return Literal(parts[0][1], line)
        built: list[Any] = []
        for kind, text in parts:
            if kind == "lit":
                built.append(text)
            else:
                built.append(Parser(text).parse_interp())
        return Template(built, line)

    def parse_interp(self) -> Expr:
        """Parse the inside of ``${...}`` as a standalone expression."""
        return self.parse_expr()

    def parse_collection(self, opener: str) -> Expr:
        t = self.peek()
        self.next()
        closer = "RBRACK" if opener == "[" else "RBRACE"
        if self.at("FOR"):
            self.next()
            inner: list[Expr] = []
            binds: list[str] = []
            # "[for a, b in source : out]" — the `in` keyword is not an
            # expression and the loop variables are local bindings, so both
            # are consumed rather than parsed into the expression tree.
            while not self.at("COLON") and not self.at("EOF"):
                cur = self.peek()
                if cur.kind == "IDENT" and cur.value == "in":
                    self.next()
                    continue
                if cur.kind == "IDENT" and self.peek(1).kind == "IDENT" and self.peek(1).value == "in":
                    binds.append(cur.value)
                    self.next()
                    continue
                if cur.kind == "IDENT" and self.peek(1).kind == "COMMA":
                    binds.append(cur.value)
                    self.next()
                    self.accept("COMMA")
                    continue
                inner.append(self.parse_expr())
                self.accept("COMMA")
            self.accept("COLON")
            if opener == "{":
                # An object for-expression carries "key => value".
                inner.append(self.parse_expr())
                self.accept("FATARROW")
                inner.append(self.parse_expr())
            else:
                inner.append(self.parse_expr())
            # The optional filter: "[for x in y : x if x.enabled]". It is in
            # every popular module and it is not an operator, so it has to be
            # consumed here — the expression parser would stop at the closer.
            if self.at("IDENT") and self.peek().value == "if":
                self.next()
                inner.append(self.parse_expr())
            self.expect(closer)
            return For_(opener, inner, t.line, tuple(binds))
        if self.at(closer):
            self.next()
            return (List_ if opener == "[" else Map_)([], t.line)

        if opener == "[":
            items: list[Expr] = []
            while not self.at("RBRACK") and not self.at("EOF"):
                items.append(self.parse_expr())
                if not self.accept("COMMA"):
                    break
            self.expect("RBRACK")
            # trailing "for" tail on a literal list is rare; ignore it
            return List_(items, t.line)

        entries: list[tuple[str, Any]] = []
        while not self.at("RBRACE") and not self.at("EOF"):
            key_line = self.peek().line
            key = self.parse_object_key()
            if self.accept("ASSIGN") or self.accept("COLON"):
                entries.append((key, self.parse_expr()))
            elif self.at("LBRACE"):
                self.next()
                body = self.parse_body()
                self.expect("RBRACE")
                entries.append((key, body))
            else:
                raise self.error(f"object key {key!r} has no value", self.peek().line)
            if not self.accept("COMMA"):
                # HCL lets object entries be newline-separated; tuple elements
                # may not (they need commas). Requiring a new line here is what
                # keeps `a = [1]` + `b = 2` from swallowing b as an element.
                nx = self.peek()
                if nx.kind not in ("STRING", "IDENT", "NUMBER", "LPAREN") or nx.line <= key_line:
                    break
        self.expect("RBRACE")
        return Map_(entries, t.line)

    def parse_object_key(self) -> str:
        t = self.peek()
        if t.kind == "STRING":
            self.next()
            parts = t.parts or []
            if len(parts) == 1 and parts[0][0] == "lit":
                return parts[0][1]
            return "".join(p if isinstance(p, str) else "${...}" for p in parts)
        if t.kind in ("IDENT", "NUMBER"):
            self.next()
            return str(t.value)
        if t.kind == "LPAREN":
            self.next()
            inner = self.parse_expr()
            self.expect("RPAREN")
            return str(inner.as_py())
        raise self.error(f"unexpected object key {t.value!r}", t.line)


def parse(text: str, path: str = "") -> Document:
    """Parse ``text`` and return a :class:`Document`."""
    p = Parser(text)
    doc = p.parse()
    doc.path = path
    return doc


def parse_interp(text: str) -> Expr:
    """Parse the body of a ``${...}`` interpolation on its own."""
    return Parser(text).parse_interp()

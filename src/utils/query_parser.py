"""
Query Syntax Parser
Supported Fields: request_id, type, attack_types, time, ip, cdn_ip, country, city,
                  fingerprint, method, url, headers, content
Supported Operators: AND, OR, NOT, IN, Parentheses grouping
Time Format: ISO 8601, e.g., 2026-03-24T22:43:23.313218

If a value contains spaces, parentheses, semicolons, or other special characters, wrap it in double quotes:
    headers:"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    headers:"Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)"

Examples:
    attack_types:IN(sqli,xss) AND type:block AND NOT ip:10.0.0.1
    (method:POST OR method:PUT) AND url:/api/*
    time:2026-01-01T00:00:00.000000,2026-03-24T23:59:59.999999
    content:~select AND method:POST
    headers:"Mozilla/5.0 (Windows NT 10.0)" AND type:block
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any


# ──────────────────────────────────────────────
# Token Definitions
# ──────────────────────────────────────────────

VALID_FIELDS = {
    "request_id", "type", "attack_types", "time", "ip", "cdn_ip",
    "country", "city", "fingerprint", "method", "url", "headers", "content",
}

TOKEN_PATTERNS = [
    ("LPAREN",  r"\("),
    ("RPAREN",  r"\)"),
    ("AND",     r"\bAND\b"),
    ("OR",      r"\bOR\b"),
    ("NOT",     r"\bNOT\b"),
    ("IN",      r"\bIN\b"),
    # field:"any character (including parentheses/spaces/semicolons/% etc.)" <- Quoted, preferred match
    # field:IN(a,b,c)                                                         <- IN list
    # field:bare_value (no whitespace or parentheses)                         <- Normal value
    ("FIELD",   r'[a-zA-Z_][a-zA-Z0-9_]*:(?:"[^"]*"|IN\([^)]+\)|[^\s()]+)'),
    ("SKIP",    r"\s+"),
]

_MASTER_RE = re.compile(
    "|".join(f"(?P<{name}>{pat})" for name, pat in TOKEN_PATTERNS)
)


@dataclass
class Token:
    type: str
    value: str
    pos: int


def tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    for m in _MASTER_RE.finditer(query):
        kind = m.lastgroup
        if kind == "SKIP":
            continue
        tokens.append(Token(kind, m.group(), m.start()))

    # Check for unrecognized characters
    covered: set[int] = set()
    for m in _MASTER_RE.finditer(query):
        covered.update(range(m.start(), m.end()))
    for i, ch in enumerate(query):
        if i not in covered and not ch.isspace():
            raise SyntaxError(f"Unrecognized character {ch!r} at position {i}")
    return tokens


# ──────────────────────────────────────────────
# AST Nodes
# ──────────────────────────────────────────────

@dataclass
class FieldNode:
    """Represents a single field condition, e.g., ip:1.2.3.4 or attack_types:IN(sqli,xss)"""
    field: str
    op: str          # "eq" | "fuzzy" | "in" | "range"
    value: Any       # str | list[str] | tuple[str, str]

    def __str__(self):
        if self.op == "in":
            return f"{self.field}:IN({','.join(self.value)})"
        if self.op == "range":
            return f"{self.field}:{self.value[0]},{self.value[1]}"
        if self.op == "fuzzy":
            return f"{self.field}:~{self.value}"
        return f"{self.field}:{self.value}"


@dataclass
class NotNode:
    operand: Any

    def __str__(self):
        return f"NOT {self.operand}"


@dataclass
class BinaryNode:
    op: str   # "AND" | "OR"
    left: Any
    right: Any

    def __str__(self):
        return f"({self.left} {self.op} {self.right})"


# ──────────────────────────────────────────────
# Time Utilities
# ──────────────────────────────────────────────

# Simple time format in query syntax: YYYY.MM.DD.HH.mm (parts can be omitted from the end)
# Valid examples: 2026.3.28 / 2026.3.28.12 / 2026.3.28.12.30
_SIMPLE_TIME_RE = re.compile(
    r"(\d{4})(?:\.(\d{1,2})(?:\.(\d{1,2})(?:\.(\d{1,2})(?:\.(\d{1,2}))?)?)?)?$"
)


def _parse_simple_time(s: str) -> datetime:
    """
    Parses a simple time string into a datetime object.
    Omitted parts are filled with minimum values (Month/Day = 1, Hour/Minute = 0).
    Example:
        "2026"           → 2026-01-01 00:00:00
        "2026.3"         → 2026-03-01 00:00:00
        "2026.3.28"      → 2026-03-28 00:00:00
        "2026.3.28.12"   → 2026-03-28 12:00:00
        "2026.3.28.12.30"→ 2026-03-28 12:30:00
    """
    m = _SIMPLE_TIME_RE.fullmatch(s.strip())
    if not m:
        raise ValueError(
            f"Invalid time format {s!r}, expected YYYY.MM.DD.HH.mm (e.g., 2026.3.28.12.30)"
        )
    year  = int(m.group(1))
    month = int(m.group(2) or 1)
    day   = int(m.group(3) or 1)
    hour  = int(m.group(4) or 0)
    minute= int(m.group(5) or 0)
    return datetime(year, month, day, hour, minute)


def _parse_simple_time_end(s: str) -> datetime:
    """
    Parses a range end time: Omitted parts are filled with maximum values (Month = 12, Day = end of month, Hour = 23, Minute = 59).
    This allows time:2026.3.28,2026.3.28 to cover the entire day.
    """
    import calendar
    m = _SIMPLE_TIME_RE.fullmatch(s.strip())
    if not m:
        raise ValueError(
            f"Invalid time format {s!r}, expected YYYY.MM.DD.HH.mm (e.g., 2026.3.28.12.30)"
        )
    year  = int(m.group(1))
    month = int(m.group(2) or 12)
    day   = int(m.group(3) or calendar.monthrange(year, month)[1])
    hour  = int(m.group(4) or 23)
    minute= int(m.group(5) or 59)
    return datetime(year, month, day, hour, minute)


def _parse_iso(s: str) -> datetime:
    """Parses an ISO 8601 datetime string (the format stored in logs)."""
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Invalid ISO time format: {s!r}")


def _is_simple_time(s: str) -> bool:
    return bool(_SIMPLE_TIME_RE.fullmatch(s.strip()))


# ──────────────────────────────────────────────
# Field Value Parsing
# ──────────────────────────────────────────────

def parse_field_token(token: Token) -> FieldNode:
    """Parses a 'field:value' token into a FieldNode."""
    raw = token.value
    colon = raw.index(":")
    fname = raw[:colon].lower()
    rest  = raw[colon + 1:]

    if fname not in VALID_FIELDS:
        raise ValueError(f"Unknown field {fname!r}, supported: {sorted(VALID_FIELDS)}")

    # ── Quoted values: Strip quotes, keep content as-is (supports spaces, parentheses, etc.) ──
    # Content inside quotes is typically treated as eq (with wildcard) or fuzzy match, not split by IN/range.
    if rest.startswith('"') and rest.endswith('"') and len(rest) >= 2:
        inner = rest[1:-1]          # Remove start/end quotes
        if inner.startswith("~"):
            return FieldNode(fname, "fuzzy", inner[1:])
        return FieldNode(fname, "eq", inner)

    # IN(a,b,c)
    in_m = re.fullmatch(r"IN\(([^)]+)\)", rest, re.IGNORECASE)
    if in_m:
        values = [v.strip() for v in in_m.group(1).split(",") if v.strip()]
        return FieldNode(fname, "in", values)

    # Time range: Two simple times separated by a comma, e.g., 2026.3.1,2026.3.28.23.59
    if fname == "time" and "," in rest:
        parts = rest.split(",", 1)
        start_s, end_s = parts[0].strip(), parts[1].strip()
        # Validate format (raises ValueError on error)
        start_dt = _parse_simple_time(start_s)
        end_dt   = _parse_simple_time_end(end_s)
        # Internally stored as ISO strings for comparison in evaluate()
        return FieldNode(fname, "range", (start_dt.isoformat(), end_dt.isoformat()))

    # Single simple time: Automatically expands to a range (start with min values, end with max values)
    # e.g., time:2026.3.24 is equivalent to time:2026.3.24.0.0,2026.3.24.23.59
    if fname == "time" and _is_simple_time(rest):
        start_dt = _parse_simple_time(rest)
        end_dt   = _parse_simple_time_end(rest)
        return FieldNode(fname, "range", (start_dt.isoformat(), end_dt.isoformat()))

    # Fuzzy match ~value
    if rest.startswith("~"):
        return FieldNode(fname, "fuzzy", rest[1:])

    return FieldNode(fname, "eq", rest)


# ──────────────────────────────────────────────
# Recursive Descent Parser
# ──────────────────────────────────────────────

class Parser:
    """
    Grammar Rules (BNF):
        expr   ::= term  (OR  term)*
        term   ::= unary (AND unary)*
        unary  ::= NOT unary | atom
        atom   ::= LPAREN expr RPAREN | FIELD
    """

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def consume(self, expected: str | None = None) -> Token:
        tok = self.peek()
        if tok is None:
            raise SyntaxError("Unexpected end of expression")
        if expected and tok.type != expected:
            raise SyntaxError(
                f"Expected {expected}, got {tok.type}({tok.value!r}) at position {tok.pos}"
            )
        self.pos += 1
        return tok

    def parse(self) -> Any:
        node = self.expr()
        if self.peek() is not None:
            tok = self.peek()
            raise SyntaxError(f"Extra token: {tok.value!r} at position {tok.pos}")
        return node

    def expr(self) -> Any:
        node = self.term()
        while self.peek() and self.peek().type == "OR":
            self.consume("OR")
            right = self.term()
            node = BinaryNode("OR", node, right)
        return node

    def term(self) -> Any:
        node = self.unary()
        while self.peek() and self.peek().type == "AND":
            self.consume("AND")
            right = self.unary()
            node = BinaryNode("AND", node, right)
        return node

    def unary(self) -> Any:
        if self.peek() and self.peek().type == "NOT":
            self.consume("NOT")
            operand = self.unary()
            return NotNode(operand)
        return self.atom()

    def atom(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise SyntaxError("Expected field or left parenthesis, but expression ended")
        if tok.type == "LPAREN":
            self.consume("LPAREN")
            node = self.expr()
            self.consume("RPAREN")
            return node
        if tok.type == "FIELD":
            self.consume("FIELD")
            return parse_field_token(tok)
        raise SyntaxError(
            f"Expected field or '(', got {tok.type}({tok.value!r}) at position {tok.pos}"
        )


# ──────────────────────────────────────────────
# Public Interface
# ──────────────────────────────────────────────

def parse(query: str) -> Any:
    """Parses a query string and returns the AST root node."""
    tokens = tokenize(query.strip())
    return Parser(tokens).parse()


# ──────────────────────────────────────────────
# Evaluator
# ──────────────────────────────────────────────

# Composite fields: Matched against flattened string (substring match, not fullmatch)
_CONTAINER_FIELDS = {"headers", "attack_types", "cookies"}


def _flatten(val: Any) -> str:
    """Unifies field values into a string, supporting dict / list / base types."""
    if isinstance(val, dict):
        # dict: join all values together for easy search
        # also preserve key:value format for specific searches
        parts = []
        for k, v in val.items():
            parts.append(f"{k}:{v}")
        return " ".join(parts)
    if isinstance(val, list):
        return " ".join(_flatten(v) for v in val)
    return str(val) if val is not None else ""


def _is_container(raw_val: Any) -> bool:
    """Treated as a container if the original value is a dict or list (matches via inclusion rather than equality)."""
    return isinstance(raw_val, (dict, list))


# 'content' is a user-friendly alias, internally mapped to record["data"] (contains form/json/args)
_FIELD_ALIAS = {
    "content": "data",
}


def evaluate(node: Any, record: dict) -> bool:
    """
    Evaluates a request record (dict) against the AST.

    Field Aliases:
      content -> data (automatically flattens data.form / data.json / data.args)

    Match Semantics:
      - Scalar Fields (ip / method / type / url / time ...):
          eq    → fullmatch (supports '*' wildcard)
          fuzzy → substring inclusion
          in    → value exists in list
      - Container Fields (headers dict / attack_types list / data dict ...):
          eq    → substring inclusion after flattening (compiled to search if wildcards present)
          fuzzy → substring inclusion after flattening
          in    → any value in the list exists as a substring of the flattened string
    """
    if isinstance(node, BinaryNode):
        left  = evaluate(node.left,  record)
        right = evaluate(node.right, record)
        return (left and right) if node.op == "AND" else (left or right)

    if isinstance(node, NotNode):
        return not evaluate(node.operand, record)

    if isinstance(node, FieldNode):
        # Field alias resolution
        actual_field = _FIELD_ALIAS.get(node.field, node.field)
        raw_val = record.get(actual_field)
        rec_str = _flatten(raw_val)
        is_container = _is_container(raw_val)

        if node.op == "eq":
            pattern = re.escape(node.value).replace(r"\*", ".*")
            if is_container:
                # Container field: search within flattened string (substring match)
                return bool(re.search(pattern, rec_str, re.IGNORECASE))
            else:
                # Scalar field: fullmatch (exact or wildcard)
                return bool(re.fullmatch(pattern, rec_str, re.IGNORECASE))

        if node.op == "fuzzy":
            # Universal substring inclusion check
            return node.value.lower() in rec_str.lower()

        if node.op == "in":
            if is_container:
                # Container field: any value in list is a substring of flattened string
                return any(v.lower() in rec_str.lower() for v in node.value)
            else:
                # Scalar field: value exists in the list
                return rec_str.lower() in [v.lower() for v in node.value]

        if node.op == "range":
            # time range: ISO datetime comparison
            if node.field == "time":
                try:
                    rec_dt   = _parse_iso(rec_str)
                    start_dt = _parse_iso(node.value[0])
                    end_dt   = _parse_iso(node.value[1])
                    return start_dt <= rec_dt <= end_dt
                except ValueError:
                    return False
            # Other fields: Lexicographical comparison
            return node.value[0] <= rec_str <= node.value[1]

    raise TypeError(f"Unknown node type: {type(node)}")


# ──────────────────────────────────────────────
# Debug/Formatting Utilities
# ──────────────────────────────────────────────

def pretty(node: Any, indent: int = 0) -> str:
    """Formats the AST into a readable tree structure string."""
    pad = "  " * indent
    if isinstance(node, BinaryNode):
        return (
            f"{pad}[{node.op}]\n"
            + pretty(node.left,  indent + 1) + "\n"
            + pretty(node.right, indent + 1)
        )
    if isinstance(node, NotNode):
        return f"{pad}[NOT]\n" + pretty(node.operand, indent + 1)
    if isinstance(node, FieldNode):
        return f"{pad}{node}"
    return f"{pad}{node}"
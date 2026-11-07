"""Every deobfuscation step unwrap knows. Nothing here ever executes the input.

Two kinds of step:

* **rewrites** evaluate a small expression built only from literals and write the result back as a
  literal (`'Inv'+'oke'` -> `'Invoke'`, `[char]73` -> `'I'`). They run to a fixed point inside a layer.
* **decoders** recognise a whole wrapper (`-EncodedCommand`, Base64 + gzip, `eval(...)`) and return
  the script hidden inside it, which becomes the next layer.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import functools
import re
import zlib
from collections import Counter
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote_to_bytes

from .literals import (JS_STR, PS_ANY_STR, PS_SINGLE, PS_STR, VBS_STR, js_render, js_value, ps_render, ps_value,
                       vbs_render, vbs_value)

MAX_INFLATED = 50 * 1024 * 1024        # decompression-bomb guard
NUM = r"(?:0x[0-9a-fA-F]+|\d+)"
NUMS = NUM + r"(?:\s*,\s*" + NUM + r")*"


@dataclass(frozen=True)
class Rewrite:
    name: str
    langs: tuple
    fn: Callable[[str], tuple[str, int]]


@dataclass
class Decoded:
    technique: str
    detail: str
    text: str | None = None          # the next layer, when the payload is text
    data: bytes | None = None        # a binary payload (an artifact), when it is not
    language: str | None = None      # known when the wrapper runs it (iex: PowerShell, eval: JavaScript)


# ── helpers ───────────────────────────────────────────────────────────────────


def _int(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _chars(nums: str) -> str | None:
    try:
        return "".join(chr(_int(n)) for n in re.findall(NUM, nums))
    except (ValueError, OverflowError):
        return None


def b64decode(s: str) -> bytes | None:
    s = re.sub(r"\s+", "", s)
    if len(s) < 8 or re.search(r"[^A-Za-z0-9+/=_-]", s):
        return None
    s = s.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text)


def as_text(data: bytes | None) -> str | None:
    """Bytes that hold a script -> text. Tries UTF-16LE (PowerShell's favourite) first when it looks like it."""
    if not data:
        return None
    if data[:2] == b"\xff\xfe":
        candidates = ["utf-16-le"]
        data = data[2:]
    elif data[:3] == b"\xef\xbb\xbf":
        candidates = ["utf-8"]
        data = data[3:]
    else:
        candidates = (["utf-16-le"] if len(data) >= 4 and data[1::2].count(0) > len(data) // 4 else []) + \
            ["utf-8", "latin-1"]
    for codec in candidates:
        try:
            text = data.decode(codec)
        except UnicodeDecodeError:
            continue
        if text and printable_ratio(text) > 0.95:
            return text
    return None


def inflate(data: bytes, gzip: bool) -> bytes | None:
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip else -zlib.MAX_WBITS)
        out = d.decompress(data, MAX_INFLATED)
        return None if d.unconsumed_tail else out
    except zlib.error:
        return None


def sniff(data: bytes) -> str:
    for magic, kind in ((b"MZ", "PE executable"), (b"\x7fELF", "ELF executable"), (b"PK\x03\x04", "ZIP archive"),
                        (b"%PDF", "PDF document"), (b"\x1f\x8b", "gzip data"), (b"\xd0\xcf\x11\xe0", "OLE2 (Office)")):
        if data.startswith(magic):
            return kind
    return "binary data"



# ── literal awareness ─────────────────────────────────────────────────────────
# Rewrites and decoders must never act on *part* of a string literal: a nested layer's code often sits
# inside a literal of the outer layer (say, a [char[]] expression quoted inside a concatenation), and
# folding it there would break the outer quoting. Matches may sit outside literals or cover whole
# literals, nothing else.

_PS_LIT = re.compile(PS_ANY_STR)
_JS_LIT = re.compile(JS_STR)
_VBS_LIT = re.compile(VBS_STR)


@functools.lru_cache(maxsize=8)            # every rule of a pass asks about the same text
def _spans(text: str, lit: re.Pattern | None) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in lit.finditer(text)] if lit else []


def _starts(spans: list[tuple[int, int]]) -> list[int]:
    return [s for s, _ in spans]


def _containing(spans: list[tuple[int, int]], starts: list[int], pos: int) -> int:
    """Index of the literal that holds pos strictly inside it, or -1."""
    i = bisect.bisect_right(starts, pos) - 1
    return i if i >= 0 and spans[i][0] < pos < spans[i][1] else -1


def _inside(spans: list[tuple[int, int]], starts: list[int], pos: int) -> bool:
    return _containing(spans, starts, pos) >= 0


def _safe(rx: re.Pattern, repl, text: str, lit: re.Pattern | None) -> tuple[str, int]:
    """rx.subn, except matches that start or end strictly inside a string literal are skipped."""
    spans = _spans(text, lit)
    starts = _starts(spans)
    out, pos, at, n = [], 0, 0, 0
    while at <= len(text):
        m = rx.search(text, at)
        if not m:
            break
        holder = _containing(spans, starts, m.start())
        if holder >= 0:
            at = spans[holder][1]                        # nothing may start in there: skip the whole literal
            continue
        if m.end() == m.start() or _inside(spans, starts, m.end()):
            at = m.start() + 1
            continue
        new = repl(m)
        out += [text[pos:m.start()], new]
        n += new != m.group(0)
        pos = at = m.end()
    out.append(text[pos:])
    return "".join(out), n


def _search(rx: re.Pattern, text: str, lit: re.Pattern | None = None) -> re.Match | None:
    """First match that does not start inside a string literal."""
    lit = lit or _PS_LIT
    spans = _spans(text, lit)
    starts = _starts(spans)
    at = 0
    while at <= len(text):
        m = rx.search(text, at)
        if not m:
            return None
        holder = _containing(spans, starts, m.start())
        if holder < 0:
            return m
        at = spans[holder][1]
    return None


_PS_SINGLE = re.compile(PS_SINGLE)


def _outside_single_quotes(text: str, fn) -> tuple[str, int]:
    """Apply a substitution only outside PowerShell '...' literals (backticks are literal in there)."""
    out, total, last = [], 0, 0
    for m in _PS_SINGLE.finditer(text):
        part, n = fn(text[last:m.start()])
        out += [part, m.group(0)]
        total += n
        last = m.end()
    part, n = fn(text[last:])
    out.append(part)
    return "".join(out), total + n


# ── PowerShell rewrites ───────────────────────────────────────────────────────

_TICK = re.compile(r"`([A-Za-z])(?=(.?))", re.S)


def ps_ticks(t):
    """I`E`X -> IEX. Ticks before escape letters (`n, `t ...) mean something, even in bare words, so they stay.
    `e is plain 'e' in Windows PowerShell 5.1 (ESC only in PowerShell 7), and `u only escapes as `u{...}."""
    def sub(part):
        n = 0

        def r(m):
            nonlocal n
            ch = m.group(1).lower()
            if ch in "abfnrtv" or (ch == "u" and m.group(2) == "{"):
                return m.group(0)
            n += 1
            return m.group(1)
        return _TICK.sub(r, part), n
    return _outside_single_quotes(t, sub)


_ASSIGN = re.compile(r"\$(\w+)\s*=\s*(" + PS_STR + r")\s*(;|\r?\n|$)", re.I)


_ASSIGN_TARGET = re.compile(r"\$(\w+)\s*[+\-*/]?=(?!=)")
_VAR_USE = re.compile(r"\$(\w+)\b(?!\s*[+\-*/]?=(?!=))")
MAX_GROWTH = 1 << 20          # propagating one variable may not grow a layer by more than 1 MB


def ps_vars(t):
    """Constant propagation: a variable assigned one literal exactly once is replaced by that literal.

    One pass for all variables. Uses inside literals ("...$a..." strings, nested code) are left alone; the
    assignment is dropped only when nothing else refers to the variable (${a}, $script:a, such uses).
    """
    spans = _spans(t, _PS_LIT)
    starts = _starts(spans)
    assigned = Counter(m.group(1).lower() for m in _ASSIGN_TARGET.finditer(t))      # anywhere, nested code too
    consts = {}
    for m in _ASSIGN.finditer(t):
        name = m.group(1).lower()
        if assigned[name] == 1 and not _inside(spans, starts, m.start()):
            consts[name] = m
    if not consts:
        return t, 0
    uses = [u for u in _VAR_USE.finditer(t) if u.group(1).lower() in consts and not _inside(spans, starts, u.start())]
    count = Counter(u.group(1).lower() for u in uses)
    live = {k: m for k, m in consts.items()
            if count[k] and (count[k] == 1 or len(m.group(2)) * count[k] <= MAX_GROWTH)}
    if not live:
        return t, 0
    edits = [(u.start(), u.end(), live[u.group(1).lower()].group(2)) for u in uses if u.group(1).lower() in live]
    for name, m in live.items():
        refs = len(re.findall(r"(?:\$\{?|:)" + re.escape(name) + r"\b", t, re.I))
        if refs == 1 + count[name]:                      # the assignment and the uses we replace: now dead
            edits.append((m.start(), m.end(), ""))
    out, pos = [], 0
    for start, end, new in sorted(edits):
        out += [t[pos:start], new]
        pos = end
    out.append(t[pos:])
    return "".join(out), len(edits)


_FORMAT = re.compile(r"\(\s*(" + PS_STR + r")\s*-f\s*(" + PS_STR + r"(?:\s*,\s*" + PS_STR + r")*)\s*\)", re.I)


def ps_format(t):
    """("{2}{0}{1}" -f 'b','c','a') -> 'abc'."""
    def r(m):
        fmt = ps_value(m.group(1))
        if re.search(r"\{\d+[,:][^}]*\}", fmt):
            return m.group(0)                            # alignment / format specifiers: leave alone
        args = [ps_value(a) for a in re.findall(PS_STR, m.group(2))]
        if any(int(i) >= len(args) for i in re.findall(r"\{(\d+)\}", fmt)):
            return m.group(0)
        out = re.sub(r"\{(\d+)\}", lambda s: args[int(s.group(1))], fmt)
        return ps_render(out.replace("{{", "{").replace("}}", "}"))
    return _safe(_FORMAT, r, t, _PS_LIT)


_PS_CONCAT = re.compile(PS_STR + r"(?:\s*\+\s*" + PS_STR + r")+")


def ps_concat(t):
    return _safe(_PS_CONCAT, lambda m: ps_render("".join(ps_value(x) for x in re.findall(PS_STR, m.group(0)))), t,
                 _PS_LIT)


_PS_PARENS = re.compile(r"(?<![\w\]\)$`'\"])\(\s*(" + PS_STR + r")\s*\)")


def ps_parens(t):
    return _safe(_PS_PARENS, lambda m: m.group(1), t, _PS_LIT)


_PS_CHAR = re.compile(r"\[char\]\s*(" + NUM + r")", re.I)


def ps_char(t):
    def r(m):
        s = _chars(m.group(1))
        return ps_render(s) if s is not None else m.group(0)
    return _safe(_PS_CHAR, r, t, _PS_LIT)


_CHAR_ARRAYS = [
    (re.compile(r"\[char\[\]\]\s*@?\(\s*(" + NUMS + r")\s*\)\s*-join\s*(" + PS_STR + r")", re.I), 1, 2),
    (re.compile(r"-join\s*\[char\[\]\]\s*@?\(\s*(" + NUMS + r")\s*\)", re.I), 1, None),
    (re.compile(r"\(\s*(" + NUMS + r")\s*\|\s*(?:%|foreach(?:-object)?)\s*\{\s*\[char\]\s*\$_\s*\}\s*\)\s*-join\s*("
                + PS_STR + r")", re.I), 1, 2),
    (re.compile(r"\[string\]::join\(\s*(" + PS_STR + r")\s*,\s*\[char\[\]\]\s*@?\(\s*(" + NUMS + r")\s*\)\s*\)", re.I),
     2, 1),
]


def ps_char_arrays(t):
    total = 0
    for rx, nums_group, sep_group in _CHAR_ARRAYS:
        def r(m):
            chars = _chars(m.group(nums_group))
            if chars is None:
                return m.group(0)
            sep = ps_value(m.group(sep_group)) if sep_group else ""
            return ps_render(sep.join(chars))
        t, n = _safe(rx, r, t, _PS_LIT)
        total += n
    return t, total


_JOIN_LIST = [
    (re.compile(r"\(\s*(" + PS_STR + r"(?:\s*,\s*" + PS_STR + r")+)\s*\)\s*-join\s*(" + PS_STR + r")", re.I), True),
    (re.compile(r"-join\s*\(\s*(" + PS_STR + r"(?:\s*,\s*" + PS_STR + r")+)\s*\)", re.I), False),
]


def ps_join(t):
    total = 0
    for rx, has_sep in _JOIN_LIST:
        def r(m):
            items = [ps_value(x) for x in re.findall(PS_STR, m.group(1))]
            return ps_render((ps_value(m.group(2)) if has_sep else "").join(items))
        t, n = _safe(rx, r, t, _PS_LIT)
        total += n
    return t, total


# the lower bound: a number, or the length of a variable / literal (after constant propagation it is the literal)
_BOUND = r"(\d+|\(\s*(?:\$\w+|" + PS_STR + r")\s*\.length\s*\)|\$\w+\.length)"
_REVERSE = [
    re.compile(r"(" + PS_STR + r")\s*\[\s*-1\s*\.\.\s*-\s*" + _BOUND + r"\s*\]\s*-join\s*(?:''|\"\")", re.I),
    re.compile(r"-join\s*\(\s*(" + PS_STR + r")\s*\[\s*-1\s*\.\.\s*-\s*" + _BOUND + r"\s*\]\s*\)", re.I),
]


def ps_reverse(t):
    """'olleh'[-1..-5] -join ''  ->  'hello'."""
    total = 0
    for rx in _REVERSE:
        def r(m):
            value = ps_value(m.group(1))
            bound = m.group(2)
            if bound.isdigit():
                return ps_render(value[::-1][:int(bound)])
            lit = re.search(PS_STR, bound)
            if lit and ps_value(lit.group(0)) != value:
                return m.group(0)                        # the length of some other string: not a plain reverse
            return ps_render(value[::-1])                # -($x.Length) and friends: the whole string
        t, n = _safe(rx, r, t, _PS_LIT)
        total += n
    return t, total


_REPLACE_OP = re.compile(r"(" + PS_STR + r")\s*-([ci]?)replace\s*(" + PS_STR + r")(?:\s*,\s*(" + PS_STR + r"))?", re.I)
_REPLACE_METHOD = re.compile(r"(" + PS_STR + r")\s*\.replace\(\s*(" + PS_STR + r")\s*,\s*(" + PS_STR + r")\s*\)", re.I)


def ps_replace(t):
    def op(m):
        src, pattern = ps_value(m.group(1)), ps_value(m.group(3))
        repl = ps_value(m.group(4)) if m.group(4) else ""
        repl = re.sub(r"\$(\d+)", r"\\\1", repl.replace("\\", "\\\\"))
        try:
            out = re.sub(pattern, repl, src, flags=0 if m.group(2).lower() == "c" else re.I)
        except (re.error, IndexError):
            return m.group(0)
        return ps_render(out)
    t, n1 = _safe(_REPLACE_OP, op, t, _PS_LIT)
    t, n2 = _safe(_REPLACE_METHOD, lambda m: ps_render(ps_value(m.group(1)).replace(ps_value(m.group(2)),
                                                                                  ps_value(m.group(3)))), t, _PS_LIT)
    return t, n1 + n2


_INVOKE_ALIAS = re.compile(r"(?<![\w$)\]])[&.]\s*(" + PS_STR + r")(?=(\S?))")


def ps_invoke_alias(t):
    """&('IEX') / .("New-Object") -> the bare command name, so the wrapper can be recognised."""
    def r(m):
        name = ps_value(m.group(1)).strip()
        if not re.fullmatch(r"[A-Za-z][\w-]*", name):
            return m.group(0)                            # a path or a script block: invoking it is not a rename
        return name + (" " if m.group(2) and m.group(2) not in "(;|)" else "")
    return _safe(_INVOKE_ALIAS, r, t, _PS_LIT)


# Invoke-Obfuscation spells IEX with characters picked out of variables that hold the same value on every
# Windows machine: $ShellId[1]+$ShellId[13]+'x', $env:ComSpec[4,15,25]-Join'', (gv '*mdr*').Name[3,11,2] ...
_WELL_KNOWN = {
    "pshome": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    "shellid": "Microsoft.PowerShell",
    "env:comspec": "C:\\WINDOWS\\system32\\cmd.exe",
    "env:public": "C:\\Users\\Public",
    "verbosepreference": "SilentlyContinue",
    "mdr": "MaximumDriveCount",
}
_AUTOMATIC = re.compile(
    r"\$(pshome|shellid|env:comspec|env:public)\b(?=\s*\[)"
    r"|\$(verbosepreference)\.tostring\(\s*\)(?=\s*\[)"
    r"|\(\s*\[string\]\s*\$(verbosepreference)\s*\)(?=\s*\[)"
    r"|\(\s*(?:get-variable|gv|variable)\s+(['\"])\*(mdr)\*\4\s*\)\.name(?=\s*\[)", re.I)


def ps_automatic(t):
    """$ShellId[1] -> 'Microsoft.PowerShell'[1], only where the variable is indexed (its value is known)."""
    def r(m):
        name = next(g for g in (m.group(1), m.group(2), m.group(3), m.group(5)) if g)
        return ps_render(_WELL_KNOWN[name.lower()])
    return _safe(_AUTOMATIC, r, t, _PS_LIT)


_PS_INDEX = re.compile(r"(?<![\w.])(" + PS_STR + r")\s*\[\s*(-?" + NUM + r"(?:\s*,\s*-?" + NUM + r")*)\s*\]")
_LIST_PLUS = re.compile(r"\(\s*(" + PS_STR + r"(?:\s*,\s*" + PS_STR + r")+)\s*\)\s*\+\s*(" + PS_STR + r")(?!\s*[\[.])")


def ps_index(t):
    """'Microsoft.PowerShell'[1] -> 'i'; several indexes give a list: [1,3] -> ('i','r')."""
    def r(m):
        value, out = ps_value(m.group(1)), []
        for raw in re.findall(r"-?" + NUM, m.group(2)):
            i = -_int(raw[1:]) if raw.startswith("-") else _int(raw)
            if not -len(value) <= i < len(value):
                return m.group(0)
            out.append(value[i])
        return ps_render(out[0]) if len(out) == 1 else "(" + ",".join(ps_render(c) for c in out) + ")"
    t, n1 = _safe(_PS_INDEX, r, t, _PS_LIT)
    t, n2 = _safe(_LIST_PLUS, lambda m: f"({m.group(1)},{m.group(2)})", t, _PS_LIT)   # ('i','e')+'x' -> one list
    return t, n1 + n2


# ── JavaScript rewrites ───────────────────────────────────────────────────────

_FROMCHARCODE = re.compile(r"String\.fromCharCode\(\s*(" + NUMS + r")\s*\)")


def js_fromcharcode(t):
    def r(m):
        s = _chars(m.group(1))
        return js_render(s) if s is not None else m.group(0)
    return _safe(_FROMCHARCODE, r, t, _JS_LIT)


_ATOB = re.compile(r"\batob\(\s*(" + JS_STR + r")\s*\)")


def js_atob(t):
    def r(m):
        data = b64decode(js_value(m.group(1)))
        text = data.decode("latin-1") if data is not None else None
        return js_render(text) if text and printable_ratio(text) > 0.95 else m.group(0)
    return _safe(_ATOB, r, t, _JS_LIT)


def _js_unescape(s: str) -> str:
    s = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return unquote_to_bytes(s).decode("latin-1") if "%" in s else s


_UNESCAPE = re.compile(r"\b(unescape|decodeURIComponent|decodeURI)\(\s*(" + JS_STR + r")\s*\)")


def js_unescape(t):
    def r(m):
        value = js_value(m.group(2))
        if m.group(1) == "unescape":
            return js_render(_js_unescape(value))
        try:
            return js_render(unquote_to_bytes(value).decode("utf-8"))
        except UnicodeDecodeError:
            return m.group(0)
    return _safe(_UNESCAPE, r, t, _JS_LIT)


_JS_CONCAT = re.compile(JS_STR + r"(?:\s*\+\s*" + JS_STR + r")+")


def js_concat(t):
    return _safe(_JS_CONCAT, lambda m: js_render("".join(js_value(x) for x in re.findall(JS_STR, m.group(0)))), t,
                 _JS_LIT)


_JS_ESCAPED = re.compile(r"(?:'(?:[^'\\\n]|\\.)*\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F{])(?:[^'\\\n]|\\.)*'|"
                         r"\"(?:[^\"\\\n]|\\.)*\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F{])(?:[^\"\\\n]|\\.)*\")")


def js_escapes(t):
    """'\\x49\\x45\\x58' -> 'IEX': literals spelled with hex/unicode escapes."""
    def r(m):
        value = js_value(m.group(0))
        return js_render(value) if printable_ratio(value) > 0.95 else m.group(0)
    return _safe(_JS_ESCAPED, r, t, _JS_LIT)


_JS_REVERSE = re.compile(r"(" + JS_STR + r")\.split\(\s*(?:''|\"\")\s*\)\.reverse\(\)\.join\(\s*(?:''|\"\")\s*\)")
_JS_REPLACE_STR = re.compile(r"(" + JS_STR + r")\.(replace|replaceAll)\(\s*(" + JS_STR + r")\s*,\s*(" + JS_STR + r")\s*\)")
_JS_REPLACE_RE = re.compile(r"(" + JS_STR + r")\.replace\(\s*/((?:[^/\\\n]|\\.)+)/([a-z]*)\s*,\s*(" + JS_STR + r")\s*\)")


def js_strings(t):
    t, n1 = _safe(_JS_REVERSE, lambda m: js_render(js_value(m.group(1))[::-1]), t, _JS_LIT)

    def plain(m):
        src, old, new = js_value(m.group(1)), js_value(m.group(3)), js_value(m.group(4))
        if "$" in new:
            return m.group(0)
        return js_render(src.replace(old, new) if m.group(2) == "replaceAll" else src.replace(old, new, 1))
    t, n2 = _safe(_JS_REPLACE_STR, plain, t, _JS_LIT)

    def regex(m):
        new = js_value(m.group(4))
        if "$" in new or set(m.group(3)) - set("gimsuy"):
            return m.group(0)
        try:
            rx = re.compile(m.group(2), re.I if "i" in m.group(3) else 0)
        except re.error:
            return m.group(0)
        return js_render(rx.sub(new.replace("\\", "\\\\"), js_value(m.group(1)), count=0 if "g" in m.group(3) else 1))
    t, n3 = _safe(_JS_REPLACE_RE, regex, t, _JS_LIT)
    return t, n1 + n2 + n3


_JS_PARENS = re.compile(r"(?<![\w\]\)$'\"])\(\s*(" + JS_STR + r")\s*\)")


def js_parens(t):
    return _safe(_JS_PARENS, lambda m: m.group(1), t, _JS_LIT)


# ── VBScript rewrites ─────────────────────────────────────────────────────────

_VBS_CHR = re.compile(r"\bChrW?\(\s*(&H[0-9a-fA-F]+|\d+)\s*\)", re.I)


def vbs_chr(t):
    def r(m):
        raw = m.group(1)
        try:
            return vbs_render(chr(int(raw[2:], 16) if raw.lower().startswith("&h") else int(raw)))
        except (ValueError, OverflowError):
            return m.group(0)
    t, n1 = _safe(_VBS_CHR, r, t, _VBS_LIT)
    t, n2 = _safe(_VBS_CONST, lambda m: vbs_render(_VBS_CONSTANTS[m.group(1).lower()]), t, _VBS_LIT)
    return t, n1 + n2


_VBS_CONSTANTS = {"crlf": "\r\n", "newline": "\r\n", "lf": "\n", "cr": "\r", "tab": "\t", "nullchar": "\0"}
_VBS_CONST = re.compile(r"\bvb(crlf|newline|lf|cr|tab|nullchar)\b", re.I)


_VBS_CONCAT = re.compile(VBS_STR + r"(?:\s*[&+]\s*" + VBS_STR + r")+")
_VBS_REVERSE = re.compile(r"\bStrReverse\(\s*(" + VBS_STR + r")\s*\)", re.I)
_VBS_REPLACE = re.compile(r"\bReplace\(\s*(" + VBS_STR + r")\s*,\s*(" + VBS_STR + r")\s*,\s*(" + VBS_STR + r")\s*\)", re.I)
_VBS_PARENS = re.compile(r"(?<![\w\)])\(\s*(" + VBS_STR + r")\s*\)")


def vbs_strings(t):
    t, n1 = _safe(_VBS_CONCAT, lambda m: vbs_render("".join(vbs_value(x) for x in re.findall(VBS_STR, m.group(0)))),
                   t, _VBS_LIT)
    t, n2 = _safe(_VBS_REVERSE, lambda m: vbs_render(vbs_value(m.group(1))[::-1]), t, _VBS_LIT)
    t, n3 = _safe(_VBS_REPLACE, lambda m: vbs_render(vbs_value(m.group(1)).replace(vbs_value(m.group(2)),
                                                                                   vbs_value(m.group(3)))),
                   t, _VBS_LIT)
    t, n4 = _safe(_VBS_PARENS, lambda m: m.group(1), t, _VBS_LIT)
    return t, n1 + n2 + n3 + n4


# ── Batch rewrites ────────────────────────────────────────────────────────────

_CARET = re.compile(r"\^(?=[\w\-/.:\\])")
_SET = re.compile(r"(?i)\bset\s+\"?([A-Za-z_][\w]*)=([^\"\r\n&|]*)\"?")


def bat_carets(t):
    return _CARET.subn("", t)


def _substring(value: str, spec: str | None) -> str | None:
    if not spec:
        return value
    m = re.fullmatch(r"~\s*(-?\d+)\s*(?:,\s*(-?\d+))?", spec)
    if not m:
        return None
    start, length = int(m.group(1)), m.group(2)
    if start < 0:
        start = max(len(value) + start, 0)
    rest = value[start:]
    if length is None:
        return rest
    length = int(length)
    return rest[:length] if length >= 0 else rest[:length or None]


def bat_vars(t):
    """set a=pow&& set b=ershell&& call %a%%b%  ->  call powershell (also %v:~start,len% slices)."""
    values: dict[str, str] = {}
    counts: dict[str, int] = {}
    for m in _SET.finditer(t):
        key = m.group(1).lower()
        counts[key] = counts.get(key, 0) + 1
        values[key] = m.group(2)
    single = {k: v for k, v in values.items() if counts[k] == 1}
    if not single:
        return t, 0

    total = 0

    def r(m):
        nonlocal total
        name = m.group(1).lower()
        out = _substring(single[name], m.group(2)) if name in single else None
        if out is None:
            return m.group(0)
        total += 1
        return out
    # leave the `set` statements themselves alone, expand only the uses
    use = re.compile(r"[%!]([A-Za-z_]\w*)(?::(~[^%!]*))?[%!]")
    pieces, last = [], 0
    for s in _SET.finditer(t):
        pieces += [use.sub(r, t[last:s.start()]), s.group(0)]
        last = s.end()
    pieces.append(use.sub(r, t[last:]))
    return "".join(pieces), total


REWRITES = [
    Rewrite("backtick", ("powershell",), ps_ticks),
    Rewrite("char", ("powershell",), ps_char),
    Rewrite("char-array", ("powershell",), ps_char_arrays),
    Rewrite("automatic-variable", ("powershell",), ps_automatic),
    Rewrite("index", ("powershell",), ps_index),
    Rewrite("constant-variable", ("powershell",), ps_vars),
    Rewrite("format-operator", ("powershell",), ps_format),
    Rewrite("concatenation", ("powershell",), ps_concat),
    Rewrite("join", ("powershell",), ps_join),
    Rewrite("reverse", ("powershell",), ps_reverse),
    Rewrite("replace", ("powershell",), ps_replace),
    Rewrite("parentheses", ("powershell",), ps_parens),
    Rewrite("invoke-alias", ("powershell",), ps_invoke_alias),
    Rewrite("fromCharCode", ("javascript",), js_fromcharcode),
    Rewrite("atob", ("javascript",), js_atob),
    Rewrite("unescape", ("javascript",), js_unescape),
    Rewrite("escape-sequences", ("javascript",), js_escapes),
    Rewrite("concatenation", ("javascript",), js_concat),
    Rewrite("string-methods", ("javascript",), js_strings),
    Rewrite("parentheses", ("javascript",), js_parens),
    Rewrite("Chr", ("vbscript",), vbs_chr),
    Rewrite("string-functions", ("vbscript",), vbs_strings),
    Rewrite("caret-escapes", ("batch",), bat_carets),
    Rewrite("variable-expansion", ("batch",), bat_vars),
]


# ── decoders ──────────────────────────────────────────────────────────────────

_ENCODED_CMD = re.compile(
    r"(?i)(?:^|[\s\"'])[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|"
    r"encodedcomma|encodedcomman|encodedcommand)\s+['\"]?([A-Za-z0-9+/]{8,}={0,2})")


def dec_encoded_command(t):
    if not re.search(r"(?i)\b(powershell|pwsh)\b", t):
        return None
    m = _search(_ENCODED_CMD, t)
    data = b64decode(m.group(1)) if m else None
    if not data:
        return None
    try:
        text = data.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if printable_ratio(text) < 0.95:
        return None
    return Decoded("encoded-command", f"-EncodedCommand: Base64 of UTF-16LE ({len(m.group(1)):,} chars)", text,
                   language="powershell")


_GETSTRING = re.compile(r"(?i)\[(?:system\.)?text\.encoding\]::(utf8|unicode|ascii|utf32|default|bigendianunicode|utf7)"
                        r"\.getstring\(\s*\[(?:system\.)?convert\]::frombase64string\(\s*(" + PS_STR + r")\s*\)\s*\)")
_CODECS = {"utf8": "utf-8", "unicode": "utf-16-le", "ascii": "ascii", "utf32": "utf-32-le", "default": "utf-8",
           "bigendianunicode": "utf-16-be", "utf7": "utf-7"}


def dec_getstring(t):
    m = _search(_GETSTRING, t)
    if not m:
        return None
    data = b64decode(ps_value(m.group(2)))
    if data is None:
        return None
    try:
        text = data.decode(_CODECS[m.group(1).lower()])
    except (UnicodeDecodeError, LookupError):
        return None
    if printable_ratio(text) < 0.95:
        return None
    return Decoded("base64-getstring", f"[Convert]::FromBase64String -> {m.group(1)}.GetString", text)


_FROM_B64 = re.compile(r"(?i)\[(?:system\.)?convert\]::frombase64string\(\s*(" + PS_STR + r")\s*\)")


def dec_compressed(t):
    kind = _search(re.compile(r"(?i)\b(gzipstream|deflatestream)\b"), t)
    m = _search(_FROM_B64, t)
    if not kind or not m:
        return None
    data = b64decode(ps_value(m.group(1)))
    if data is None:
        return None
    gzip = data[:2] == b"\x1f\x8b" or kind.group(1).lower() == "gzipstream"
    raw = inflate(data, gzip) or inflate(data, not gzip)
    text = as_text(raw)
    if text is None:
        return Decoded(f"{'gzip' if gzip else 'deflate'}-base64", "Base64 -> decompressed binary payload",
                       data=raw) if raw else None
    return Decoded(f"{'gzip' if gzip else 'deflate'}-base64",
                   f"Base64 -> {'gzip' if gzip else 'raw deflate'} ({len(data):,} -> {len(raw):,} bytes)", text)


_BXOR = re.compile(r"(?i)-bxor\s*(" + NUM + r")")


def dec_xor(t):
    k, m = _search(_BXOR, t), _search(_FROM_B64, t)
    if not k or not m:
        return None
    data = b64decode(ps_value(m.group(1)))
    key = _int(k.group(1))
    if data is None or not 0 <= key <= 255:
        return None
    text = as_text(bytes(b ^ key for b in data))
    if text is None:
        return None
    return Decoded("xor", f"Base64 -> XOR with 0x{key:02x}", text)


_IEX_LITERAL = [
    (re.compile(r"(?is)^\s*(?:invoke-expression|iex)(?:\s+-command)?\s*\(?\s*(" + PS_STR + r")\s*\)?\s*;?\s*$"),
     "invoke-expression", "Invoke-Expression of a literal"),
    (re.compile(r"(?is)^\s*\(?\s*(" + PS_STR + r")\s*\)?\s*\|\s*(?:invoke-expression|iex)\s*;?\s*$"),
     "invoke-expression", "literal piped into Invoke-Expression"),
    (re.compile(r"(?is)^\s*(?:[&.]|icm|invoke-command(?:\s+-scriptblock)?)?\s*\(?\s*\[scriptblock\]::create\(\s*("
                + PS_STR + r")\s*\)\s*\)?(?:\.invoke\(\s*\))?\s*;?\s*$"),
     "scriptblock", "[ScriptBlock]::Create of a literal"),
    (re.compile(r"(?is)^\s*\$executioncontext\.invokecommand\.(?:invokescript|newscriptblock)\(\s*(" + PS_STR
                + r")\s*\)(?:\.invoke\(\s*\))?\s*;?\s*$"),
     "scriptblock", "$ExecutionContext.InvokeCommand of a literal"),
    (re.compile(r"(?is)^\s*(?:powershell|pwsh)(?:\.exe)?\b.*?\s[-/]c(?:o|om|omm|omma|omman|ommand)?\s+(" + PS_STR
                + r")\s*$"),
     "powershell-command", "powershell -Command of a literal"),
]
# the same wrapper as one statement among others (the rest stays visible in the layer before)
_IEX_STATEMENT = re.compile(r"(?im)(?:^|;)\s*(?:invoke-expression|iex)(?:\s+-command)?\s*\(?\s*(" + PS_STR
                            + r")\s*\)?\s*(?=;|$)")


def dec_iex_literal(t):
    for rx, name, detail in _IEX_LITERAL:
        m = rx.match(t)
        if m:
            return Decoded(name, detail, ps_value(m.group(1)), language="powershell")
    m = _search(_IEX_STATEMENT, t)
    if m:
        return Decoded("invoke-expression", "Invoke-Expression of a literal (one statement of several)",
                       ps_value(m.group(1)), language="powershell")
    return None


_PACKER = re.compile(r"(?s)eval\(function\(p,a,c,k,e,[dr]\)\{.*?\}\(\s*(" + JS_STR + r")\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*("
                     + JS_STR + r")\.split\(\s*['\"]\|['\"]\s*\)")


def _base_n(word: str, radix: int) -> int | None:
    n = 0
    for ch in word:
        if ch.isdigit() or "a" <= ch <= "z":
            v = int(ch, 36)
        elif "A" <= ch <= "Z":
            v = ord(ch) - 29
        else:
            return None
        if v >= radix:
            return None
        n = n * radix + v
    return n


def dec_packer(t):
    """Dean Edwards' p,a,c,k,e,d packer, unpacked statically."""
    m = _search(_PACKER, t, _JS_LIT)
    if not m:
        return None
    payload, radix, words = js_value(m.group(1)), int(m.group(2)), js_value(m.group(4)).split("|")

    def lookup(w):
        i = _base_n(w.group(0), radix)
        return words[i] if i is not None and i < len(words) and words[i] else w.group(0)
    return Decoded("packer", f"p,a,c,k,e,d packer (radix {radix}, {len(words)} words)",
                   re.sub(r"\b\w+\b", lookup, payload), language="javascript")


_JS_EVAL = [
    (re.compile(r"(?s)\beval\s*\(\s*(" + JS_STR + r")\s*\)"), "eval", "eval() of a literal"),
    (re.compile(r"(?s)\b(?:new\s+)?Function\s*\(\s*(" + JS_STR + r")\s*\)\s*\(\s*\)"), "function-constructor",
     "Function() constructor of a literal"),
    (re.compile(r"(?s)\bdocument\.write(?:ln)?\s*\(\s*(" + JS_STR + r")\s*\)"), "document-write",
     "document.write() of a literal"),
]


def dec_js_eval(t):
    for rx, name, detail in _JS_EVAL:
        m = _search(rx, t, _JS_LIT)
        if m:
            return Decoded(name, detail, js_value(m.group(1)), language="javascript")
    return None


_VBS_EXECUTE = re.compile(r"(?is)\b(?:Execute|ExecuteGlobal|Eval)\s*\(?\s*(" + VBS_STR + r")\s*\)?")


def dec_vbs_execute(t):
    m = _search(_VBS_EXECUTE, t, _VBS_LIT)
    return Decoded("vbs-execute", "Execute() of a literal", vbs_value(m.group(1)), language="vbscript") if m else None


_ANY_LITERAL = re.compile(PS_STR + "|" + JS_STR)
_HEX_BLOB = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){24,})(?![0-9a-fA-F])")


def dec_blob(t):
    """Last resort: a long Base64 or hex literal that decodes to text (or to a recognisable binary)."""
    for m in _ANY_LITERAL.finditer(t):
        body = m.group(0)[1:-1]
        if len(body) < 40:
            continue
        data = b64decode(body)
        if data is None:
            continue
        text = as_text(data)
        if text and re.search(r"[A-Za-z]{3}", text):
            return Decoded("base64-literal", f"Base64 literal ({len(body):,} chars)", text)
        if sniff(data) != "binary data":
            return Decoded("base64-literal", f"Base64 literal holds a {sniff(data)}", data=data)
    m = _HEX_BLOB.search(t)
    if m:
        data = bytes.fromhex(m.group(1))
        text = as_text(data)
        if text and re.search(r"[A-Za-z]{3}", text):
            return Decoded("hex-literal", f"hex string ({len(m.group(1)):,} chars)", text)
        if sniff(data) != "binary data":
            return Decoded("hex-literal", f"hex string holds a {sniff(data)}", data=data)
    return None


DECODERS = [dec_iex_literal, dec_encoded_command, dec_compressed, dec_xor, dec_getstring, dec_packer,
            dec_js_eval, dec_vbs_execute, dec_blob]

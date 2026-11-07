"""String literals per language: a regex that matches one, a decoder for its value, a renderer back.

Folding obfuscation is mostly "evaluate this expression made of literals and write the result back
as a literal", so every transform is built on these three operations.
"""

from __future__ import annotations

import re

# Performance matters here: these patterns run over hostile, megabyte-sized input. Each is an "unrolled
# loop" (normal* (escape normal*)*), linear and free of catastrophic backtracking, and none may open on a
# quote that is the second half of an escape ('' `" \' ""): a real tokenizer never starts a literal
# there, and allowing it makes an unterminated run of escapes cost O(n^2).

# PowerShell: '...' ('' escapes a quote), "..." without $ expansion (` and "" escape), and here-strings
# @'<newline>...<newline>'@ / @"..."@, where droppers like to park a big payload.
_PS_HERE_SQ = r"@'\r?\n[\s\S]*?\r?\n'@"
_PS_HERE_DQ = r"@\"\r?\n(?:[^`$]|`[\s\S])*?\r?\n\"@"
_PS_SQ = r"(?<!')'[^']*(?:''[^']*)*'"
PS_STR = (r"(?:" + _PS_HERE_SQ + "|" + _PS_HERE_DQ + "|" + _PS_SQ +
          r"|(?<![`\"])\"[^\"`$]*(?:(?:`.|\"\")[^\"`$]*)*\")")
# Where literals are, for skipping: also expandable strings ("...$x..."), which cannot be folded
PS_ANY_STR = (r"(?:" + _PS_HERE_SQ + r"|@\"\r?\n[\s\S]*?\r?\n\"@|" + _PS_SQ +
              r"|(?<![`\"])\"[^\"`]*(?:(?:`[\s\S]|\"\")[^\"`]*)*\")")
PS_SINGLE = r"(?:" + _PS_HERE_SQ + "|" + _PS_SQ + ")"
# JavaScript: '...' and "..." with backslash escapes, single line
JS_STR = r"(?:(?<!\\)'[^'\\\n]*(?:\\.[^'\\\n]*)*'|(?<!\\)\"[^\"\\\n]*(?:\\.[^\"\\\n]*)*\")"
# VBScript: "..." ("" escapes a quote). Source literals never hold a line break, but folded ones can
# (Execute "a" & vbCrLf & "b"), so line breaks are allowed inside.
VBS_STR = r"(?<!\")\"[^\"]*(?:\"\"[^\"]*)*\""

_PS_TICK = {"0": "\0", "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def _ps_unescape(body: str, doubled_quotes: bool) -> str:
    def r(m):
        return '"' if m.group(0) == '""' else _PS_TICK.get(m.group(1), m.group(1))
    return re.sub(r'`(.)|""' if doubled_quotes else r"`(.)", r, body, flags=re.S)


def ps_value(lit: str) -> str:
    if lit[0] == "@":                                    # here-string: the lines between the markers
        body = lit[lit.index("\n") + 1:lit.rindex("\n")]
        body = body[:-1] if body.endswith("\r") else body
        return body if lit[1] == "'" else _ps_unescape(body, doubled_quotes=False)
    body = lit[1:-1]
    if lit[0] == "'":
        return body.replace("''", "'")
    return _ps_unescape(body, doubled_quotes=True)


def ps_render(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


_JS_ESC = re.compile(r"\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|[0-7]{1,3}|.)", re.S)
_JS_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def js_value(lit: str) -> str:
    def esc(m):
        s = m.group(1)
        if len(s) == 3 and s[0] == "x":
            return chr(int(s[1:], 16))
        if s.startswith("u{"):
            code = int(s[2:-1], 16)
            return chr(code) if code <= 0x10FFFF else m.group(0)
        if len(s) == 5 and s[0] == "u":
            return chr(int(s[1:], 16))
        if s[0] in "01234567" and s != "0":
            return chr(int(s, 8))                        # legacy octal escape
        return _JS_SIMPLE.get(s, s)                      # \q, \8, a lone \x or \u: the character itself
    return _JS_ESC.sub(esc, lit[1:-1])


def js_render(value: str) -> str:
    out = value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
    return "'" + out + "'"


def vbs_value(lit: str) -> str:
    return lit[1:-1].replace('""', '"')


def vbs_render(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


LANGS = {
    "powershell": (PS_STR, ps_value, ps_render),
    "javascript": (JS_STR, js_value, js_render),
    "vbscript": (VBS_STR, vbs_value, vbs_render),
}

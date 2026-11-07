"""Peel layers until nothing more can be decoded. Every step is a pure text transformation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .transforms import DECODERS, REWRITES, Decoded, sniff

MAX_LAYERS = 32
MAX_PASSES = 200
MAX_INPUT = 20 * 1024 * 1024

_SIGNALS = {
    "powershell": [r"\$\w+", r"-join\b", r"\[convert\]", r"\biex\b", r"invoke-expression", r"\[char\]",
                   r"new-object", r"-f\s*['\"]", r"-[ci]?replace\b", r"\bwrite-(?:host|output)\b", r"\bget-\w+",
                   r"\bpowershell\b", r"-bxor\b", r"`[a-z]", r"\bset-\w+"],
    "javascript": [r"\bfunction\s*\(", r"\bvar\s+\w+\s*=", r"\beval\s*\(", r"fromcharcode", r"\batob\(",
                   r"\bdocument\.", r"=>", r"\b(?:let|const)\s+\w+\s*=", r"\bwindow\.", r"activexobject",
                   r"\bunescape\(", r"\bconsole\.log\("],
    "vbscript": [r"\bchrw?\(", r"\bdim\s+\w+", r"\bcreateobject\(", r"\bexecute(?:global)?\b", r"\bwscript\.",
                 r"\bend\s+(?:sub|function)\b", r"\bstrreverse\(", r"\bmsgbox\b", r"\"\s*&\s*"],
    "batch": [r"^\s*@?echo\s+off", r"^\s*set\s+\w+=", r"%\w+(?::~[^%]*)?%", r"\bgoto\s+\w+", r"\bcall\s+",
              r"\bcmd(?:\.exe)?\s+/[ck]\b", r"%comspec%", r"\^\w"],
}


def detect_language(text: str) -> str:
    low = text[:200_000].lower()
    scores = {lang: sum(1 for p in pats if re.search(p, low, re.M)) for lang, pats in _SIGNALS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else "unknown"


@dataclass
class Layer:
    index: int
    language: str
    source: str                      # the layer as it arrived
    text: str                        # after rewrites
    rewrites: dict[str, int] = field(default_factory=dict)
    decoded_by: Decoded | None = None


@dataclass
class Artifact:
    kind: str
    size: int
    sha256: str
    layer: int
    technique: str


@dataclass
class Result:
    layers: list[Layer]
    artifacts: list[Artifact]
    stopped: str

    @property
    def final(self) -> str:
        return self.layers[-1].text

    @property
    def rewrite_count(self) -> int:
        return sum(sum(layer.rewrites.values()) for layer in self.layers)


def _rewrite(layer: Layer) -> None:
    rules = [r for r in REWRITES if layer.language in r.langs]
    text = layer.text
    for _ in range(MAX_PASSES):
        changed = False
        for rule in rules:
            new, n = rule.fn(text)
            if n and new != text:
                layer.rewrites[rule.name] = layer.rewrites.get(rule.name, 0) + n
                text, changed = new, True
        if not changed:
            break
    layer.text = text


def unwrap(text: str, max_layers: int = MAX_LAYERS) -> Result:
    if len(text) > MAX_INPUT:
        raise ValueError(f"input is larger than {MAX_INPUT // (1024 * 1024)} MB")
    layers: list[Layer] = []
    artifacts: list[Artifact] = []
    seen: set[str] = set()
    current, stopped, language = text, "nothing left to decode", None
    for index in range(max_layers):
        layer = Layer(index, language or detect_language(current), current, current)
        _rewrite(layer)
        layers.append(layer)
        seen.add(layer.text.strip())
        decoded = next((d for d in map(lambda dec: dec(layer.text), DECODERS) if d is not None), None)
        if decoded is None:
            break
        if decoded.text is None:
            data = decoded.data or b""
            layer.decoded_by = decoded
            artifacts.append(Artifact(sniff(data), len(data), hashlib.sha256(data).hexdigest(), index,
                                      decoded.technique))
            stopped = "binary payload extracted"
            break
        if decoded.text.strip() in seen:
            stopped = "decoding loops back to an earlier layer"
            break
        if len(decoded.text) > MAX_INPUT:
            layer.decoded_by = decoded
            stopped = f"next layer is larger than {MAX_INPUT // (1024 * 1024)} MB"
            break
        layer.decoded_by = decoded
        current, language = decoded.text, decoded.language    # a wrapper that runs code knows its language
    else:
        stopped = f"layer limit ({max_layers}) reached"
    return Result(layers, artifacts, stopped)

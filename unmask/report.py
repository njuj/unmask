"""Turning a traced chain into what an analyst acts on: the chain, the configuration, what to report
and to whom, and files to block with (IOC list, YARA rule)."""

from __future__ import annotations

import json
import re
from dataclasses import asdict

from . import __version__, providers
from .families import Config
from .trace import Stage

CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"


def number(i: int) -> str:
    return CIRCLED[i] if i < len(CIRCLED) else f"({i + 1})"


def defang(value: str) -> str:
    """Unclickable but readable: hxxps://host[.]example/path, host[.]example."""
    m = re.match(r"(?i)(\w+)(://)([^/?#]*)(.*)", value, re.S)
    if m:
        return re.sub(r"(?i)^http", "hxxp", m.group(1)) + m.group(2) + m.group(3).replace(".", "[.]") + m.group(4)
    return value.replace(".", "[.]")


def stages(root: Stage) -> list[Stage]:
    return [s for s in root.walk() if not s.duplicate_of]


def c2_list(root: Stage) -> list[tuple[str, str, Stage]]:
    out, seen = [], set()
    for s in stages(root):
        if s.config:
            for host, port in s.config.c2:
                if (host, port) not in seen:
                    seen.add((host, port))
                    out.append((host, port, s))
    return out


def remote_urls(root: Stage) -> list[tuple[str, Stage]]:
    out, seen = [], set()
    for s in stages(root):
        for u in s.urls + (s.config.remote_config if s.config else []):
            if u not in seen:
                seen.add(u)
                out.append((u, s))
    return out


def _host(url: str) -> str:
    m = re.match(r"(?i)\w+://([^/:?#]+)", url)
    return m.group(1) if m else url


class Painter:
    def __init__(self, color: bool):
        self.on = color

    def __call__(self, s: str, code: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if self.on else s


def render(root: Stage, elapsed: float, color: bool, lookup: dict[str, str] | None = None) -> str:
    p = Painter(color)
    lookup = lookup or {}
    all_stages = stages(root)
    index = {id(s): i for i, s in enumerate(all_stages)}
    out = [p(f" unmask v{__version__}", "1;36") + p(f"  ·  {root.name}  ·  {len(all_stages)} stage(s)  ·  "
                                                     f"{elapsed:.1f}s", "2"), ""]

    out.append(p(" CHAIN", "1"))

    def tree(s: Stage, depth: int):
        pad = "   " * depth
        branch = "└─" if depth else ""
        if s.duplicate_of:
            out.append(f" {pad}{branch}{p('↺', '2')} {s.name}  {p(f'same file as {s.duplicate_of}', '2')}")
            return
        mark = ""
        if s.config:
            mark = p(f"  ✖ {s.config.family}" + (f" {s.config.version}" if s.config.version else ""), "1;31")
        out.append(f" {pad}{branch}{p(number(index[id(s)]), '1;35')} {p(s.name, '1')}  "
                   f"{p(s.detail or s.kind, '36')}  {p(f'{len(s.data):,} B', '2')}  {p(s.sha256[:16], '2')}{mark}")
        sub = pad + ("   " if depth else "")
        if depth:
            steps = "  →  ".join(s.how)
            if s.origin != s.name or steps:
                out.append(f" {sub}  {p('from', '2')} {s.origin}" + (p(f"  ·  {steps}", "33") if steps else ""))
        for note in s.notes:
            out.append(f" {sub}  {p('note', '2')} {note}")
        for c in s.children:
            tree(c, depth + 1)

    tree(root, 0)

    for s in all_stages:
        if s.config:
            out += [""] + config_block(s.config, number(index[id(s)]), p, lookup)

    c2 = c2_list(root)
    urls = remote_urls(root)
    telegram = [(s.config.telegram, s) for s in all_stages if s.config and s.config.telegram]
    if c2 or urls or telegram:
        out += ["", p(" TAKE IT DOWN", "1") + p("  ·  report these and the attacker loses every victim at once", "2")]
        for host, port, _ in c2:
            owner = providers.classify(host)
            where = owner.report if owner else "the domain's registrar (--lookup finds its abuse contact)"
            who = f"{owner.provider} · {owner.category}" if owner else "domain"
            if host in lookup:
                where = f"{lookup[host]}  ({where})"
            out.append(f"   {p(defang(host), '1;31')}:{port}  {p(who, '36')}  →  {where}")
        for url, _ in urls:
            owner = providers.classify(_host(url))
            who = f"{owner.provider} · {owner.category}" if owner else "web server"
            where = owner.report if owner else "the site's host"
            out.append(f"   {p(defang(url), '33')}  {p(who, '36')}  →  {where}")
            out.append(p("      a next stage on a server: not downloaded (fetching it can warn the attacker); "
                         "report it so it is removed", "2"))
        for (token, chat), _ in telegram:
            bot = token.split(":")[0]
            out.append(f"   {p('Telegram bot ' + bot, '1;31')}  →  abuse@telegram.org "
                       + p("(send the bot ID; do not use the token yourself)", "2"))
        out.append(p("   also share the C2 and hashes with abuse.ch ThreatFox / URLhaus so every defender blocks them", "2"))

    behaviour = [(b, s) for s in all_stages for b in s.behaviours]
    if behaviour:
        out += ["", p(" BEHAVIOUR", "1")]
        seen = set()
        for (tech, desc, evidence), s in behaviour:
            if (tech, desc) in seen:
                continue
            seen.add((tech, desc))
            out.append(f"   {p(tech, '35'):<20} {desc}  {p(number(index[id(s)]), '2')}")
            out.append(p(f"      {evidence[:120]}", "2"))

    iocs = other_iocs(root)
    if iocs:
        out += ["", p(" OTHER INDICATORS", "1")]
        for kind, values in iocs.items():
            for v in values[:15]:
                out.append(f"   {p(kind[:-1] if kind.endswith('s') else kind, '2'):<10} {defang(v)}")

    out.append("")
    configs = [s for s in all_stages if s.config]
    if configs:
        fams = ", ".join(sorted({s.config.family for s in configs}))
        out.append(p(f" ✖ {fams} found  ·  {len(c2)} C2 endpoint(s)", "1;31"))
    elif any(s.kind == "pe" for s in all_stages):
        out.append(p(" no RAT configuration recognised", "1;33") + p("  ·  the chain above is what could be opened "
                                                                       "statically", "2"))
    else:
        out.append(p(" no executable reached", "1;33") + p("  ·  see the notes and next-stage URLs above", "2"))
    return "\n".join(out)


def config_block(cfg: Config, num: str, p: Painter, lookup: dict[str, str]) -> list[str]:
    title = f" ✖ {cfg.family}" + (f" {cfg.version}" if cfg.version else "") + " configuration"
    out = [p(title, "1;31") + p(f"  ·  stage {num}, class {cfg.location}" +
                                ("  ·  field names were obfuscated, values matched by shape" if cfg.renamed else ""), "2")]
    if cfg.key_note:
        out.append(p(f"   decrypted with {cfg.key_note}", "2"))
    for host, port in cfg.c2:
        owner = providers.classify(host)
        tag = f"{owner.provider} · {owner.category}" if owner else ""
        out.append(f"   {'C2':<32} {p(host + ':' + port, '1;31')}  {p(tag, '36')}")
    for item in cfg.items:
        if item.label in ("C2 host", "C2 hosts", "C2 port"):
            continue
        note = p(f"  {item.note}", "2") if item.note else ""
        out.append(f"   {item.label:<32} {item.value}{note}")
    for url in cfg.remote_config:
        out.append(f"   {'C2 list at':<32} {p(defang(url), '33')}  " + p("the C2 address is read from this page", "2"))
    return out


def other_iocs(root: Stage) -> dict[str, list[str]]:
    c2 = {h.lower() for h, _, _ in c2_list(root)}
    stage_urls = {u for u, _ in remote_urls(root)}
    out: dict[str, list[str]] = {}
    for s in stages(root):
        for kind, values in s.iocs.items():
            for v in values:
                if v.lower() in c2 or v in stage_urls:
                    continue
                bucket = out.setdefault(kind, [])
                if v not in bucket:
                    bucket.append(v)
    return out


def to_json(root: Stage, elapsed: float, lookup: dict[str, str] | None = None) -> str:
    def node(s: Stage) -> dict:
        d = {"name": s.name, "kind": s.kind, "detail": s.detail, "size": len(s.data), "sha256": s.sha256,
             "origin": s.origin, "how": s.how, "notes": s.notes, "next_stage_urls": s.urls, "iocs": s.iocs,
             "behaviours": [{"technique": t, "description": d_, "evidence": e} for t, d_, e in s.behaviours],
             "config": asdict(s.config) if s.config else None, "children": [node(c) for c in s.children]}
        if s.duplicate_of:
            d = {"name": s.name, "sha256": s.sha256, "duplicate_of": s.duplicate_of}
        return d

    takedown = []
    for host, port, _ in c2_list(root):
        owner = providers.classify(host)
        takedown.append({"c2": f"{host}:{port}", "provider": owner.provider if owner else None,
                         "category": owner.category if owner else None, "report": owner.report if owner else None,
                         "abuse_contact": (lookup or {}).get(host)})
    return json.dumps({"tool": "unmask", "version": __version__, "elapsed": round(elapsed, 3), "chain": node(root),
                       "takedown": takedown}, indent=2)


def ioc_list(root: Stage) -> str:
    lines = ["# unmask indicators: one per line, for firewalls, DNS blocklists and threat-intel platforms"]
    c2 = c2_list(root)
    if c2:
        lines.append("# C2 endpoints (host:port)")
        lines += sorted({f"{h}:{p}" for h, p, _ in c2})
        lines.append("# C2 hosts")
        lines += sorted({h for h, _, _ in c2})
    urls = remote_urls(root)
    if urls:
        lines.append("# next-stage URLs")
        lines += [u for u, _ in urls]
    lines.append("# SHA-256 of every stage")
    lines += [f"{s.sha256}  {s.name}" for s in stages(root)]
    return "\n".join(lines) + "\n"


def yara_rules(root: Stage) -> str:
    rules = []
    for s in stages(root):
        cfg = s.config
        if not cfg:
            continue
        strings = list(dict.fromkeys(cfg.raw))[:12]          # as stored in the binary (UTF-16 in #US)
        if not strings:
            continue
        name = re.sub(r"\W", "_", f"unmask_{cfg.family}_{s.sha256[:12]}")
        body = [f"rule {name}", "{", "    meta:",
                f'        description = "{cfg.family} {cfg.version} configuration values (unmask)"',
                f'        sha256 = "{s.sha256}"', "    strings:"]
        for i, v in enumerate(strings):
            esc = v.replace(chr(92), chr(92) * 2).replace('"', chr(92) + '"')
            body.append(f'        $s{i} = "{esc}" wide')
        body += ["    condition:", f"        uint16(0) == 0x5A4D and ({min(3, len(strings))} of them)", "}"]
        rules.append("\n".join(body))
    return "\n\n".join(rules) + ("\n" if rules else "")

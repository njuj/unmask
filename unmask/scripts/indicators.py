"""Indicators and behaviours, gathered from every layer (a URL often only exists in the middle one)."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .literals import JS_STR, PS_STR

TLDS = set("com net org io co info biz xyz top club online site me us uk de fr nl ru cn br in jp kr ir su tk ml ga "
           "cf gq pw cc tv ws app dev ai gov edu mil int eu ca au es it pl ua live store shop link click space tech "
           "fun icu rest bar cam cloud host website digital network news blog world today page onion example".split())

URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}|\\^`,;]+", re.I)
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
EMAIL = re.compile(r"\b[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})", re.I)
WINPATH = re.compile(r"(?:\b[a-zA-Z]:|%\w+%|\$env:\w+)\\(?:[^\\/:*?\"<>|\r\n']+\\)*[^\\/:*?\"<>|\s'\";)]+")
REGISTRY = re.compile(r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HK(?:LM|CU|CR|U)):?\\[\w\\. {}-]*[\w}]",
                      re.I)
LITERAL = re.compile(PS_STR + "|" + JS_STR)

BEHAVIOURS = [
    (r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|start-bitstransfer|"
     r"net\.webclient|msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|urldownloadtofile|\bcurl(?:\.exe)?\s|\bwget\s",
     "T1105", "downloads content from the network"),
    (r"\biex\b|invoke-expression|\beval\s*\(|\bexecute(?:global)?\b|new\s+function\s*\(|\.invoke\(\)",
     "T1059", "executes code it built at run time"),
    (r"frombase64string|\batob\(|-decode\b", "T1140", "decodes data at run time"),
    (r"reflection\.assembly\]::load|assembly\]::load\(|\bassembly\.load\(", "T1620", "loads a .NET assembly from memory"),
    (r"virtualalloc|virtualprotect|createthread|writeprocessmemory|rtlmovememory|getdelegateforfunctionpointer",
     "T1055", "allocates executable memory (shellcode / injection)"),
    (r"add-mppreference|set-mppreference|disablerealtimemonitoring", "T1562.001", "weakens Microsoft Defender"),
    (r"amsi[u]tils|amsi[i]nit[f]ailed|amsi[s]can[b]uffer", "T1562.001", "tampers with AMSI"),
    (r"new-service|\bsc(?:\.exe)?\s+create|schtasks(?:\.exe)?\s+/create|register-scheduledtask",
     "T1543.003 / T1053.005", "installs a service or scheduled task"),
    (r"currentversion\\run", "T1547.001", "writes an autorun registry key"),
    (r"-w(?:indowstyle)?\s+hidden|-windowstyle\s+1\b|\.run\([^)]*,\s*0\s*[,)]", "T1564.003", "hides its window"),
    (r"wscript\.shell|shell\.application|\bshellexecute|start-process|\bcmd(?:\.exe)?\s+/c", "T1059",
     "starts another program or shell"),
    (r"\b(?:certutil|bitsadmin|mshta|regsvr32|rundll32|wmic)(?:\.exe)?\b", "T1218", "uses a living-off-the-land binary"),
    (r"vssadmin(?:\.exe)?\s+delete|shadowcopy\s+delete|recoveryenabled\s+no", "T1490", "destroys shadow copies / recovery"),
    (r"\bnet1?(?:\.exe)?\s+(?:user|localgroup)\b[^\n]*/add", "T1136 / T1098", "creates or promotes an account"),
    (r"convertto-securestring|get-credential|sekur[l]sa::|lsadu[m]p::", "T1003", "handles credentials"),
    (r"uploadstring|uploaddata|uploadfile|-method\s+post", "T1041", "sends data out"),
    (r"\bwhoami\b|\bsysteminfo\b|get-ciminstance|get-wmiobject|\bipconfig\b|win32_operatingsystem", "T1082",
     "collects system information"),
]


def _is_host(ip: str) -> bool:
    """Version=4.0.0.0 and friends end in .0, as do network addresses; loopback and broadcast are no IOC."""
    return not ip.endswith(".0") and not ip.startswith("127.") and ip != "255.255.255.255"


def _unique(items):
    seen, out = set(), []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def extract(texts: list[str]) -> dict[str, list[str]]:
    urls, ips, domains, emails, paths, keys = [], [], [], [], [], []
    for text in texts:
        found_urls = [u.rstrip(".)'\"") for u in URL.findall(text)]
        urls += found_urls
        for u in found_urls:
            host = urlsplit(u).hostname or ""
            (ips if IPV4.fullmatch(host) else domains).append(host)
        ips += [ip for ip in IPV4.findall(text) if _is_host(ip)]
        for m in EMAIL.finditer(text):
            emails.append(m.group(0))
            domains.append(m.group(1))
        # a bare domain only counts when it is a whole string literal: avoids System.IO and friends
        for lit in LITERAL.findall(text):
            value = lit[1:-1]
            m = DOMAIN.fullmatch(value)
            if m and m.group(1).lower() in TLDS:
                domains.append(value)
        paths += [p.rstrip(".") for p in WINPATH.findall(text)]
        keys += REGISTRY.findall(text)
    domains = [d for d in domains if d and not IPV4.fullmatch(d) and d.rsplit(".", 1)[-1].lower() in TLDS]
    out = {"urls": _unique(urls), "ips": _unique(ips), "domains": _unique(domains), "emails": _unique(emails),
           "paths": _unique(paths), "registry": _unique(keys)}
    return {k: v for k, v in out.items() if v}


def defang(value: str, kind: str) -> str:
    """hxxp://evil[.]example/path: unclickable, but the path stays readable."""
    if kind == "urls":
        m = re.match(r"(?i)(\w+)(://)([^/?#]*)(.*)", value, re.S)
        if m:
            return re.sub(r"(?i)^http", "hxxp", m.group(1)) + m.group(2) + m.group(3).replace(".", "[.]") + m.group(4)
    if kind in ("ips", "domains", "emails"):
        return value.replace(".", "[.]").replace("@", "[@]")
    return value


EVIDENCE = 110


def _evidence(text: str, m: re.Match) -> str:
    """The statement around a match: its whole line when short, else a window that starts on a word."""
    start = max(text.rfind("\n", 0, m.start()) + 1, text.rfind(";", 0, m.start()) + 1)
    end = text.find("\n", m.end())
    end = len(text) if end < 0 else end
    line = text[start:end].strip()
    if len(line) <= EVIDENCE:
        return line
    lo = max(m.start() - 40, start)
    if lo > start:
        space = text.find(" ", lo, m.start())
        lo = space + 1 if space >= 0 else lo
    window = " ".join(text[lo:min(lo + EVIDENCE, end)].split())
    return ("..." if lo > start else "") + window + ("..." if lo + EVIDENCE < end else "")


def behaviours(texts: list[str]) -> list[tuple[str, str, str]]:
    """(technique, description, evidence) for every behaviour seen in any layer."""
    found = []
    for pattern, technique, description in BEHAVIOURS:
        rx = re.compile(pattern, re.I)
        for text in reversed(texts):                      # prefer evidence from the most decoded layer
            m = rx.search(text)
            if m:
                found.append((technique, description, _evidence(text, m)))
                break
    return found

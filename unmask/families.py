"""RAT configuration extractors. Each reads the values a builder wrote into the stub's static fields
(see dotnet.Metadata._initialisers) and decodes them the way the RAT itself does at start-up.

Field names are used when the builder's own survive; when an obfuscator renamed them, every value is
recognised by its shape instead (a host, a port, a separator, an install path), so the result is
the same either way."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field

from . import aes
from .dotnet import Assembly, TypeInfo

HOST = re.compile(r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3})$", re.I)
TELEGRAM = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,50}$")
FILE_EXT = re.compile(r"\.(?:exe|dll|scr|com|bat|cmd|vbs|js|ps1|tmp|log|txt|dat|bin|sys|lnk)$", re.I)  # USB.exe is no host


@dataclass
class Item:
    label: str
    value: str
    note: str = ""


@dataclass
class Config:
    family: str
    version: str = ""
    c2: list[tuple[str, str]] = field(default_factory=list)       # (host, port)
    items: list[Item] = field(default_factory=list)
    telegram: tuple[str, str] | None = None                         # (token, chat id)
    remote_config: list[str] = field(default_factory=list)          # pastebin-style URLs holding the C2
    key_note: str = ""                                              # how the config was decrypted
    location: str = ""                                              # which class held it
    renamed: bool = False                                           # field names were obfuscated
    raw: list[str] = field(default_factory=list)                    # the values exactly as stored in the file

    def add(self, label: str, value, note: str = "") -> None:
        if value not in (None, ""):
            self.items.append(Item(label, str(value), note))


def _b64text(value: str) -> str | None:
    if len(value) < 4 or len(value) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return None
    try:
        text = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if text and all(c.isprintable() for c in text) else None


def _hosts(value: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"[,;|\s]+", value) if p.strip()]
    return parts if parts and all(HOST.match(p) and not FILE_EXT.search(p) for p in parts) else []


def _port(value: str) -> bool:
    return value.isdigit() and 0 < int(value) < 65536


# ── njRAT ───────────────────────────────────────────────────────────────────

NJ_FIELDS = {
    "VN": "Victim name / campaign", "VR": "Version", "H": "C2 host", "P": "C2 port", "EXE": "Installed as",
    "DR": "Install folder", "RG": "Registry key / mutex", "Y": "Separator", "BD": "BSOD if the process is killed",
    "Idr": "Copies itself to install folder", "IsF": "Copies itself to Startup folder",
    "Isu": "Run-key persistence", "anti": "Anti-analysis", "usb": "Spreads over USB drives",
    "task": "Scheduled task persistence", "LO": "Original file",
}
NJ_VERSION = re.compile(r"^(?:0\.\d[\w.]*|im\d+|v?\d\.\d+[a-z]*\s*(?:lime|golden|green|blue|nc)?)$", re.I)


def njrat(asm: Assembly) -> Config | None:
    best = None
    for t in asm.types:
        values = {k: v for k, v in t.values.items() if isinstance(v, (str, int))}
        strings = {k: v for k, v in values.items() if isinstance(v, str)}
        named = sum(k in NJ_FIELDS for k in values)
        separator = next((k for k, v in strings.items() if v and _separator(v)), None)
        version = next((k for k, v in strings.items() if NJ_VERSION.match(v)), None)
        score = named + 3 * bool(separator) + 2 * bool(version)
        if score >= 5 and (best is None or score > best[0]):
            best = (score, t, strings, values, separator, version)
    if best is None:
        return None
    _, t, strings, values, separator, version = best
    renamed = sum(k in NJ_FIELDS for k in values) < 4
    cfg = Config("njRAT", location=t.full, renamed=renamed, raw=[v for v in strings.values() if len(v) >= 5])

    def get(name: str, shape) -> str | None:
        if not renamed and name in strings:
            return strings[name]
        return next((v for k, v in strings.items() if shape(v)), None)

    raw_host = get("H", lambda v: bool(_hosts(v) or _hosts(_b64text(v) or "")))
    host = raw_host
    if raw_host and not _hosts(raw_host) and _b64text(raw_host):
        host = _b64text(raw_host)
    port = get("P", _port)
    ver = strings.get("VR") if not renamed and "VR" in strings else (strings.get(version) if version else None)
    cfg.version = ver or ""
    if host:
        for h in _hosts(host) or [host]:
            cfg.c2.append((h, port or "?"))
    cfg.add("C2 host", host, "decoded from base64" if host != raw_host else "")
    cfg.add("C2 port", port)
    vn = strings.get("VN") if not renamed else None
    if vn:
        cfg.add("Victim name / campaign", _b64text(vn) or vn, f"base64 {vn}" if _b64text(vn) else "")
    cfg.add("Version", ver)
    sep = strings.get(separator) if separator else None
    cfg.add("Separator", sep, "splits every message between victim and C2")
    for name, label in NJ_FIELDS.items():
        if name in ("VN", "VR", "H", "P", "Y") or renamed or name not in values:
            continue
        v = values[name]
        cfg.add(label, ("yes" if v else "no") if isinstance(v, int) else v)
    if renamed:
        exe = next((v for v in strings.values() if v.lower().endswith(".exe")), None)
        cfg.add("Installed as", exe)
    return cfg


def _separator(v: str) -> bool:
    """njRAT's message separator: a short run of punctuation such as |'|'| or @!#&^%$."""
    return 3 <= len(v) <= 12 and not any(c.isalnum() for c in v) and len(set(v)) >= 2


# ── XWorm ───────────────────────────────────────────────────────────────────

XW_FIELDS = {
    "Hosts": "C2 hosts", "Host": "C2 host", "Port": "C2 port", "KEY": "Encryption key", "SPL": "Separator",
    "Sleep": "Sleep (seconds)", "Groub": "Group / build", "Group": "Group / build", "USBNM": "USB spreader name",
    "InstallDir": "Install folder", "InstallStr": "Installed as", "Mutex": "Mutex", "LoggerPath": "Keylogger file",
    "ChatID": "Telegram chat ID", "Token": "Telegram bot token", "Pastebin": "Pastebin URL",
}


def xworm_key(mutex: str) -> bytes:
    """XWorm's AES-256 key: MD5(mutex) copied to offset 0 and again to offset 15 of a 32-byte buffer."""
    h = hashlib.md5(mutex.encode("utf-8")).digest()
    return h[:15] + h + b"\0"


def _cipher_blob(v: str) -> bytes | None:
    if len(v) < 24 or len(v) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
        return None
    try:
        b = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return None
    return b if len(b) % 16 == 0 else None


def _plain(b: bytes | None) -> str | None:
    if b is None:
        return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if all(c.isprintable() for c in s) else None


def xworm(asm: Assembly) -> Config | None:
    for t in asm.types:
        strings = {k: v for k, v in t.values.items() if isinstance(v, str)}
        blobs = {k: b for k, v in strings.items() if (b := _cipher_blob(v)) is not None}
        if len(blobs) < 3:
            continue
        # the mutex is the one value stored in plain text; try those first, then every short user string
        plain = [v for k, v in strings.items() if k not in blobs and 4 <= len(v) <= 64]
        extra = [s for s in asm.user_strings if 4 <= len(s) <= 64 and s not in plain]
        for mutex in plain + extra[:200]:
            key = xworm_key(mutex)
            decrypted = {k: _plain(aes.decrypt_ecb(key, b)) for k, b in blobs.items()}
            good = {k: v for k, v in decrypted.items() if v is not None}
            if len(good) >= max(3, int(0.6 * len(blobs))):
                return _xworm_config(asm, t, strings, good, mutex)
    return None


def _xworm_config(asm: Assembly, t: TypeInfo, strings: dict, good: dict, mutex: str) -> Config:
    values = dict(t.values)
    values.update(good)
    renamed = sum(k in XW_FIELDS for k in values) < 4
    cfg = Config("XWorm", location=t.full, renamed=renamed,
                 key_note=f"AES-256-ECB, key = MD5(mutex \"{mutex}\") as XWorm derives it",
                 raw=[v for v in strings.values() if len(v) >= 8])
    by_label: dict[str, str] = {}
    if not renamed:
        for k, v in values.items():
            if k in XW_FIELDS:
                by_label[XW_FIELDS[k]] = str(v)
    else:
        for k, v in values.items():
            label = _xworm_shape(str(v), v, by_label, mutex)
            if label:
                by_label.setdefault(label, str(v))
    hosts = by_label.get("C2 hosts") or by_label.get("C2 host") or ""
    port = by_label.get("C2 port", "?")
    group = by_label.get("Group / build", "")
    m = re.search(r"XWorm\s*V?\s*(\d+(?:\.\d+)*)", group + " " + " ".join(asm.user_strings), re.I)
    cfg.version = m.group(1) if m else ""
    if hosts.lower().startswith("http"):
        cfg.remote_config.append(hosts)                             # "pastebin mode": the host list lives at a URL
    for h in _hosts(hosts):
        cfg.c2.append((h, port))
    if by_label.get("Pastebin", "").lower().startswith("http"):
        cfg.remote_config.append(by_label["Pastebin"])
    token, chat = by_label.get("Telegram bot token", ""), by_label.get("Telegram chat ID", "")
    if TELEGRAM.match(token):
        cfg.telegram = (token, chat)
    order = ["C2 hosts", "C2 host", "C2 port", "Encryption key", "Separator", "Group / build", "Mutex",
             "Install folder", "Installed as", "USB spreader name", "Keylogger file", "Sleep (seconds)",
             "Pastebin URL", "Telegram bot token", "Telegram chat ID"]
    for label in order:
        v = by_label.get(label)
        if v and v not in ("null", "%BotToken%", "%ChatID%"):
            cfg.add(label, v)
    if not cfg.telegram:
        cfg.add("Telegram", "not used", "the builder's Telegram fields are empty")
    return cfg


def _xworm_shape(s: str, raw, seen: dict, mutex: str) -> str | None:
    if isinstance(raw, int):
        return "Sleep (seconds)"
    if s == mutex:
        return "Mutex"
    if TELEGRAM.match(s):
        return "Telegram bot token"
    if s.lower().startswith("http"):
        return "C2 hosts"
    if _hosts(s):
        return "C2 hosts"
    if _port(s):
        return "C2 port" if "C2 port" not in seen else "Telegram chat ID"
    if re.fullmatch(r"\d{6,12}", s):
        return "Telegram chat ID"
    if re.fullmatch(r"<\d+>", s):
        return "Encryption key"
    if re.fullmatch(r"<[^<>]+>", s):
        return "Separator"
    if re.fullmatch(r"%\w+%", s):
        return "Install folder"
    if re.search(r"\.(tmp|log|txt)$", s, re.I):
        return "Keylogger file"
    if s.lower().endswith(".exe"):
        return "USB spreader name" if "usb" in s.lower() else "Installed as"
    if "xworm" in s.lower() or s:
        return "Group / build"
    return None


# ── AsyncRAT family (recognised; extraction comes later) ─────────────────────

ASYNC_FIELDS = {"Por_ts", "Hos_ts", "Ver_sion", "In_stall", "Install_Folder", "Install_File", "MTX", "Certificate",
                "Serversignature", "Pastebin", "BDOS", "Anti", "Hwid", "Group", "Ports", "Hosts", "Version", "Key"}


def asyncrat(asm: Assembly) -> Config | None:
    for t in asm.types:
        hits = ASYNC_FIELDS & set(t.values)
        if len(hits) >= 6 and ("Certificate" in hits or "Serversignature" in hits):
            dc = any("dcrat" in s.lower() for s in asm.user_strings + asm.names)
            cfg = Config("DcRat" if dc else "AsyncRAT-family", location=t.full)
            cfg.add("Status", "recognised", "this family's configuration (AES-256-CBC + HMAC, PBKDF2 key) "
                                             "is not decrypted yet in this version")
            return cfg
    return None


EXTRACTORS = [xworm, njrat, asyncrat]


def extract(asm: Assembly) -> Config | None:
    for fn in EXTRACTORS:
        cfg = fn(asm)
        if cfg:
            return cfg
    return None

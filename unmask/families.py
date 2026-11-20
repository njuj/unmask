"""RAT configuration extractors. Each reads the values a builder wrote into the stub's static fields
(see dotnet.Metadata._initialisers) and decodes them the way the RAT itself does at start-up.

Field names are used when the builder's own survive; when an obfuscator renamed them, every value is
recognised by its shape instead (a host, a port, a separator, an install path), so the result is
the same either way."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
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


# ── AsyncRAT family: AsyncRAT, DcRat, VenomRAT ───────────────────────────────
# Every value is sealed by the client's Aes256 class: PBKDF2-SHA1 over the base64-decoded Key field
# (50,000 rounds) gives a 32-byte AES key and a 64-byte HMAC key; a value is HMAC-SHA256 (32) | IV (16) |
# AES-256-CBC ciphertext. The HMAC confirms a key and salt pair outright, so candidates are tried, never guessed.

ASYNC_SALTS = [
    bytes.fromhex("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941"),   # AsyncRAT
    b"bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",                # the same, as text
    b"DcRatByqwqdanchun",                                                              # DcRat
    b"VenomRATByVenom",                                                                # VenomRAT
]
SALT_NAMES = ["AsyncRAT's salt", "AsyncRAT's salt as text", '"DcRatByqwqdanchun"', '"VenomRATByVenom"']
ASYNC_LABELS = {
    "hosts": "C2 hosts", "ports": "C2 ports", "version": "Version", "install": "Installs itself",
    "installfolder": "Install folder", "installfile": "Installed as", "mtx": "Mutex", "pastebin": "Pastebin URL",
    "anti": "Anti-analysis", "antiprocess": "Kills analysis tools", "bsod": "BSOD if the process is killed",
    "bdos": "BSOD if the process is killed", "group": "Group / campaign", "delay": "Start-up delay (seconds)",
    "certificate": "Server certificate", "serversignature": "Server signature", "key": "Master key",
}
ASYNC_ORDER = ["C2 hosts", "C2 ports", "Version", "Group / campaign", "Mutex", "Installs itself", "Install folder",
               "Installed as", "Anti-analysis", "Kills analysis tools", "BSOD if the process is killed",
               "Start-up delay (seconds)"]
MAX_KDF = 40                                     # PBKDF2 runs per type, 50,000 rounds each


def _norm(name: str) -> str:
    return re.sub(r"[^a-z]", "", name.lower())


def _async_blob(v: str) -> bytes | None:
    if len(v) < 88 or len(v) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
        return None
    try:
        b = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return None
    return b if len(b) >= 64 and (len(b) - 48) % 16 == 0 else None


def async_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    out = hashlib.pbkdf2_hmac("sha1", password, salt, 50000, 96)
    return out[:32], out[32:]


def async_decrypt(aes_key: bytes, auth_key: bytes, blob: bytes) -> bytes | None:
    """None unless the HMAC matches: a wrong key or salt never yields text."""
    if not hmac.compare_digest(hmac.new(auth_key, blob[32:], hashlib.sha256).digest(), blob[:32]):
        return None
    return aes.decrypt_cbc(aes_key, blob[32:48], blob[48:])


def _async_salts(asm: Assembly, t: TypeInfo):
    yield from ASYNC_SALTS
    seen = set(ASYNC_SALTS)
    texts = [v for v in t.values.values() if isinstance(v, str)] + asm.user_strings
    for cand in [a.data for a in asm.arrays if 16 <= len(a.data) <= 64] + [s.encode() for s in texts if 8 <= len(s) <= 80]:
        if cand not in seen:
            seen.add(cand)
            yield cand


def asyncrat(asm: Assembly) -> Config | None:
    for t in asm.types:
        strings = {k: v for k, v in t.values.items() if isinstance(v, str)}
        blobs = {k: b for k, v in strings.items() if (b := _async_blob(v)) is not None}
        if len(blobs) >= 3:
            # the master key: base64 of a printable string; the builder's own field name first
            keys = [(k, s) for k, v in strings.items() if k not in blobs and (s := _b64text(v)) and 8 <= len(s) <= 128]
            keys.sort(key=lambda kv: _norm(kv[0]) != "key")
            probe = min(blobs.values(), key=len)
            runs = 0
            for kname, password in keys:
                for salt in _async_salts(asm, t):
                    if runs >= MAX_KDF:
                        break
                    runs += 1
                    ak, hk = async_keys(password.encode("utf-8"), salt)
                    if async_decrypt(ak, hk, probe) is None:
                        continue
                    plain = {k: _plain(async_decrypt(ak, hk, b)) for k, b in blobs.items()}
                    return _async_config(asm, t, strings, {k: v for k, v in plain.items() if v is not None}, kname, salt)
        hits = {_norm(k) for k in t.values} & set(ASYNC_LABELS)
        if len(hits) >= 6 and ("certificate" in hits or "serversignature" in hits):
            cfg = Config(_async_family(asm, ""), location=t.full)
            cfg.add("Status", "recognised", "no key and salt pair passed the HMAC check, values left sealed")
            return cfg
    return None


def _cert_names(der: bytes) -> list[str]:
    """Every commonName in a DER certificate (issuer first, then subject)."""
    out, i = [], 0
    while (i := der.find(b"\x06\x03\x55\x04\x03", i)) != -1 and i + 7 <= len(der):
        tag, n = der[i + 5], der[i + 6]
        if tag in (0x0C, 0x13, 0x14, 0x16) and n < 0x80 and i + 7 + n <= len(der):
            out.append(der[i + 7:i + 7 + n].decode("utf-8", "replace"))
        i += 5
    return out


def _cert_of(v: str) -> str:
    if len(v) < 60 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
        return ""
    try:
        names = _cert_names(base64.b64decode(v + "=" * (-len(v) % 4)))
    except (binascii.Error, ValueError):
        return ""
    return names[-1] if names else ""


def _async_family(asm: Assembly, hint: str) -> str:
    text = (hint + " " + " ".join(asm.user_strings + asm.names)).lower()
    if "venom" in text:
        return "VenomRAT"
    if "dcrat" in text or "qwqdanchun" in text:
        return "DcRat"
    return "AsyncRAT"


def _async_shape(s: str, seen: dict) -> str | None:
    if re.fullmatch(r"\d{1,5}(?:\s*,\s*\d{1,5})*", s) and all(_port(p.strip()) for p in s.split(",")):
        return "C2 ports" if "C2 ports" not in seen else "Start-up delay (seconds)"
    if _hosts(s):
        return "C2 hosts"
    if s.lower() in ("true", "false"):
        return None                                   # several flags share this shape: not labelled blind
    if s.lower().startswith("http") or s == "null":
        return "Pastebin URL"
    if re.fullmatch(r"%\w+%", s):
        return "Install folder"
    if s.lower().endswith(".exe"):
        return "Installed as"
    if re.fullmatch(r"[A-Za-z]+_[A-Za-z0-9]{6,}", s) or "mutex" in s.lower():
        return "Mutex"
    if re.fullmatch(r"[\w +]*?v?\s*\d+\.\d+(?:\.\d+)*[A-Za-z]?", s):
        return "Version"
    return None


def _async_config(asm: Assembly, t: TypeInfo, strings: dict, plain: dict, kname: str, salt: bytes) -> Config:
    renamed = sum(_norm(k) in ASYNC_LABELS for k in t.values) < 4
    by_label: dict[str, str] = {}
    cert_cn = ""
    for k, v in {**strings, **plain}.items():
        if k == kname:
            continue
        if not cert_cn and (cn := _cert_of(v)):
            cert_cn = cn
            continue
        label = _async_shape(v, by_label) if renamed else ASYNC_LABELS.get(_norm(k))
        if label and label not in ("Server signature", "Master key", "Server certificate"):
            by_label.setdefault(label, v)
    family = _async_family(asm, cert_cn + " " + by_label.get("Version", ""))
    salt_name = (SALT_NAMES[ASYNC_SALTS.index(salt)] if salt in ASYNC_SALTS
                 else f"salt found in the sample {salt[:24].decode('latin-1')!r}")
    cfg = Config(family, location=t.full, renamed=renamed,
                 key_note=f"AES-256-CBC + HMAC-SHA256, keys = PBKDF2-SHA1(Key, {salt_name}, 50,000), HMAC verified",
                 raw=[v for v in strings.values() if 8 <= len(v) <= 200])
    cfg.version = by_label.get("Version", "")
    ports = [p.strip() for p in by_label.get("C2 ports", "").split(",") if p.strip()]
    for h in _hosts(by_label.get("C2 hosts", "")):
        for port in ports or ["?"]:
            cfg.c2.append((h, port))
    pb = by_label.get("Pastebin URL", "")
    if pb.lower().startswith("http"):
        cfg.remote_config.append(pb)
    for label in ASYNC_ORDER:
        v = by_label.get(label)
        if v and label != "Pastebin URL":            # a URL is listed once, defanged, as remote config
            cfg.add(label, v)
    if cert_cn:
        cfg.add("Server certificate", f"CN={cert_cn}", "pinned in the client, the C2 presents it: hunt for it")
    return cfg


EXTRACTORS = [xworm, njrat, asyncrat]


def extract(asm: Assembly) -> Config | None:
    for fn in EXTRACTORS:
        cfg = fn(asm)
        if cfg:
            return cfg
    return None

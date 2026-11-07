"""Following a delivery chain: every stage is opened, everything it carries is pulled out and peeled
(layers.find), and each result is traced in turn, until the RAT at the end gives up its configuration.
Payloads that sit on a server are reported as URLs and never fetched."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field

from . import dotnet, families, layers, pe
from .scripts import behaviours, extract, unwrap

MAX_STAGES = 200
MAX_DEPTH = 16
ZIP_PASSWORDS = [b"infected", b"1234", b"123", b"12345", b"123456", b"password", b"2024", b"2025", b"2026", b"pass"]
STAGE_URL = re.compile(r"(?i)(discordapp\.(?:com|net)/attachments|githubusercontent\.com|pastebin\.com/raw|"
                       r"paste\.ee/[rd]/|rentry\.(?:co|org)/[^/]+/raw|transfer\.sh|catbox\.moe|dropbox|"
                       r"drive\.google|mega\.nz|0x0\.st|firebasestorage|archive\.org/download|"
                       r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|txt|bin|dat|jpg|png|zip|rar|msi)(?:[?#]|$))")
NOISE_HOSTS = re.compile(r"(?i)(^|\.)(microsoft\.com|windows\.com|w3\.org|xmlsoap\.org|digicert\.com|verisign\.com|"
                         r"symantec\.com|sectigo\.com|globalsign\.(?:com|net)|usertrust\.com|comodoca\.com|"
                         r"openxmlformats\.org|purl\.org|adobe\.com|apple\.com|mozilla\.org|example\.(?:com|org|net))$")


@dataclass
class Stage:
    name: str
    kind: str
    data: bytes = field(repr=False)
    how: list[str] = field(default_factory=list)       # transforms from the parent's blob to this stage
    origin: str = ""                                    # where in the parent it was found
    children: list["Stage"] = field(default_factory=list)
    config: families.Config | None = None
    detail: str = ""                                    # ".NET exe, assembly FpsBooster", "PowerShell, 3 layers"
    urls: list[str] = field(default_factory=list)       # next stages on a server: not fetched
    iocs: dict[str, list[str]] = field(default_factory=dict)
    behaviours: list[tuple[str, str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    duplicate_of: str | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


class Tracer:
    def __init__(self):
        self.seen: dict[str, Stage] = {}
        self.count = 0

    def trace(self, data: bytes, name: str, how: list[str] | None = None, origin: str = "input", depth: int = 0,
              kind: str | None = None) -> Stage:
        stage = Stage(name, kind or layers.sniff(data), data, how or [], origin)
        digest = stage.sha256
        if digest in self.seen:
            stage.duplicate_of = self.seen[digest].name
            return stage
        self.seen[digest] = stage
        self.count += 1
        if depth >= MAX_DEPTH or self.count >= MAX_STAGES:
            stage.notes.append("not opened: the chain is deeper than the tool follows")
            return stage
        handler = {"pe": self._pe, "zip": self._zip, "script": self._script, "text": self._script,
                   "resources": self._resources}.get(stage.kind)
        blobs = handler(stage) if handler else []
        if stage.kind in ("rar", "7z"):
            stage.notes.append(f"{stage.kind.upper()} archive: extract it (7-Zip) and run unmask on the files inside")
        for where, blob, *before in blobs:
            found = layers.find(blob)
            if found is None:
                continue
            how = (before[0] if before else []) + found.how
            stage.children.append(self.trace(found.data, _child_name(where, found.kind), how, where, depth + 1,
                                             found.kind))
        return stage

    # ── stage handlers: each returns the blobs worth peeling ────────────────
    def _pe(self, stage: Stage) -> list[tuple[str, bytes]]:
        try:
            p = pe.parse(stage.data)
        except pe.PEError as e:
            stage.notes.append(f"damaged executable: {e}")
            return []
        what = "DLL" if p.is_dll else "exe"
        blobs: list[tuple[str, bytes]] = []
        if p.is_dotnet:
            try:
                asm = dotnet.read_assembly(p)
            except dotnet.DotNetError as e:
                stage.detail = f".NET {what} (metadata unreadable: {e})"
                stage.notes.append("the .NET metadata is damaged or obfuscated beyond this reader")
                asm = None
            if asm:
                stage.detail = f".NET {what}, assembly \"{asm.name}\"" + (f", entry {asm.entry}" if asm.entry else "")
                stage.config = families.extract(asm)
                blobs += [(b.origin, b.data) for b in asm.resources]
                blobs += [(b.origin, b.data) for b in asm.arrays]
                long = [s for s in asm.user_strings if len(s) >= 200]
                blobs += [(f"string literal ({len(s):,} chars)", s.encode("latin-1", "ignore")) for s in long]
                texts = [s for s in asm.user_strings if len(s) < 2000]
                found = extract(['"' + s.replace('"', "") + '"' for s in texts])
                stage.iocs = _clean(found)
                stage.urls = [u for u in stage.iocs.get("urls", []) if STAGE_URL.search(u)]
                if any("assembly::load" in r.lower() or r.lower().endswith("::load") for r in asm.member_refs):
                    stage.behaviours.append(("T1620", "loads a .NET assembly from memory", "Assembly.Load"))
                if not stage.config and _decryptor_hints(asm):
                    stage.notes.append("calls crypto/compression APIs and carries data: a loader")
        else:
            stage.detail = f"native {what} ({'64' if p.is64 else '32'}-bit)"
            blobs += [(f"resource {r.type}/{r.name}", r.data) for r in p.resources
                      if r.type not in ("ICON", "GROUP_ICON", "VERSION", "MANIFEST", "CURSOR", "GROUP_CURSOR")]
            strings = _ascii_strings(stage.data)
            found = extract(strings)
            stage.iocs = _clean(found)
            stage.urls = [u for u in stage.iocs.get("urls", []) if STAGE_URL.search(u)]
            if b"AutoIt" in stage.data[:0x100000] or b"AU3!EA06" in stage.data:
                stage.notes.append("AutoIt-compiled: decompile the script (e.g. with AutoIt-Ripper) and run unmask on it")
        if p.overlay and len(p.overlay) >= 64:
            blobs.append((f"overlay ({len(p.overlay):,} bytes after the last section)", p.overlay))
        for off in _embedded_pe(stage.data):
            blobs.append((f"executable embedded at offset {off:#x}", stage.data[off:]))
        return blobs

    def _zip(self, stage: Stage) -> list[tuple[str, bytes]]:
        out = []
        try:
            z = zipfile.ZipFile(io.BytesIO(stage.data))
        except zipfile.BadZipFile as e:
            stage.notes.append(f"damaged ZIP: {e}")
            return out
        names = [i for i in z.infolist() if not i.is_dir()]
        stage.detail = f"ZIP, {len(names)} file(s)"
        password = None
        for info in names[:200]:
            if info.file_size > layers.MAX_OUTPUT:
                stage.notes.append(f"{info.filename}: too large to open")
                continue
            try:
                data = z.read(info, pwd=password)
            except RuntimeError:                       # encrypted
                data = None
                for pw in ZIP_PASSWORDS:
                    try:
                        data = z.read(info, pwd=pw)
                        password = pw
                        stage.notes.append(f"password-protected; the password is \"{pw.decode()}\"")
                        break
                    except (RuntimeError, zipfile.BadZipFile, ValueError):
                        continue
                if data is None:
                    stage.notes.append(f"{info.filename}: encrypted with an unknown password")
                    continue
            except (zipfile.BadZipFile, NotImplementedError, ValueError, EOFError) as e:
                stage.notes.append(f"{info.filename}: {e}")
                continue
            out.append((info.filename, data))
        return out

    def _resources(self, stage: Stage) -> list[tuple[str, bytes]]:
        try:
            entries = dotnet.read_resources(stage.data)
        except (dotnet.DotNetError, IndexError, ValueError):
            return []
        stage.detail = f".NET resources, {len(entries)} entries"
        return [(f"resource entry {k}", v) for k, v in entries]

    def _script(self, stage: Stage) -> list[tuple[str, bytes]]:
        text = layers.text_of(stage.data) or stage.data.decode("latin-1")
        try:
            result = unwrap(text)
        except ValueError as e:
            stage.notes.append(str(e))
            return []
        texts = [text] + [layer.text for layer in result.layers]
        lang = result.layers[0].language if result.layers else "text"
        stage.kind = "script" if lang != "unknown" else stage.kind
        stage.detail = f"{_LANG.get(lang, lang)} script" + (f", {len(result.layers)} layers peeled"
                                                            if len(result.layers) > 1 else "")
        stage.iocs = _clean(extract(texts))
        stage.urls = [u for u in stage.iocs.get("urls", []) if STAGE_URL.search(u)]
        stage.behaviours = behaviours(texts)
        blobs: list[tuple[str, bytes]] = []
        for layer in result.layers:
            if layer.decoded_by and layer.decoded_by.data:
                blobs.append((f"layer {layer.index + 1}: {layer.decoded_by.detail}", layer.decoded_by.data))
        big = _big_literals(texts)
        decoded_big = [d for d in (layers.b64(c) for c in big) if d]
        for found in layers.aes_hunt(texts, decoded_big):
            blobs.append(("AES-encrypted blob in the script", found.data, found.how))
        for i, chunk in enumerate(big):
            blobs.append((f"encoded blob #{i + 1} in the script ({len(chunk):,} chars)", chunk.encode()))
        if result.layers and len(result.layers) > 1 and not blobs:
            final = result.final
            if final.strip() != text.strip():
                blobs.append(("fully decoded script", final.encode("utf-8")))
        return blobs


_LANG = {"powershell": "PowerShell", "batch": "batch", "vbscript": "VBScript", "javascript": "JavaScript",
         "unknown": "text"}


def _child_name(where: str, kind: str) -> str:
    base = where.split("→")[-1].strip()
    base = re.sub(r"^(resource entry|resource|static array|string literal)\s+", "", base)
    return base[:60] or kind


def _clean(found: dict[str, list[str]]) -> dict[str, list[str]]:
    out = {}
    for k, values in found.items():
        if k in ("urls", "domains", "emails"):
            values = [v for v in values if not NOISE_HOSTS.search(_host_of(v))]
        if k == "paths" or k == "registry":
            continue
        if values:
            out[k] = values
    return out


def _host_of(v: str) -> str:
    m = re.match(r"(?i)\w+://([^/:?#]+)", v)
    return (m.group(1) if m else v.split("@")[-1]).lower()


def _ascii_strings(data: bytes, minimum: int = 6) -> list[str]:
    out = [m.group(0).decode() for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data[:8 * 1024 * 1024])]
    out += [m.group(0).decode("utf-16-le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum,
                                                                     data[:8 * 1024 * 1024])]
    return ['"' + s.replace('"', "") + '"' for s in out]


def _embedded_pe(data: bytes) -> list[int]:
    """Executables carried in plain form inside another (after offset 0, with a valid PE header)."""
    out = []
    for m in re.finditer(rb"MZ", data[2:]):
        off = m.start() + 2
        if pe.is_pe(data[off:off + 0x400]) or (len(data) - off > 0x40 and pe.is_pe(data[off:])):
            out.append(off)
            if len(out) >= 8:
                break
    return out


def _big_literals(texts: list[str]) -> list[str]:
    out, seen = [], set()
    for text in texts:
        for m in re.finditer(r"[A-Za-z0-9+/=\s]{400,}", text):
            chunk = re.sub(r"\s+", "", m.group(0))
            if len(chunk) >= 400 and chunk not in seen:
                seen.add(chunk)
                out.append(chunk)
        # payloads split over comment lines of a batch file (":: <base64>")
        lines = [ln[3:].strip() for ln in text.splitlines() if ln.startswith((":: ", "::")) and len(ln) > 60]
        joined = "".join(lines)
        if len(joined) >= 400 and joined not in seen:
            seen.add(joined)
            out.append(joined)
    return out[:20]


def _decryptor_hints(asm: dotnet.Assembly) -> bool:
    refs = " ".join(asm.member_refs).lower()
    return any(k in refs for k in ("createdecryptor", "gzipstream", "deflatestream", "frombase64string", "::xor"))


def trace(data: bytes, name: str) -> Stage:
    return Tracer().trace(data, name)

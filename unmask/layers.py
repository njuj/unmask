"""Finding the next stage inside a blob: the encodings and ciphers loaders wrap payloads in, tried
breadth-first until something recognisable comes out (an executable, an archive, a script).

XOR keys are not guessed: a Windows executable starts with a DOS header whose first 60 bytes are the
same in nearly every file, so XOR-ing those with the blob gives the key outright, for any key up to
30 bytes, and the rest of the header confirms it."""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib
from collections import deque
from dataclasses import dataclass

from . import aes
from .scripts import detect_language

# the first 60 bytes of the DOS header every mainstream linker writes (e_lfanew follows at 0x3C)
DOS_HEADER = bytes.fromhex("4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000"
                           "000000000000000000000000000000000000000000000000")[:60]

MAGIC = [(b"MZ", "pe"), (b"PK\x03\x04", "zip"), (b"\x1f\x8b\x08", "gzip"), (b"Rar!\x1a\x07", "rar"),
         (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"%PDF", "pdf"),
         (b"MSCF", "cab"), (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"\x7fELF", "elf"),
         (b"\xce\xca\xef\xbe", "resources")]
WANTED = {"pe", "zip", "rar", "7z", "ole", "cab", "lnk", "elf", "script", "resources"}

B64 = re.compile(rb"^\s*={0,2}[A-Za-z0-9+/\s]+={0,2}\s*$")      # padding first when the text is reversed
B64_LITERAL = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX = re.compile(rb"^(?:[0-9a-fA-F]{2}[\s,-]?){16,}$")
BYTE_LIST = re.compile(rb"^\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){15,}\s*$")

MAX_DEPTH = 5
MAX_OUTPUT = 64 * 1024 * 1024


@dataclass
class Found:
    kind: str
    data: bytes
    how: list[str]


def text_of(data: bytes) -> str | None:
    """The text a blob holds, if it is text (UTF-8, UTF-16 with or without BOM)."""
    if not data:
        return None
    sample = data[:4096]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if len(sample) > 8 and sample[1::2].count(0) > len(sample) // 4 and sample[0::2].count(0) < 4:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    ok = sum(c.isprintable() or c in "\r\n\t" for c in text[:4096])
    return text if ok >= 0.95 * min(len(text), 4096) else None


def sniff(data: bytes) -> str:
    for magic, kind in MAGIC:
        if data.startswith(magic):
            if kind == "pe" and len(data) < 0x40:
                return "data"
            return kind
    text = text_of(data)
    if text is None:
        return "data"
    if detect_language(text) != "unknown" or re.search(r"(?im)^\s*@?echo\s+off|<script|\bpowershell\b", text[:20000]):
        return "script"
    return "text"


def _xor(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        k = key[0]
        return bytes(b ^ k for b in data)
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def xor_pe_key(data: bytes) -> bytes | None:
    """Recover a repeating XOR key from the known DOS header; None if the blob is not a XOR'd executable."""
    if len(data) < 0x80:
        return None
    stream = bytes(c ^ p for c, p in zip(data, DOS_HEADER))
    if stream == bytes(len(stream)):
        return None                                   # a plain executable, not an XOR'd one
    for n in range(1, 31):
        key = stream[:n]
        if not all(stream[i] == key[i % n] for i in range(n, len(stream))):
            continue
        lfanew = int.from_bytes(bytes(data[0x3C + i] ^ key[(0x3C + i) % n] for i in range(4)), "little")
        if 0x40 <= lfanew <= len(data) - 4:
            sig = bytes(data[lfanew + i] ^ key[(lfanew + i) % n] for i in range(4))
            if sig == b"PE\0\0":                      # the PE signature where the header says: confirmed
                return key
    return None


def describe_key(key: bytes) -> str:
    shown = key.decode("latin-1")
    if all(32 <= b < 127 for b in key):
        return f'{len(key)}-byte key "{shown}"'
    return f"{len(key)}-byte key 0x{key.hex()}"


def _candidates(data: bytes):
    """(technique, transformed bytes) for every transform that applies to this blob."""
    head = data[:16]
    if head.startswith(b"\x1f\x8b"):
        try:
            yield "gzip", gzip.decompress(data)
        except (OSError, EOFError, zlib.error):
            pass
    if len(data) > 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        try:
            yield "zlib", zlib.decompress(data)
        except zlib.error:
            pass
    stripped = data.strip()
    if 24 <= len(stripped) and B64.match(stripped[:4096]) and B64.match(stripped[-4096:]):
        compact = re.sub(rb"\s+", b"", stripped)
        for label, body in (("base64", compact), ("reversed base64", compact[::-1])):
            try:
                yield label, base64.b64decode(body + b"=" * (-len(body) % 4), validate=True)
            except (binascii.Error, ValueError):
                pass
    if HEX.match(stripped[:4096]) and len(stripped) >= 32:
        try:
            yield "hex", bytes.fromhex(re.sub(rb"[\s,-]", b"", stripped).decode())
        except ValueError:
            pass
    if BYTE_LIST.match(stripped[:4096]):
        try:
            yield "byte list", bytes(int(x, 0) for x in stripped.decode().split(","))
        except ValueError:
            pass
    rev = data[::-1]
    if any(rev.startswith(m) for m, _ in MAGIC[:3]):
        yield "reversed bytes", rev
    key = xor_pe_key(data)
    if key:
        yield f"XOR ({describe_key(key)})", _xor(data, key)
    for magic in (b"\x1f\x8b\x08", b"PK\x03\x04"):
        k = data[0] ^ magic[0] if data else 0
        if k and all(i < len(data) and data[i] ^ k == magic[i] for i in range(len(magic))):
            yield f"XOR (1-byte key 0x{k:02x})", _xor(data, bytes([k]))
    if len(data) >= 64 and sniff(data) == "data":
        try:
            d = zlib.decompressobj(-15)
            out = d.decompress(data, MAX_OUTPUT)
            if d.eof and len(out) > len(data):
                yield "raw deflate", out
        except zlib.error:
            pass


def find(data: bytes, max_depth: int = MAX_DEPTH) -> Found | None:
    """The first recognisable stage reachable from this blob, and how to get there."""
    kind = sniff(data)
    if kind in WANTED:
        return Found(kind, data, [])
    queue = deque([(data, [])])
    seen = {hash(data)}
    while queue:
        blob, how = queue.popleft()
        if len(how) >= max_depth:
            continue
        for technique, out in _candidates(blob):
            if not out or len(out) > MAX_OUTPUT or hash(out) in seen:
                continue
            seen.add(hash(out))
            path = how + [technique]
            kind = sniff(out)
            if kind in WANTED:
                return Found(kind, out, path)
            queue.append((out, path))
    return None


# ── AES with keys found in a script ──────────────────────────────────────────

def b64(s: str) -> bytes | None:
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def literals(texts: list[str]) -> list[bytes]:
    out, seen = [], set()
    for text in texts:
        for m in B64_LITERAL.finditer(text):
            s = m.group(0)
            if s in seen:
                continue
            seen.add(s)
            try:
                out.append(base64.b64decode(s + "=" * (-len(s) % 4), validate=True))
            except (binascii.Error, ValueError):
                pass
    return out


def aes_hunt(texts: list[str], extra_blobs: list[bytes] = ()) -> list[Found]:
    """Loaders decrypt their payload with a key and IV written as Base64 next to it. Try every pairing of
    key-sized and IV-sized literals against every ciphertext-sized one; a correct key shows itself
    through valid padding and a recognisable result."""
    decoded = literals(texts)
    keys = [d for d in decoded if len(d) in (16, 24, 32)][:12]
    ivs = [d for d in decoded if len(d) == 16][:12]
    blobs = sorted({d for d in list(decoded) + list(extra_blobs) if len(d) >= 48 and len(d) % 16 == 0},
                   key=len, reverse=True)[:16]
    found = []
    for blob in blobs:
        hit = None
        for key in keys:
            if blob == key:
                continue
            cipher = aes.AES(key)
            last = cipher.decrypt_block(blob[-16:])
            for iv in ivs + [None]:
                if iv is not None:
                    tail = bytes(a ^ b for a, b in zip(last, blob[-32:-16]))
                    if aes.unpad(b"\0" * 16 + tail) is None:
                        continue
                    plain = aes.decrypt_cbc(key, iv, blob)
                    label = f"AES-{len(key) * 8}-CBC (key and IV from the script)"
                else:
                    if aes.unpad(b"\0" * 16 + last) is None:
                        continue
                    plain = aes.decrypt_ecb(key, blob)
                    label = f"AES-{len(key) * 8}-ECB (key from the script)"
                if plain is None:
                    continue
                result = find(plain)
                if result:
                    hit = Found(result.kind, result.data, [label] + result.how)
                    break
            if hit:
                break
        if hit:
            found.append(hit)
    return found

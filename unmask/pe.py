"""Just enough of the PE format to find what a sample carries: sections, resources, the overlay
after the last section, and the .NET header. Every read is bounds-checked: samples are hostile."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 9: "ACCELERATOR",
            10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST"}


class PEError(ValueError):
    pass


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw: int
    rawsize: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.flags & 0x80000000)


@dataclass
class Resource:
    type: str
    name: str
    lang: int
    data: bytes


@dataclass
class PE:
    data: bytes
    machine: int
    is64: bool
    timestamp: int
    characteristics: int
    sections: list[Section]
    dirs: list[tuple[int, int]]
    overlay_offset: int
    resources: list[Resource] = field(default_factory=list)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    @property
    def is_dotnet(self) -> bool:
        return len(self.dirs) > 14 and self.dirs[14][0] != 0

    @property
    def overlay(self) -> bytes:
        return self.data[self.overlay_offset:] if self.overlay_offset < len(self.data) else b""

    def offset(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rawsize):
                off = rva - s.va
                return s.raw + off if off < s.rawsize else None
        return rva if rva < (self.sections[0].raw if self.sections else len(self.data)) else None

    def read(self, rva: int, size: int) -> bytes:
        off = self.offset(rva)
        if off is None or size < 0 or off + size > len(self.data):
            raise PEError(f"RVA {rva:#x}+{size} is outside the file")
        return self.data[off:off + size]


def _u(fmt: str, data: bytes, off: int):
    try:
        return struct.unpack_from(fmt, data, off)
    except struct.error:
        raise PEError("truncated header") from None


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    return lfanew + 4 <= len(data) and data[lfanew:lfanew + 4] == b"PE\0\0"


def parse(data: bytes) -> PE:
    if not is_pe(data):
        raise PEError("not a PE file")
    lfanew = _u("<I", data, 0x3C)[0]
    machine, nsec, stamp, _, _, opt_size, chars = _u("<HHIIIHH", data, lfanew + 4)
    opt = lfanew + 24
    magic = _u("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise PEError(f"unknown optional header magic {magic:#x}")
    is64 = magic == 0x20B
    ndirs_off = opt + (108 if is64 else 92)
    ndirs = min(_u("<I", data, ndirs_off)[0], 16)
    dirs = [_u("<II", data, ndirs_off + 4 + 8 * i) for i in range(ndirs)]
    sections = []
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        raw_name, vsize, va, rawsize, raw = _u("<8sIIII", data, sec_off + 40 * i)
        flags = _u("<I", data, sec_off + 40 * i + 36)[0]
        name = raw_name.rstrip(b"\0").decode("latin-1")
        sections.append(Section(name, va, vsize, raw, rawsize, flags))
    end = max((s.raw + s.rawsize for s in sections if s.rawsize), default=len(data))
    pe = PE(data, machine, is64, stamp, chars, sections, dirs, min(end, len(data)))
    if len(dirs) > 2 and dirs[2][0]:
        try:
            pe.resources = _resources(pe, dirs[2][0])
        except PEError:
            pass
    return pe


def _resources(pe: PE, base_rva: int) -> list[Resource]:
    base = pe.offset(base_rva)
    if base is None:
        return []
    data, out, seen = pe.data, [], set()

    def label(off_name: int, is_name: bool) -> str:
        if not is_name:
            return str(off_name)
        p = base + off_name
        n = _u("<H", data, p)[0]
        return data[p + 2:p + 2 + 2 * n].decode("utf-16-le", "replace")

    def walk(dir_off: int, path: list, depth: int):
        if depth > 3 or dir_off in seen:
            return
        seen.add(dir_off)
        p = base + dir_off
        named, ids = _u("<HH", data, p + 12)
        for i in range(min(named + ids, 4096)):
            name, target = _u("<II", data, p + 16 + 8 * i)
            key = label(name & 0x7FFFFFFF, bool(name & 0x80000000))
            if target & 0x80000000:
                walk(target & 0x7FFFFFFF, path + [key], depth + 1)
            else:
                rva, size = _u("<II", data, base + target)
                try:
                    blob = pe.read(rva, size)
                except PEError:
                    continue
                kind = path[0] if path else "?"
                kind = RT_NAMES.get(int(kind), kind) if kind.isdigit() else kind
                out.append(Resource(kind, path[1] if len(path) > 1 else "?", int(key) if key.isdigit() else 0, blob))

    walk(0, [], 0)
    return out

"""A .NET metadata reader (ECMA-335) written for hostile files: the tables, the string heaps, the
values a static constructor stores into each field (where RAT builders write their configuration),
embedded resources, and the raw arrays a loader keeps its payload in. Nothing is ever executed."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .pe import PE, PEError

# table id -> (name, columns). Column codes: 1/2/4 fixed size, S/G/B heap index, T<id> table index,
# C<name> coded index.
TABLES = {
    0x00: ("Module", [2, "S", "G", "G", "G"]),
    0x01: ("TypeRef", ["CResolutionScope", "S", "S"]),
    0x02: ("TypeDef", [4, "S", "S", "CTypeDefOrRef", "T4", "T6"]),
    0x03: ("FieldPtr", ["T4"]),
    0x04: ("Field", [2, "S", "B"]),
    0x05: ("MethodPtr", ["T6"]),
    0x06: ("MethodDef", [4, 2, 2, "S", "B", "T8"]),
    0x07: ("ParamPtr", ["T8"]),
    0x08: ("Param", [2, 2, "S"]),
    0x09: ("InterfaceImpl", ["T2", "CTypeDefOrRef"]),
    0x0A: ("MemberRef", ["CMemberRefParent", "S", "B"]),
    0x0B: ("Constant", [1, 1, "CHasConstant", "B"]),
    0x0C: ("CustomAttribute", ["CHasCustomAttribute", "CCustomAttributeType", "B"]),
    0x0D: ("FieldMarshal", ["CHasFieldMarshal", "B"]),
    0x0E: ("DeclSecurity", [2, "CHasDeclSecurity", "B"]),
    0x0F: ("ClassLayout", [2, 4, "T2"]),
    0x10: ("FieldLayout", [4, "T4"]),
    0x11: ("StandAloneSig", ["B"]),
    0x12: ("EventMap", ["T2", "T20"]),
    0x13: ("EventPtr", ["T20"]),
    0x14: ("Event", [2, "S", "CTypeDefOrRef"]),
    0x15: ("PropertyMap", ["T2", "T23"]),
    0x16: ("PropertyPtr", ["T23"]),
    0x17: ("Property", [2, "S", "B"]),
    0x18: ("MethodSemantics", [2, "T6", "CHasSemantics"]),
    0x19: ("MethodImpl", ["T2", "CMethodDefOrRef", "CMethodDefOrRef"]),
    0x1A: ("ModuleRef", ["S"]),
    0x1B: ("TypeSpec", ["B"]),
    0x1C: ("ImplMap", [2, "CMemberForwarded", "S", "T26"]),
    0x1D: ("FieldRVA", [4, "T4"]),
    0x1E: ("EncLog", [4, 4]),
    0x1F: ("EncMap", [4]),
    0x20: ("Assembly", [4, 2, 2, 2, 2, 4, "B", "S", "S"]),
    0x21: ("AssemblyProcessor", [4]),
    0x22: ("AssemblyOS", [4, 4, 4]),
    0x23: ("AssemblyRef", [2, 2, 2, 2, 4, "B", "S", "S", "B"]),
    0x24: ("AssemblyRefProcessor", [4, "T35"]),
    0x25: ("AssemblyRefOS", [4, 4, 4, "T35"]),
    0x26: ("File", [4, "S", "B"]),
    0x27: ("ExportedType", [4, 4, "S", "S", "CImplementation"]),
    0x28: ("ManifestResource", [4, 4, "S", "CImplementation"]),
    0x29: ("NestedClass", ["T2", "T2"]),
    0x2A: ("GenericParam", [2, 2, "CTypeOrMethodDef", "S"]),
    0x2B: ("MethodSpec", ["CMethodDefOrRef", "B"]),
    0x2C: ("GenericParamConstraint", ["T42", "CTypeDefOrRef"]),
}

CODED = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasCustomAttribute": (5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B,
                               0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [None, None, 0x06, 0x0A, None]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}

# operand sizes of IL opcodes (anything not listed takes none); -1: switch
_OP1 = {0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1, 0x1F: 1, 0x20: 4, 0x21: 8, 0x22: 4, 0x23: 8, 0x27: 4,
        0x28: 4, 0x29: 4, 0x45: -1, 0x6F: 4, 0x70: 4, 0x71: 4, 0x72: 4, 0x73: 4, 0x74: 4, 0x75: 4, 0x79: 4, 0x7B: 4,
        0x7C: 4, 0x7D: 4, 0x7E: 4, 0x7F: 4, 0x80: 4, 0x81: 4, 0x8C: 4, 0x8D: 4, 0x8F: 4, 0xA3: 4, 0xA4: 4, 0xA5: 4,
        0xC2: 4, 0xC6: 4, 0xD0: 4, 0xDD: 4, 0xDE: 1}
_OP1.update({op: 1 for op in range(0x2B, 0x38)})
_OP1.update({op: 4 for op in range(0x38, 0x45)})
_OP2 = {0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2, 0x12: 1, 0x15: 4, 0x16: 4, 0x19: 1,
        0x1C: 4}
LDSTR, STSFLD, CALL, CALLVIRT, NEWOBJ = 0x72, 0x80, 0x28, 0x6F, 0x73


class DotNetError(ValueError):
    pass


@dataclass
class Instr:
    offset: int
    op: int                        # one-byte opcode, or 0xFE00 | second byte
    arg: int | None


@dataclass
class TypeInfo:
    namespace: str
    name: str
    fields: list[str]
    field_rows: list[int]
    methods: list[int]                                   # MethodDef rows
    values: dict[str, object] = field(default_factory=dict)   # what the static constructor stores
    via: dict[str, str] = field(default_factory=dict)         # field -> method the literal went through first

    @property
    def full(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name


@dataclass
class Blob:
    origin: str                    # where it was found, for the report
    data: bytes


@dataclass
class Assembly:
    name: str
    version: str
    types: list[TypeInfo]
    user_strings: list[str]
    names: list[str]               # every identifier in #Strings
    member_refs: list[str]         # methods it calls in other assemblies: "Type::Method"
    resources: list[Blob]
    arrays: list[Blob]             # static byte arrays (FieldRVA)
    entry: str | None


def _cuint(data: bytes, off: int) -> tuple[int, int]:
    """ECMA-335 compressed unsigned integer -> (value, bytes used)."""
    b = data[off]
    if b & 0x80 == 0:
        return b, 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | data[off + 1], 2
    if b & 0xE0 == 0xC0:
        return ((b & 0x1F) << 24) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3], 4
    raise DotNetError("bad compressed integer")


def _7bit(data: bytes, off: int) -> tuple[int, int]:
    """.NET BinaryWriter 7-bit encoded int -> (value, new offset)."""
    value = shift = 0
    for _ in range(5):
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, off
        shift += 7
    raise DotNetError("bad 7-bit integer")


def il(code: bytes) -> list[Instr]:
    out, i = [], 0
    while i < len(code):
        start, op = i, code[i]
        i += 1
        if op == 0xFE and i < len(code):
            op = 0xFE00 | code[i]
            i += 1
            size = _OP2.get(op & 0xFF, 0)
        else:
            size = _OP1.get(op, 0)
        if size == -1:
            if i + 4 > len(code):
                break
            n = struct.unpack_from("<I", code, i)[0]
            size = 4 + 4 * min(n, 1 << 20)
        arg = None
        if size and i + size <= len(code):
            arg = int.from_bytes(code[i:i + min(size, 8)], "little", signed=size in (1, 8) and op in (0x1F, 0x21))
        elif size:
            break
        out.append(Instr(start, op, arg))
        i += size
    return out


def _ldc(ins: Instr) -> int | None:
    if 0x15 <= ins.op <= 0x1E:
        return ins.op - 0x16
    if ins.op in (0x1F, 0x20):
        v = ins.arg or 0
        return v - (1 << 32) if ins.op == 0x20 and v >= 1 << 31 else v
    return None


class Metadata:
    def __init__(self, pe: PE):
        if not pe.is_dotnet:
            raise DotNetError("not a .NET assembly")
        self.pe = pe
        try:
            cli = pe.read(pe.dirs[14][0], 72)
        except PEError as e:
            raise DotNetError(f"CLI header unreadable: {e}") from None
        md_rva, md_size = struct.unpack_from("<II", cli, 8)
        self.entry_token = struct.unpack_from("<I", cli, 20)[0]
        self.res_rva, self.res_size = struct.unpack_from("<II", cli, 24)
        try:
            md = pe.read(md_rva, md_size)
        except PEError as e:
            raise DotNetError(f"metadata unreadable: {e}") from None
        if md[:4] != b"BSJB":
            raise DotNetError("metadata signature missing")
        vlen = struct.unpack_from("<I", md, 12)[0]
        p = 16 + vlen
        nstreams = struct.unpack_from("<H", md, p + 2)[0]
        p += 4
        self.streams: dict[str, bytes] = {}
        for _ in range(min(nstreams, 16)):
            off, size = struct.unpack_from("<II", md, p)
            end = md.index(b"\0", p + 8)
            name = md[p + 8:end].decode("latin-1")
            p = (end + 4) & ~3
            if name not in self.streams:              # a duplicate stream is an obfuscator trick: the CLR uses the first
                self.streams[name] = md[off:off + size]
        tables = self.streams.get("#~") or self.streams.get("#-")
        if tables is None:
            raise DotNetError("no metadata tables")
        self.strings_heap = self.streams.get("#Strings", b"")
        self.us_heap = self.streams.get("#US", b"")
        self.blob_heap = self.streams.get("#Blob", b"")
        self.rows: dict[int, list[tuple]] = {}
        self._tables(tables)

    # ── heaps ────────────────────────────────────────────────────────────
    def string(self, idx: int) -> str:
        h = self.strings_heap
        if not 0 <= idx < len(h):
            return ""
        end = h.find(b"\0", idx)
        return h[idx:end if end >= 0 else len(h)].decode("utf-8", "replace")

    def blob(self, idx: int) -> bytes:
        h = self.blob_heap
        try:
            n, used = _cuint(h, idx)
        except (IndexError, DotNetError):
            return b""
        return h[idx + used:idx + used + n]

    def user_string(self, idx: int) -> str | None:
        h = self.us_heap
        try:
            n, used = _cuint(h, idx)
        except (IndexError, DotNetError):
            return None
        raw = h[idx + used:idx + used + max(n - 1, 0)]
        return raw.decode("utf-16-le", "replace")

    def all_user_strings(self) -> list[str]:
        out, h, i = [], self.us_heap, 1
        while i < len(h):
            try:
                n, used = _cuint(h, i)
            except (IndexError, DotNetError):
                break
            if n > 1:
                out.append(h[i + used:i + used + n - 1].decode("utf-16-le", "replace"))
            i += used + max(n, 1)
        return out

    # ── tables ───────────────────────────────────────────────────────────
    def _tables(self, t: bytes) -> None:
        heap_sizes = t[6]
        valid = struct.unpack_from("<Q", t, 8)[0]
        p = 24
        counts = {}
        for tid in range(64):
            if valid >> tid & 1:
                counts[tid] = struct.unpack_from("<I", t, p)[0]
                p += 4
        if heap_sizes & 0x40:
            p += 4                                     # "extra data" flag some obfuscators set
        sizes = {"S": 4 if heap_sizes & 1 else 2, "G": 4 if heap_sizes & 2 else 2, "B": 4 if heap_sizes & 4 else 2}

        def col_size(c) -> int:
            if isinstance(c, int):
                return c
            if c in sizes:
                return sizes[c]
            if c[0] == "T":
                return 2 if counts.get(int(c[1:]), 0) < 1 << 16 else 4
            bits, targets = CODED[c[1:]]
            most = max((counts.get(x, 0) for x in targets if x is not None), default=0)
            return 2 if most < 1 << (16 - bits) else 4

        for tid in sorted(counts):
            if tid not in TABLES:
                raise DotNetError(f"unknown metadata table {tid:#x}")
            cols = [col_size(c) for c in TABLES[tid][1]]
            width = sum(cols)
            if p + width * counts[tid] > len(t):          # a forged row count: refuse before looping over it
                raise DotNetError(f"table {TABLES[tid][0]} claims {counts[tid]:,} rows, more than the stream holds")
            rows = []
            for r in range(counts[tid]):
                vals, q = [], p + r * width
                for size in cols:
                    vals.append(int.from_bytes(t[q:q + size], "little"))
                    q += size
                rows.append(tuple(vals))
            self.rows[tid] = rows
            p += width * counts[tid]
            if p > len(t):
                raise DotNetError("metadata tables are truncated")

    def coded(self, kind: str, value: int) -> tuple[int | None, int]:
        bits, targets = CODED[kind]
        tag = value & ((1 << bits) - 1)
        return (targets[tag] if tag < len(targets) else None), value >> bits

    def method_body(self, rva: int) -> bytes | None:
        if not rva:
            return None
        try:
            head = self.pe.read(rva, 1)[0]
            if head & 3 == 2:
                return self.pe.read(rva + 1, head >> 2)
            if head & 3 == 3:
                flags_size, _, code_size = struct.unpack("<HHI", self.pe.read(rva, 8))
                return self.pe.read(rva + (flags_size >> 12) * 4, code_size)
        except PEError:
            return None
        return None

    def type_name(self, tid: int | None, row: int) -> str:
        r = self.rows.get(tid, [])
        if not 1 <= row <= len(r):
            return "?"
        if tid == 0x01:
            ns, name = self.string(r[row - 1][2]), self.string(r[row - 1][1])
        elif tid == 0x02:
            ns, name = self.string(r[row - 1][2]), self.string(r[row - 1][1])
        else:
            return "?"
        return f"{ns}.{name}" if ns else name

    # ── what the tool needs ──────────────────────────────────────────────
    def read(self) -> Assembly:
        typedefs = self.rows.get(0x02, [])
        fields = self.rows.get(0x04, [])
        methods = self.rows.get(0x06, [])
        types: list[TypeInfo] = []
        for i, row in enumerate(typedefs):
            f_end = typedefs[i + 1][4] if i + 1 < len(typedefs) else len(fields) + 1
            m_end = typedefs[i + 1][5] if i + 1 < len(typedefs) else len(methods) + 1
            f_rows = list(range(row[4], max(row[4], f_end)))
            m_rows = list(range(row[5], max(row[5], m_end)))
            names = [self.string(fields[f - 1][1]) for f in f_rows if 1 <= f <= len(fields)]
            types.append(TypeInfo(self.string(row[2]), self.string(row[1]), names, f_rows, m_rows))

        field_owner = {f: t for t in types for f in t.field_rows}
        field_name = {f: self.string(fields[f - 1][1]) for f in range(1, len(fields) + 1)}
        method_name = {m: self.string(methods[m - 1][3]) for m in range(1, len(methods) + 1)}
        member_refs = self._member_refs()

        # the static constructor of each type: literals stored into its fields
        for t in types:
            for m in t.methods:
                if not 1 <= m <= len(methods) or method_name.get(m) != ".cctor":
                    continue
                self._initialisers(methods[m - 1][0], field_owner, field_name, method_name, member_refs)

        entry = None
        if self.entry_token >> 24 == 0x06:
            row = self.entry_token & 0xFFFFFF
            owner = next((t for t in types if row in t.methods), None)
            entry = f"{owner.full}::{method_name.get(row, '?')}" if owner else method_name.get(row)

        asm_rows = self.rows.get(0x20, [])
        name, version = "", ""
        if asm_rows:
            a = asm_rows[0]
            name, version = self.string(a[7]), f"{a[1]}.{a[2]}.{a[3]}.{a[4]}"
        elif self.rows.get(0x00):
            name = self.string(self.rows[0x00][0][1])

        idents = sorted({s for s in self.strings_heap.decode("utf-8", "replace").split("\0") if s})
        return Assembly(name, version, types, self.all_user_strings(), idents, sorted(set(member_refs.values())),
                        self._resources(), self._arrays(), entry)

    def _member_refs(self) -> dict[int, str]:
        out = {}
        for i, (parent, name, _) in enumerate(self.rows.get(0x0A, []), 1):
            tid, row = self.coded("MemberRefParent", parent)
            out[i] = f"{self.type_name(tid, row)}::{self.string(name)}"
        return out

    def _initialisers(self, rva, field_owner, field_name, method_name, member_refs) -> None:
        body = self.method_body(rva)
        if not body:
            return
        pending: object = None
        through: str | None = None
        for ins in il(body):
            value = _ldc(ins)
            if ins.op == LDSTR and ins.arg is not None and ins.arg >> 24 == 0x70:
                pending, through = self.user_string(ins.arg & 0xFFFFFF), None
            elif value is not None:
                pending, through = value, None
            elif ins.op in (CALL, CALLVIRT) and pending is not None and ins.arg:
                table, row = ins.arg >> 24, ins.arg & 0xFFFFFF
                callee = method_name.get(row) if table == 0x06 else member_refs.get(row) if table == 0x0A else None
                through = through or callee
            elif ins.op == STSFLD and ins.arg and ins.arg >> 24 == 0x04:
                row = ins.arg & 0xFFFFFF
                owner = field_owner.get(row)
                if owner is not None and pending is not None:
                    owner.values.setdefault(field_name[row], pending)
                    if through:
                        owner.via.setdefault(field_name[row], through)
                pending, through = None, None
            elif ins.op in (0x2A, 0x26):                  # ret, pop: the literal went nowhere
                pending, through = None, None

    def _resources(self) -> list[Blob]:
        out = []
        for offset, _, name, impl in self.rows.get(0x28, []):
            if impl:                                          # lives in another file
                continue
            try:
                head = self.pe.read(self.res_rva + offset, 4)
                size = struct.unpack("<I", head)[0]
                data = self.pe.read(self.res_rva + offset + 4, size)
            except PEError:
                continue
            out.append(Blob(f"resource {self.string(name)}", data))   # .resources files are opened as a stage
        return out

    def _arrays(self) -> list[Blob]:
        fields = self.rows.get(0x04, [])
        layouts = {row[2]: row[1] for row in self.rows.get(0x0F, [])}   # TypeDef row -> class size
        out = []
        for rva, frow in self.rows.get(0x1D, []):
            if not 1 <= frow <= len(fields):
                continue
            sig = self.blob(fields[frow - 1][2])
            size = None
            if len(sig) >= 3 and sig[0] == 0x06 and sig[1] == 0x11:
                try:
                    coded, _ = _cuint(sig, 2)
                except (IndexError, DotNetError):
                    continue
                tid, row = self.coded("TypeDefOrRef", coded)
                size = layouts.get(row) if tid == 0x02 else None
            if size and size >= 32:
                try:
                    out.append(Blob(f"static array {self.string(fields[frow - 1][1])}", self.pe.read(rva, size)))
                except PEError:
                    pass
        return out


def read_resources(data: bytes) -> list[tuple[str, bytes]]:
    """The entries of a .resources file (System.Resources.ResourceReader format): byte arrays, streams and
    strings as bytes; other serialized objects (images) as their raw bytes, where loaders also hide payloads."""
    magic, header_version, skip = struct.unpack_from("<III", data, 0)
    if magic != 0xBEEFCACE:
        raise DotNetError("not a .resources file")
    p = 12
    if header_version > 1:
        p += skip
    else:
        for _ in range(2):
            n, p = _7bit(data, p)
            p += n
    version, count, ntypes = struct.unpack_from("<iii", data, p)
    if not 0 <= count <= len(data) // 8 or not 0 <= ntypes <= len(data):
        raise DotNetError("forged resource count")
    p += 12
    for _ in range(min(ntypes, 4096)):
        n, p = _7bit(data, p)
        p += n
    p += (8 - p % 8) % 8                                       # "PAD" alignment
    p += 4 * count                                             # name hashes
    positions = struct.unpack_from(f"<{count}i", data, p)
    p += 4 * count
    data_section = struct.unpack_from("<i", data, p)[0]
    names_start = p + 4
    entries = []
    for pos in positions:
        q = names_start + pos
        n, q = _7bit(data, q)
        name = data[q:q + n].decode("utf-16-le", "replace")
        offset = struct.unpack_from("<i", data, q + n)[0]
        entries.append((name, data_section + offset))
    ordered = sorted(o for _, o in entries)
    out = []
    for name, start in entries:
        nxt = next((o for o in ordered if o > start), len(data))
        if version == 1:
            out.append((name, data[start:nxt]))
            continue
        code, q = _7bit(data, start)
        if code == 1:                                          # string
            n, q = _7bit(data, q)
            out.append((name, data[q:q + n]))
        elif code in (0x20, 0x21):                             # byte[] / stream
            n = struct.unpack_from("<i", data, q)[0]
            out.append((name, data[q + 4:q + 4 + n]))
        elif code >= 0x40:                                     # a serialized object (Bitmap and the like)
            out.append((name, data[q:nxt]))
    return out


def read_assembly(pe: PE) -> Assembly:
    try:
        return Metadata(pe).read()
    except (struct.error, IndexError, ValueError) as e:
        raise DotNetError(f"unreadable .NET metadata: {e}") from None

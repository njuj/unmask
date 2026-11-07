"""unmask: follow a malware delivery chain to the RAT at its end and extract who controls it.
Exit codes: 0 no RAT configuration found · 1 configuration found · 2 could not run."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__, providers, report
from .trace import Tracer

MAX_INPUT = 200 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="unmask",
        description="Unwrap a malware sample stage by stage (bait, loader, payload) without running it, and extract "
                    "the RAT configuration at the end: C2 hosts and ports, keys, mutex, install paths, Telegram bot. "
                    "Decodes njRAT and XWorm; recognises the AsyncRAT family.")
    ap.add_argument("files", nargs="+", type=Path, help="samples, or folders of samples")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--iocs", metavar="FILE", help="write C2s, next-stage URLs and hashes, one per line")
    ap.add_argument("--yara", metavar="FILE", help="write a YARA rule for every configuration found")
    ap.add_argument("--dump", metavar="DIR", help="save every extracted stage (as .bin) for further analysis")
    ap.add_argument("--lookup", action="store_true",
                    help="look up the abuse contact of each C2 in the public RDAP registries (asks the registry, "
                         "never the C2)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _files(paths: list[Path]) -> list[Path]:
    out = []
    for p in paths:
        if p.is_dir():
            out += sorted(f for f in p.rglob("*") if f.is_file())
        else:
            out.append(p)
    return out


def _console_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _console_utf8()
    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if color and os.name == "nt":
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x4)
    files = _files(args.files)
    if not files:
        print("unmask: no files to analyse", file=sys.stderr)
        return 2
    found_any, iocs, rules, chunks = False, [], [], []
    for path in files:
        try:
            if path.stat().st_size > MAX_INPUT:
                print(f"unmask: {path}: larger than {MAX_INPUT // 2**20} MB, skipped", file=sys.stderr)
                continue
            data = path.read_bytes()
        except OSError as e:
            print(f"unmask: {path}: {e.strerror or e}", file=sys.stderr)
            return 2
        started = time.time()
        root = Tracer().trace(data, path.name)
        elapsed = time.time() - started
        lookup = {}
        if args.lookup:
            for host, _, _ in report.c2_list(root):
                contact = providers.rdap_abuse(host)
                if contact:
                    lookup[host] = contact
        found_any |= any(s.config for s in report.stages(root))
        if args.json:
            chunks.append(report.to_json(root, elapsed, lookup))
        else:
            print(report.render(root, elapsed, color, lookup))
            if len(files) > 1:
                print()
        iocs.append(report.ioc_list(root))
        rules.append(report.yara_rules(root))
        if args.dump:
            out = Path(args.dump)
            out.mkdir(parents=True, exist_ok=True)
            for i, s in enumerate(report.stages(root)):
                (out / f"{i + 1:02d}_{s.sha256[:16]}_{s.kind}.bin").write_bytes(s.data)
    if args.json:
        print(chunks[0] if len(chunks) == 1 else "[\n" + ",\n".join(chunks) + "\n]")
    if args.iocs:
        Path(args.iocs).write_text("\n".join(iocs), encoding="utf-8")
    if args.yara:
        Path(args.yara).write_text("\n".join(r for r in rules if r), encoding="utf-8")
    return 1 if found_any else 0

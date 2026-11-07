"""Whole delivery chains, built in memory around the compiled samples, followed end to end; and the
command line on files.

Script-based loaders (batch, PowerShell, VBScript) are peeled by the vendored unwrap engine, which
has its own test suite; their key search is tested here on neutral text. Loader-shaped script
fixtures are not kept in this repository: antivirus engines quarantine them on sight."""

import base64
import gzip
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from unmask import aes, report  # noqa: E402
from unmask.trace import trace  # noqa: E402
from tests.fixtures import values  # noqa: E402

BIN = ROOT / "tests" / "fixtures" / "bin"
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def sample(name: str) -> bytes:
    return (BIN / f"{name}.exe").read_bytes()


def zip_of(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def overlay_carrier() -> bytes:
    """The bait with XWorm appended after its last section: gzip, Base64, reversed."""
    return sample("bait_booster") + base64.b64encode(gzip.compress(sample("xworm_v5")))[::-1]


def configs(root):
    return {s.config.family: s.config for s in report.stages(root) if s.config}


class Chains(unittest.TestCase):
    def test_bait_resource_xor_njrat(self):
        root = trace(sample("bait_booster"), "FpsBooster.exe")
        chain = report.stages(root)
        self.assertEqual([s.kind for s in chain], ["pe", "resources", "pe"])
        self.assertEqual(chain[2].how, ['XOR (12-byte key "kira-unmask!")'])
        self.assertEqual(configs(root)["njRAT"].c2, [("kira-lab-c2.ddns.net", "5552")])

    def test_overlay_reversed_base64_gzip_xworm(self):
        root = trace(overlay_carrier(), "carrier.exe")
        xw = next(s for s in report.stages(root) if s.config and s.config.family == "XWorm")
        self.assertIn("overlay", xw.origin)
        self.assertEqual(xw.how, ["reversed base64", "gzip"])
        self.assertEqual(xw.config.telegram[0], values.TELEGRAM_TOKEN)

    def test_zip_holding_two_chains(self):
        root = trace(zip_of({"FpsBooster.exe": sample("bait_booster"), "readme/carrier.exe": overlay_carrier()}),
                     "download.zip")
        found = configs(root)
        self.assertEqual(set(found), {"njRAT", "XWorm"})
        self.assertEqual(root.detail, "ZIP, 2 file(s)")

    def test_base64_text_holding_a_zip(self):
        text = b"-----BEGIN-----\n" + base64.encodebytes(zip_of({"a.exe": sample("njrat_lime")})) + b"-----END-----\n"
        root = trace(text, "notes.txt")
        self.assertEqual(configs(root)["njRAT"].c2, [("203.0.113.77", "1177")])

    def test_aes_sealed_payload_in_text(self):
        r = random.Random(9)
        key, iv = r.randbytes(32), r.randbytes(16)
        blob = aes.encrypt_cbc(key, iv, gzip.compress(sample("xworm_obfuscated")))
        text = (f"key = '{base64.b64encode(key).decode()}'\niv = '{base64.b64encode(iv).decode()}'\n"
                f"data = '{base64.b64encode(blob).decode()}'\n").encode()
        root = trace(text, "stage.txt")
        xw = next(s for s in report.stages(root) if s.config)
        self.assertEqual(xw.how[0], "AES-256-CBC (key and IV from the script)")
        self.assertEqual(xw.config.c2, [("4.tcp.eu.ngrok.io", "13377")])

    def test_next_stage_on_a_server_is_reported_not_fetched(self):
        url = "https://cdn.discordapp.com/attachments/1300000000000000000/1300000000000000001/update.txt"
        root = trace(f"next = '{url}'\n".encode(), "stage1.txt")
        self.assertEqual(root.urls, [url])
        text = report.render(root, 0.1, color=False)
        self.assertIn("hxxps://cdn[.]discordapp[.]com", text)
        self.assertIn("not downloaded", text)
        self.assertIn("Discord", text)

    def test_duplicate_payloads_are_traced_once(self):
        exe = sample("njrat_07d")
        root = trace(zip_of({"a.exe": exe, "b.exe": exe}), "dup.zip")
        self.assertEqual(sum(1 for s in report.stages(root) if s.config), 1)
        self.assertEqual(sum(1 for s in root.walk() if s.duplicate_of), 1)

    def test_clean_input(self):
        root = trace(random.Random(5).randbytes(20000), "noise.bin")
        self.assertEqual(report.stages(root), [root])
        self.assertIsNone(root.config)


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "unmask", "--no-color", *args], cwd=ROOT, env=ENV,
                              capture_output=True, text=True, encoding="utf-8")

    def test_report_and_exit_codes(self):
        r = self.run_cli(str(BIN / "bait_booster.exe"))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("✖ njRAT 0.7d configuration", r.stdout)
        self.assertIn("TAKE IT DOWN", r.stdout)
        self.assertIn("No-IP · dynamic DNS", r.stdout)
        with tempfile.TemporaryDirectory() as d:
            clean = Path(d, "clean.bin")
            clean.write_bytes(b"nothing here " * 100)
            self.assertEqual(self.run_cli(str(clean)).returncode, 0)
        self.assertEqual(self.run_cli("does-not-exist.exe").returncode, 2)

    def test_json_iocs_yara_and_dump(self):
        with tempfile.TemporaryDirectory() as d:
            iocs, yar, dump = Path(d, "iocs.txt"), Path(d, "rules.yar"), Path(d, "stages")
            r = self.run_cli(str(BIN / "xworm_v5.exe"), "--json", "--iocs", str(iocs), "--yara", str(yar),
                             "--dump", str(dump))
            self.assertEqual(r.returncode, 1, r.stderr)
            doc = json.loads(r.stdout)
            cfg = doc["chain"]["config"]
            self.assertEqual(cfg["family"], "XWorm")
            self.assertEqual(cfg["c2"][0], ["kira-lab-c2.duckdns.org", "7000"])
            self.assertEqual(doc["takedown"][0]["provider"], "Duck DNS")
            listed = iocs.read_text(encoding="utf-8")
            self.assertIn("kira-lab-c2.duckdns.org:7000", listed)
            self.assertIn(doc["chain"]["sha256"], listed)
            self.assertEqual(len(list(dump.iterdir())), 1)
            # every string of the YARA rule is really in the sample, as UTF-16 like the #US heap stores it
            rule = yar.read_text(encoding="utf-8")
            data = sample("xworm_v5")
            strings = [line.split('"')[1] for line in rule.splitlines() if line.strip().startswith("$s")]
            self.assertGreaterEqual(len(strings), 3)
            for s in strings:
                self.assertIn(s.encode("utf-16-le"), data, s)

    def test_folder_input(self):
        r = self.run_cli(str(BIN))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.count("configuration  ·  stage"), 5)    # 2 njRAT, 2 XWorm, 1 via the bait


@unittest.skipUnless(sys.platform == "win32" and shutil.which("powershell"), "rebuilding needs Windows' csc.exe")
class Rebuilt(unittest.TestCase):
    """The committed samples rebuilt from source with today's compiler must give the same answers."""

    def test_fresh_build_matches(self):
        csc = Path(os.environ.get("WINDIR", "C:/Windows"), "Microsoft.NET/Framework64/v4.0.30319/csc.exe")
        if not csc.exists():
            self.skipTest("csc.exe not installed")
        with tempfile.TemporaryDirectory() as d:
            subprocess.run([sys.executable, str(ROOT / "tests" / "fixtures" / "build.py"), d], check=True,
                           cwd=ROOT, env=ENV, capture_output=True)
            for name, family, c2 in (("njrat_07d", "njRAT", ("kira-lab-c2.ddns.net", "5552")),
                                     ("xworm_v5", "XWorm", ("kira-lab-c2.duckdns.org", "7000")),
                                     ("xworm_obfuscated", "XWorm", ("4.tcp.eu.ngrok.io", "13377"))):
                root = trace(Path(d, f"{name}.exe").read_bytes(), name)
                self.assertEqual(root.config.family, family)
                self.assertEqual(root.config.c2[0], c2)
            bait = trace(Path(d, "bait_booster.exe").read_bytes(), "bait")
            self.assertIn("njRAT", configs(bait))


if __name__ == "__main__":
    unittest.main()

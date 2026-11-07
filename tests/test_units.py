"""The building blocks, each against a known answer: AES against FIPS-197, the .NET reader against
binaries from the real C# compiler, the extractors against the configurations baked into them."""

import base64
import gzip
import os
import random
import sys
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from unmask import aes, dotnet, families, layers, pe, providers  # noqa: E402
from unmask.report import defang  # noqa: E402
from unmask.trace import trace  # noqa: E402
from tests.fixtures import values  # noqa: E402

BIN = ROOT / "tests" / "fixtures" / "bin"


def sample(name: str) -> bytes:
    return (BIN / f"{name}.exe").read_bytes()


def assembly(name: str) -> dotnet.Assembly:
    return dotnet.read_assembly(pe.parse(sample(name)))


class AESTest(unittest.TestCase):
    PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")

    def test_fips197_vectors(self):
        for size, expected in ((16, "69c4e0d86a7b0430d8cdb78070b4c55a"), (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
                               (32, "8ea2b7ca516745bfeafc49904b496089")):
            cipher = aes.AES(bytes(range(size)))
            self.assertEqual(cipher.encrypt_block(self.PLAIN).hex(), expected)
            self.assertEqual(cipher.decrypt_block(bytes.fromhex(expected)), self.PLAIN)

    def test_modes_round_trip_and_reject_wrong_keys(self):
        r = random.Random(7)
        key, iv, data = r.randbytes(32), r.randbytes(16), r.randbytes(1000)
        self.assertEqual(aes.decrypt_cbc(key, iv, aes.encrypt_cbc(key, iv, data)), data)
        self.assertEqual(aes.decrypt_ecb(key, aes.encrypt_ecb(key, data)), data)
        wrong = [aes.decrypt_ecb(r.randbytes(32), aes.encrypt_ecb(key, data)) for _ in range(20)]
        self.assertLessEqual(sum(w is not None for w in wrong), 2)      # padding gives a wrong key away


class LayersTest(unittest.TestCase):
    def setUp(self):
        self.exe = sample("njrat_07d")

    def test_xor_keys_are_recovered_from_the_dos_header(self):
        for key in (b"\x5a", b"k1r4", b"kira-unmask!", os.urandom(30)):
            blob = bytes(b ^ key[i % len(key)] for i, b in enumerate(self.exe))
            found = layers.find(blob)
            self.assertIsNotNone(found, key)
            self.assertEqual(found.data, self.exe)
            self.assertIn(f"{len(key)}-byte key", found.how[0])

    def test_encodings_chain(self):
        gz = gzip.compress(self.exe)
        cases = {
            "base64 > gzip": base64.b64encode(gz),
            "reversed base64 > gzip": base64.b64encode(gz)[::-1],
            "hex": self.exe.hex().encode(),
            "byte list": ",".join(map(str, self.exe)).encode(),
            "raw deflate": zlib.compress(self.exe)[2:-4],
            "1-byte XOR over gzip": bytes(b ^ 0x37 for b in gz),
            "reversed bytes": self.exe[::-1],
        }
        for label, blob in cases.items():
            with self.subTest(label):
                found = layers.find(blob)
                self.assertIsNotNone(found)
                self.assertEqual(found.data, self.exe)

    def test_noise_is_not_a_payload(self):
        r = random.Random(1)
        for _ in range(30):
            self.assertIsNone(layers.find(r.randbytes(r.randint(100, 5000))))

    def test_aes_key_and_iv_found_next_to_the_ciphertext(self):
        r = random.Random(3)
        key, iv = r.randbytes(32), r.randbytes(16)
        blob = aes.encrypt_cbc(key, iv, gzip.compress(self.exe))
        text = (f"config key = {base64.b64encode(key).decode()}\n"
                f"config iv = {base64.b64encode(iv).decode()}\n"
                f"payload = {base64.b64encode(blob).decode()}\n")
        found = layers.aes_hunt([text])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].data, self.exe)
        self.assertEqual(found[0].how, ["AES-256-CBC (key and IV from the script)", "gzip"])


class DotNetTest(unittest.TestCase):
    def test_static_constructor_values(self):
        a = assembly("njrat_07d")
        ok = next(t for t in a.types if t.name == "OK")
        for k, v in values.NJRAT.items():
            self.assertEqual(ok.values[k], int(v) if isinstance(v, bool) else v, k)
        self.assertEqual(a.entry, "j.OK::Main")

    def test_resources_written_by_dotnet_itself(self):
        a = assembly("bait_booster")
        res = next(b for b in a.resources if b.origin.endswith(".resources"))
        entries = dict(dotnet.read_resources(res.data))
        self.assertEqual(entries["Title"], b"FPS Booster")
        hidden = entries["icon_data"]
        key = values.BAIT_KEY
        self.assertEqual(bytes(b ^ key[i % len(key)] for i, b in enumerate(hidden)), sample("njrat_07d"))

    def test_member_references(self):
        refs = assembly("xworm_v5").member_refs
        self.assertIn("System.Convert::FromBase64String", refs)


class ExtractorTest(unittest.TestCase):
    def items(self, cfg):
        return {i.label: i.value for i in cfg.items}

    def test_njrat_07d(self):
        cfg = families.extract(assembly("njrat_07d"))
        self.assertEqual((cfg.family, cfg.version), ("njRAT", "0.7d"))
        self.assertEqual(cfg.c2, [("kira-lab-c2.ddns.net", "5552")])
        items = self.items(cfg)
        self.assertEqual(items["Victim name / campaign"], "HacKed")
        self.assertEqual(items["Separator"], "|'|'|")
        self.assertEqual(items["Installed as"], "Windows Update.exe")
        self.assertEqual(items["Run-key persistence"], "yes")

    def test_njrat_lime_base64_host(self):
        cfg = families.extract(assembly("njrat_lime"))
        self.assertEqual(cfg.c2, [("203.0.113.77", "1177")])
        self.assertEqual(self.items(cfg)["Separator"], "@!#&^%$")
        self.assertEqual(self.items(cfg)["Victim name / campaign"], "LimeGroup")

    def test_xworm_v5_every_field(self):
        cfg = families.extract(assembly("xworm_v5"))
        self.assertEqual((cfg.family, cfg.version), ("XWorm", "5.6"))
        self.assertEqual(cfg.c2, [("kira-lab-c2.duckdns.org", "7000"), ("198.51.100.23", "7000")])
        self.assertEqual(cfg.telegram, (values.TELEGRAM_TOKEN, values.TELEGRAM_CHAT))
        items = self.items(cfg)
        for label, key in (("Encryption key", "KEY"), ("Separator", "SPL"), ("Mutex", "Mutex"),
                           ("Install folder", "InstallDir"), ("Installed as", "InstallStr"),
                           ("USB spreader name", "USBNM"), ("Keylogger file", "LoggerPath"),
                           ("Group / build", "Groub")):
            self.assertEqual(items[label], values.XWORM[key], label)
        self.assertIn('MD5(mutex "q8R2vT6yN4kP1mXw")', cfg.key_note)

    def test_xworm_with_obfuscated_names(self):
        cfg = families.extract(assembly("xworm_obfuscated"))
        self.assertTrue(cfg.renamed)
        self.assertEqual(cfg.c2, [("4.tcp.eu.ngrok.io", "13377")])
        items = self.items(cfg)
        self.assertEqual(items["Installed as"], "RuntimeBroker.exe")
        self.assertEqual(items["USB spreader name"], "USB.exe")
        self.assertEqual(items["Encryption key"], "<666777888>")
        self.assertEqual(items["Telegram"], "not used")
        self.assertIsNone(cfg.telegram)

    def test_a_plain_assembly_has_no_config(self):
        self.assertIsNone(families.extract(assembly("bait_booster")))


class ProviderTest(unittest.TestCase):
    def test_classification(self):
        cases = {"x.duckdns.org": "Duck DNS", "a.b.ddns.net": "No-IP", "4.tcp.eu.ngrok.io": "ngrok",
                 "cdn.discordapp.com": "Discord", "raw.githubusercontent.com": "GitHub",
                 "203.0.113.5": "reserved range", "10.1.2.3": "private network", "45.88.10.20": "hosting network"}
        for host, provider in cases.items():
            self.assertEqual(providers.classify(host).provider, provider, host)
        self.assertIsNone(providers.classify("example-shop.com"))

    def test_rdap_abuse_contact_parsing(self):
        rdap = {"entities": [{"roles": ["registrant"], "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                          ["email", {}, "text", "abuse@host.example"]]]}]}]}
        self.assertEqual(providers._abuse_email(rdap["entities"]), "abuse@host.example")

    def test_defang(self):
        self.assertEqual(defang("evil.duckdns.org"), "evil[.]duckdns[.]org")
        self.assertEqual(defang("https://cdn.discordapp.com/a/b.exe"), "hxxps://cdn[.]discordapp[.]com/a/b.exe")


class RobustnessTest(unittest.TestCase):
    """Samples are hostile: a damaged or booby-trapped file must give a report, never a crash."""

    def test_mutated_samples_never_crash(self):
        r = random.Random(2026)
        bases = [sample(n) for n in ("njrat_07d", "xworm_v5", "bait_booster")]
        for i in range(600):
            data = bytearray(r.choice(bases))
            for _ in range(r.randint(1, 40)):
                data[r.randrange(len(data))] = r.randrange(256)
            if r.random() < 0.3:
                data = data[:r.randrange(64, len(data))]
            try:
                trace(bytes(data), f"mutant{i}")
            except Exception as e:              # noqa: BLE001 - any crash is the failure being tested for
                self.fail(f"mutant {i} crashed the tracer: {type(e).__name__}: {e}")


if __name__ == "__main__":
    unittest.main()

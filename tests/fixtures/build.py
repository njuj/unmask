"""Builds the test samples with the real C# compiler (Windows' csc.exe) and .NET's own ResourceWriter.

The samples are inert: classes holding a configuration in the exact layout njRAT and XWorm builders
write (field names, encodings, AES scheme), a Main that does nothing, and a "bait" that only carries
a resource. No networking, no persistence, nothing that runs a payload. The binaries are committed so
the tests run everywhere; on Windows CI they are rebuilt from this script and the tests run again.

Usage: python tests/fixtures/build.py [out_dir]"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from unmask.aes import encrypt_cbc, encrypt_ecb  # noqa: E402
from tests.fixtures.values import (NJRAT, NJRAT_LIME, XWORM, XWORM_OBF, BAIT_KEY, ASYNCRAT, ASYNCRAT_KEY,  # noqa: E402
                                   DCRAT_OBF, DCRAT_KEY)

CSC = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe"


def xworm_key(mutex: str) -> bytes:
    h = hashlib.md5(mutex.encode()).digest()
    return h[:15] + h + b"\0"


def xworm_enc(mutex: str, value: str) -> str:
    return base64.b64encode(encrypt_ecb(xworm_key(mutex), value.encode())).decode()


def cs_str(s: str) -> str:
    out = []
    for ch in s:
        if ch in '"' or ord(ch) == 92 or ord(ch) < 32 or ord(ch) > 126:
            out.append(chr(92) + "u" + f"{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def njrat_source(cfg: dict, ns: str) -> str:
    fields = "\n".join(
        f"        public static bool {k} = {str(v).lower()};" if isinstance(v, bool)
        else f"        public static string {k} = {cs_str(v)};" for k, v in cfg.items())
    return f"""using System;
namespace {ns}
{{
    public class OK
    {{
{fields}
        public static void Main() {{ }}
    }}
}}
"""


def xworm_source(cfg: dict, names: dict, decrypt_name: str) -> str:
    mutex = cfg["Mutex"]
    lines = []
    for key, value in cfg.items():
        name = names.get(key, key)
        if key == "Mutex":
            lines.append(f"        public static string {name} = {cs_str(value)};")
        elif key == "Sleep":
            lines.append(f"        public static int {name} = {value};")
        else:
            lines.append(f"        public static string {name} = {cs_str(xworm_enc(mutex, value))};")
    mutex_name = names.get("Mutex", "Mutex")
    return f"""using System;
using System.Security.Cryptography;
using System.Text;
namespace Stub
{{
    public static class Settings
    {{
{chr(10).join(lines)}
    }}
    public static class AlgorithmAES
    {{
        public static string {decrypt_name}(string input)
        {{
            RijndaelManaged aes = new RijndaelManaged();
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            byte[] key = new byte[32];
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(Settings.{mutex_name}));
            Array.Copy(hash, 0, key, 0, 16);
            Array.Copy(hash, 0, key, 15, 16);
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            byte[] data = Convert.FromBase64String(input);
            return Encoding.UTF8.GetString(aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length));
        }}
    }}
    public static class Program
    {{
        public static void Main() {{ }}
    }}
}}
"""


ASYNC_SALT = bytes.fromhex("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941")


def async_enc(password: str, salt: bytes, value: str, n: int) -> str:
    """AsyncRAT's Aes256.Encrypt: HMAC-SHA256 | IV | AES-256-CBC, keys from PBKDF2-SHA1(password, salt, 50,000)."""
    keys = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 50000, 96)
    iv = hashlib.md5(f"iv{n}".encode()).digest()                   # fixed IVs: the build is reproducible
    body = iv + encrypt_cbc(keys[:32], iv, value.encode())
    return base64.b64encode(hmac.new(keys[32:], body, hashlib.sha256).digest() + body).decode()


def der_name_only(cn: str) -> bytes:
    """Not a full certificate: just the DER Name an X.509 issuer and subject hold, which is all unmask reads."""
    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag, len(body)]) + body
    name = tlv(0x30, tlv(0x31, tlv(0x30, b"\x06\x03\x55\x04\x03" + tlv(0x0C, cn.encode()))))
    return tlv(0x30, name + name)


def asyncrat_source(cfg: dict, key_b64: str, salt_cs: str, names: dict, cn: str) -> str:
    password = base64.b64decode(key_b64).decode()
    salt = ASYNC_SALT if "0xBF" in salt_cs else salt_cs.split('"')[1].encode()
    values = dict(cfg)
    values["Certificate"] = base64.b64encode(der_name_only(cn)).decode()
    values["Serversignature"] = base64.b64encode(hashlib.sha256(cn.encode()).digest() * 4).decode()
    lines = [f"        public static string {names.get(k, k)} = {cs_str(async_enc(password, salt, v, i))};"
             for i, (k, v) in enumerate(values.items())]
    lines.append(f"        public static string {names.get('Key', 'Key')} = {cs_str(key_b64)};")
    return f"""using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace Client
{{
    public static class Settings
    {{
{chr(10).join(lines)}
    }}
    public class Aes256
    {{
        private static readonly byte[] Salt = {salt_cs};
        private readonly byte[] _key;
        private readonly byte[] _authKey;
        public Aes256(string masterKey)
        {{
            using (Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(masterKey, Salt, 50000))
            {{
                _key = derive.GetBytes(32);
                _authKey = derive.GetBytes(64);
            }}
        }}
        public string Decrypt(string input)
        {{
            byte[] data = Convert.FromBase64String(input);
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {{
                aes.Key = _key;
                byte[] iv = new byte[16];
                Array.Copy(data, 32, iv, 0, 16);
                aes.IV = iv;
                return Encoding.UTF8.GetString(aes.CreateDecryptor().TransformFinalBlock(data, 48, data.Length - 48));
            }}
        }}
    }}
    public static class Program
    {{
        public static void Main() {{ }}
    }}
}}
"""


BAIT = """using System;
using System.Reflection;
namespace FpsBooster
{
    public static class Program
    {
        // the bait only carries its resources; it never reads or runs them
        public static void Main()
        {
            Console.WriteLine("FPS Booster 2.1 - optimizing...");
        }
    }
}
"""


def compile_cs(source: str, out: Path, resources: list[Path] = ()) -> None:
    with tempfile.TemporaryDirectory() as d:
        src = Path(d, "src.cs")
        src.write_text(source, encoding="utf-8")
        args = [str(CSC), "/nologo", "/optimize+", "/target:exe", "/platform:anycpu", f"/out:{out}", str(src)]
        args += [f"/resource:{r}" for r in resources]
        r = subprocess.run(args, capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f"csc failed for {out.name}:\n{r.stdout}{r.stderr}")


def write_resources(path: Path, entries: dict[str, bytes]) -> None:
    """A real .resources file, written by .NET's own ResourceWriter."""
    with tempfile.TemporaryDirectory() as d:
        blobs = []
        for i, (name, data) in enumerate(entries.items()):
            p = Path(d, f"{i}.bin")
            p.write_bytes(data)
            blobs.append(f"$w.AddResource('{name}', [IO.File]::ReadAllBytes('{p}'))")
        script = (f"$w = New-Object System.Resources.ResourceWriter('{path}'); "
                  + "; ".join(blobs) + "; $w.AddResource('Title', 'FPS Booster'); $w.Generate(); $w.Close()")
        subprocess.run(["powershell", "-NoProfile", "-Command", script], check=True)


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    compile_cs(njrat_source(NJRAT, "j"), out / "njrat_07d.exe")
    compile_cs(njrat_source(NJRAT_LIME, "Lime"), out / "njrat_lime.exe")
    compile_cs(xworm_source(XWORM, {}, "Decrypt"), out / "xworm_v5.exe")
    compile_cs(xworm_source(XWORM_OBF, {k: f"x{i:02d}" for i, k in enumerate(XWORM_OBF)}, "a"),
               out / "xworm_obfuscated.exe")
    compile_cs(asyncrat_source(ASYNCRAT, ASYNCRAT_KEY, "new byte[] { 0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B, 0xB2, 0x19, 0x02, 0x24, 0x30, 0xA5, 0x78, 0x43, 0x00, 0x3D, 0x56, 0x44, 0xD2, 0x1E, 0x62, 0xB9, 0xD4, 0xF1, 0x80, 0xE7, 0xE6, 0xC3, 0x39, 0x41 }", {}, "AsyncRAT Server"), out / "asyncrat.exe")
    compile_cs(asyncrat_source(DCRAT_OBF, DCRAT_KEY, 'Encoding.ASCII.GetBytes("DcRatByqwqdanchun")',
                               {k: f"c{i:02d}" for i, k in enumerate(list(DCRAT_OBF) + ["Certificate", "Serversignature", "Key"])},
                               "DcRat Server"), out / "dcrat_obfuscated.exe")
    # the bait: a "booster" whose .resources hide the njRAT stub, XOR'd with a 12-byte key
    payload = (out / "njrat_07d.exe").read_bytes()
    hidden = bytes(b ^ BAIT_KEY[i % len(BAIT_KEY)] for i, b in enumerate(payload))
    with tempfile.TemporaryDirectory() as d:
        res = Path(d, "FpsBooster.Properties.Resources.resources")
        write_resources(res, {"icon_data": hidden})
        compile_cs(BAIT, out / "bait_booster.exe", [res])
    for f in sorted(out.glob("*.exe")):
        print(f"{f.name:24} {f.stat().st_size:>7,} bytes  {hashlib.sha256(f.read_bytes()).hexdigest()[:16]}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "bin")

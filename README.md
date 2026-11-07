# unmask

**Follow a malware delivery chain to the RAT at its end, and find out who controls it.**

Most RAT infections today are not one file. A fake game cheat or "FPS booster" carries a loader;
the loader hides an encrypted payload in a resource, an overlay or a script; the payload is XWorm or
njRAT. `unmask` opens each stage, peels off whatever wraps the next one, and keeps going until it
reaches the RAT, then decrypts its configuration the way the RAT itself does at start-up.

It never runs the sample, never downloads a stage from the attacker's server, and never connects to a C2.

```
$ unmask FpsBooster_v2.1.zip

 CHAIN
 ① FpsBooster_v2.1.zip  ZIP, 2 file(s)
    └─② FpsBooster.exe  .NET exe, assembly "bait_booster"
       └─③ FpsBooster.Properties.Resources.resources  .NET resources, 2 entries
          └─④ icon_data  .NET exe  ✖ njRAT 0.7d
               from resource entry icon_data  ·  XOR (12-byte key "kira-unmask!")
    └─⑤ tools/Updater.exe  .NET exe, assembly "bait_booster"
       └─⑥ overlay (3,116 bytes after the last section)  .NET exe  ✖ XWorm 5.6
            from overlay  ·  reversed base64  →  gzip

 ✖ XWorm 5.6 configuration  ·  stage ⑥, class Stub.Settings
   decrypted with AES-256-ECB, key = MD5(mutex "q8R2vT6yN4kP1mXw") as XWorm derives it
   C2                               kira-lab-c2.duckdns.org:7000  Duck DNS · dynamic DNS
   Encryption key                   <123456789>
   Separator                        <Xwormmm>
   Mutex                            q8R2vT6yN4kP1mXw
   Install folder                   %AppData%
   Installed as                     XClient.exe
   USB spreader name                USB.exe
   Telegram bot token               7310452291:AAH…
   Telegram chat ID                 5207741936

 TAKE IT DOWN  ·  report these and the attacker loses every victim at once
   kira-lab-c2[.]ddns[.]net:5552  No-IP · dynamic DNS  →  noip.com abuse report
   kira-lab-c2[.]duckdns[.]org:7000  Duck DNS · dynamic DNS  →  duckdns.org
   Telegram bot 7310452291  →  abuse@telegram.org
```

(The output above is from the repository's own test samples: lab host names and a made-up token.)

## What it opens

| Stage | How |
|---|---|
| .NET executables | its own ECMA-335 metadata reader: every table, the string heaps, the IL of static constructors (where builders write the config), manifest resources, `.resources` files (byte arrays, streams, serialized images), static byte arrays |
| Native executables | resources, the overlay after the last section, executables embedded in plain form |
| ZIP | every file; password-protected ZIPs are tried with the usual "infected", "1234"… |
| Scripts | batch, PowerShell, VBScript, JavaScript peeled layer by layer by the [unwrap](https://github.com/njuj/unwrap) engine (vendored) |
| Wrappers | Base64 (also reversed), hex, byte lists, gzip, zlib, raw deflate, reversed bytes |
| XOR | **any repeating key up to 30 bytes, recovered outright**: a Windows executable's first 60 bytes are nearly always the same DOS header, so XOR-ing them with the blob *is* the key, and the PE signature where the header points confirms it |
| AES | loaders keep the key and IV as Base64 next to the ciphertext; every key-sized and IV-sized literal is tried against every ciphertext-sized one, CBC and ECB, and a right key shows itself through valid padding and a recognisable result |

A stage that sits on a server (a Discord attachment, a raw GitHub file, a paste) is reported as a URL
with its provider and **not fetched**: downloading it can tip off the attacker, and the right move is
to have it removed.

## RAT configurations

| Family | What comes out |
|---|---|
| **njRAT** (0.7d and the 0.7NC / Lime-style editions) | C2 host and port (also when Base64-encoded), victim name / campaign, version, separator, install name and folder, registry key, BSOD-on-kill, install / Startup-folder / Run-key flags |
| **XWorm** (the AES-MD5(mutex) scheme of 3.x–5.x) | every field decrypted: C2 hosts, port, encryption key, separator, group, mutex, install folder and name, USB spreader name, keylogger file, sleep, Telegram bot token and chat ID (or "not used"), pastebin-mode C2 URL |
| AsyncRAT, DcRat | recognised and reported; decryption comes in a later version |

**Obfuscated builds still work.** When an obfuscator renames the `Settings` fields, the mutex is
found among the plain-text values by trying each as the key, and every decrypted value is
recognised by its shape (a host, a port, `<digits>` for the key, `<letters>` for the separator, a
`%folder%`, a `.exe`), so the result is the same as for a clean build.

## Taking it down

For every C2, `unmask` says who runs the infrastructure and where to report it: dynamic DNS
(Duck DNS, No-IP, Dynu, FreeDNS, dynv6), tunnels (ngrok, playit.gg, portmap.io, Cloudflare Tunnel…),
file and paste hosts (Discord, GitHub, Pastebin, catbox…). Reporting a dynamic-DNS name or a tunnel
cuts the attacker off from every victim at once. `--lookup` asks the public RDAP registries for the
abuse contact of an IP's network or a domain's registrar (the registry, never the C2).

The Telegram bot is reported by its ID. **Do not use an attacker's token yourself**: it is
someone else's account, and taking it over is unauthorised access even when the owner is a criminal.
The same goes for connecting to a C2. Report, block, share.

## Use

```
unmask sample.exe                          # the chain and every configuration
unmask suspicious/                         # every file in a folder
unmask sample.exe --json                   # machine-readable
unmask sample.exe --iocs iocs.txt          # C2s, next-stage URLs and stage hashes, one per line
unmask sample.exe --yara rules.yar         # a YARA rule per configuration, from the strings as stored
unmask sample.exe --dump stages/           # save every extracted stage for further analysis
unmask sample.exe --lookup                 # abuse contacts from RDAP
```

Exit codes: `0` no RAT configuration found, `1` configuration found, `2` could not run.

```
pip install git+https://github.com/njuj/unmask
```

or just `python -m unmask` from a clone. Python 3.10+, no dependencies.

## Handle samples safely

Analyse real samples in a virtual machine or a dedicated analysis box. Your antivirus will (rightly)
quarantine them as soon as they touch disk. `unmask` only reads bytes, but the files it reads are
live malware.

## Tests

Samples are built with the real C# compiler and .NET's own `ResourceWriter`: inert classes holding a
configuration in exactly the layout njRAT and XWorm builders write (field names, encodings, the
AES-MD5(mutex) scheme), including an XWorm build with every field and method renamed, and a "booster"
bait carrying njRAT XOR'd in its resources. The binaries are committed with their source; on Windows CI
they are rebuilt from source and checked again. No live malware is in this repository or was used to
build it, so new builder versions that change the layout need a sample to confirm; issues welcome.

The tests cover AES against the FIPS-197 vectors, XOR key recovery up to 30 bytes, every wrapper, AES key
search, whole chains (bait → resources → XOR → njRAT, overlay → reversed Base64 → gzip → XWorm, ZIPs of
chains, Base64 text holding a ZIP, AES-sealed payloads), the command line, YARA rules checked against the
bytes they describe, and **600 randomly damaged samples**, which caught a forged metadata row count that
would have hung the parser (a trick malware uses against analysis tools).

Loader-shaped script fixtures are deliberately not kept here: antivirus engines quarantine them, and a
test suite should not ship a working loader. Script peeling is covered by unwrap's own tests.

```
python -m unittest discover -s tests -t . -v
```

## License

MIT

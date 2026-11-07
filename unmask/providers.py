"""Who runs the infrastructure a sample points at, and where to report it so it is taken down.
Taking the attacker's host or bot away is the response; nothing here ever connects to it."""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from dataclasses import dataclass

# (suffixes, provider, category, where to report)
PROVIDERS = [
    (("duckdns.org",), "Duck DNS", "dynamic DNS", "duckdns.org (report the subdomain to the operator)"),
    (("ddns.net", "hopto.org", "zapto.org", "sytes.net", "servehttp.com", "serveftp.com", "myftp.biz", "myftp.org",
      "no-ip.org", "no-ip.biz", "no-ip.info", "redirectme.net", "servegame.com", "myvnc.com", "bounceme.net",
      "servebeer.com", "gotdns.ch", "serveirc.com", "servemp3.com", "servepics.com", "servequake.com",
      "sytes.org"),
     "No-IP", "dynamic DNS", "noip.com abuse report"),
    (("dynu.net", "dynu.com", "freeddns.org", "mywire.org", "giize.com", "gleeze.com", "kozow.com",
      "loseyourip.com", "ooguy.com", "theworkpc.com", "casacam.net", "accesscam.org", "camdvr.org"),
     "Dynu", "dynamic DNS", "dynu.com abuse report"),
    (("mooo.com", "chickenkiller.com", "us.to", "strangled.net", "twilightparadox.com", "crabdance.com",
      "jumpingcrab.com", "ignorelist.com", "afraid.org"), "FreeDNS (afraid.org)", "dynamic DNS",
     "freedns.afraid.org abuse report"),
    (("dynv6.net", "v6.rocks"), "dynv6", "dynamic DNS", "dynv6.com abuse report"),
    (("ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok-free.dev", "ngrok.dev"), "ngrok", "tunnel",
     "ngrok.com/abuse"),
    (("playit.gg", "ply.gg", "joinmc.link"), "playit.gg", "tunnel", "playit.gg support / abuse report"),
    (("portmap.io", "portmap.host"), "portmap.io", "tunnel", "portmap.io abuse report"),
    (("localto.net",), "LocalToNet", "tunnel", "localtonet.com abuse report"),
    (("pinggy.link", "pinggy.io", "pinggy.online"), "Pinggy", "tunnel", "pinggy.io abuse report"),
    (("serveo.net",), "Serveo", "tunnel", "serveo.net operator"),
    (("bore.pub",), "bore", "tunnel", "bore.pub operator"),
    (("loca.lt",), "localtunnel", "tunnel", "localtunnel operator"),
    (("trycloudflare.com",), "Cloudflare Tunnel", "tunnel", "abuse.cloudflare.com"),
    (("cdn.discordapp.com", "media.discordapp.net", "discord.com", "discordapp.com"), "Discord", "file hosting",
     "Discord Trust & Safety (dis.gd/report)"),
    (("raw.githubusercontent.com", "github.com", "objects.githubusercontent.com", "gist.githubusercontent.com",
      "githubusercontent.com"), "GitHub", "file hosting", "github.com/contact/report-abuse"),
    (("gitlab.com",), "GitLab", "file hosting", "GitLab abuse report"),
    (("bitbucket.org",), "Bitbucket", "file hosting", "Atlassian abuse report"),
    (("pastebin.com",), "Pastebin", "paste site", "the paste's own Report button"),
    (("paste.ee",), "paste.ee", "paste site", "paste.ee abuse report"),
    (("rentry.co", "rentry.org"), "Rentry", "paste site", "rentry abuse report"),
    (("transfer.sh",), "transfer.sh", "file hosting", "transfer.sh operator"),
    (("catbox.moe",), "Catbox", "file hosting", "catbox.moe abuse report"),
    (("dropbox.com", "dropboxusercontent.com"), "Dropbox", "file hosting", "Dropbox abuse report"),
    (("drive.google.com", "docs.google.com", "drive.usercontent.google.com"), "Google Drive", "file hosting",
     "Google Drive abuse report"),
    (("firebasestorage.googleapis.com",), "Firebase Storage", "file hosting", "Google abuse report"),
    (("mega.nz", "mega.co.nz"), "MEGA", "file hosting", "mega.nz abuse report"),
    (("0x0.st",), "0x0.st", "file hosting", "0x0.st operator"),
    (("archive.org",), "Internet Archive", "file hosting", "archive.org abuse report"),
    (("t.me", "api.telegram.org", "telegram.org"), "Telegram", "messaging", "abuse@telegram.org"),
]


@dataclass
class Owner:
    provider: str
    category: str
    report: str


def classify(host: str) -> Owner | None:
    h = host.lower().rstrip(".")
    for suffixes, provider, category, report in PROVIDERS:
        if any(h == s or h.endswith("." + s) for s in suffixes):
            return Owner(provider, category, report)
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return None
    if ip.version == 4 and _documentation(ip) or ip.is_reserved:
        return Owner("reserved range", "documentation address", "nothing to report: a test value")
    if ip.is_private or ip.is_loopback:
        return Owner("private network", "local address", "nothing to report: the C2 is on the attacker's own LAN "
                                                         "or a test machine")
    return Owner("hosting network", "IP address", "the network's abuse contact (--lookup fetches it from RDAP)")


def _documentation(ip) -> bool:
    return any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def rdap_abuse(target: str, timeout: float = 10) -> str | None:
    """The abuse e-mail registered for an IP's network or a domain's registrar, from the public RDAP
    registries (rdap.org redirects to the right one). Asks the registry, never the host itself."""
    try:
        ipaddress.ip_address(target)
        url = f"https://rdap.org/ip/{target}"
    except ValueError:
        parts = target.lower().rstrip(".").split(".")
        url = f"https://rdap.org/domain/{'.'.join(parts[-2:])}"
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json", "User-Agent": "unmask"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except (OSError, ValueError):
        return None
    return _abuse_email(data.get("entities", []))


def _abuse_email(entities: list) -> str | None:
    for e in entities:
        if "abuse" in (e.get("roles") or []):
            for item in (e.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "email":
                    return item[3]
        found = _abuse_email(e.get("entities", []))
        if found:
            return found
    return None

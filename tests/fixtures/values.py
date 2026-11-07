"""The configurations baked into the test samples, and what unmask must recover from them.
Hosts use reserved documentation addresses and lab names; the Telegram token is assembled from parts
so no token-shaped string sits in the repository."""

# njRAT 0.7d: the builder's field names, victim name in base64, the classic separator
NJRAT = {
    "VN": "SGFjS2Vk",                       # "HacKed"
    "VR": "0.7d",
    "H": "kira-lab-c2.ddns.net",
    "P": "5552",
    "EXE": "Windows Update.exe",
    "DR": "TEMP",
    "RG": "5cd8f17f4086744065eb0992a09e05a2",
    "Y": "|'|'|",
    "BD": False,
    "Idr": True,
    "IsF": False,
    "Isu": True,
}

# a "Lime" edition: the host and victim name in base64, its own separator
NJRAT_LIME = {
    "VN": "TGltZUdyb3Vw",                   # "LimeGroup"
    "VR": "0.7NC",
    "H": "MjAzLjAuMTEzLjc3",                # "203.0.113.77"
    "P": "1177",
    "EXE": "svchost.exe",
    "DR": "AppData",
    "RG": "ce2b8d5a1c7f",
    "Y": "@!#&^%$",
    "BD": True,
    "Idr": True,
    "IsF": True,
    "Isu": False,
}

TELEGRAM_TOKEN = "7310452291" + ":" + "AAH" + "kQ3x9vLmZt2pRb8YwNc5" + "JfUe4DsKo1Gi7"
TELEGRAM_CHAT = "5207741936"

# XWorm 5.x: every value AES-encrypted with a key derived from the plain Mutex
XWORM = {
    "Hosts": "kira-lab-c2.duckdns.org,198.51.100.23",
    "Port": "7000",
    "KEY": "<123456789>",
    "SPL": "<Xwormmm>",
    "Sleep": 3,
    "Groub": "XWorm V5.6",
    "USBNM": "USB.exe",
    "InstallDir": "%AppData%",
    "InstallStr": "XClient.exe",
    "Mutex": "q8R2vT6yN4kP1mXw",
    "LoggerPath": "\\Log.tmp",
    "ChatID": TELEGRAM_CHAT,
    "Token": TELEGRAM_TOKEN,
}

# the same family after an obfuscator renamed every field and the decrypt method; a tunnel host, no Telegram
XWORM_OBF = {
    "Hosts": "4.tcp.eu.ngrok.io",
    "Port": "13377",
    "KEY": "<666777888>",
    "SPL": "<Xwormmm>",
    "Sleep": 1,
    "Groub": "XWorm V3.1",
    "USBNM": "USB.exe",
    "InstallDir": "%Temp%",
    "InstallStr": "RuntimeBroker.exe",
    "Mutex": "zW7cK2pL9sQ4dF1h",
    "LoggerPath": "\\Log.tmp",
}

BAIT_KEY = b"kira-unmask!"

"""The script deobfuscator from unwrap (github.com/njuj/unwrap, same author, MIT), vendored so unmask
stays a single zero-dependency install: PowerShell, batch, VBScript and JavaScript peeled layer by layer."""

from .engine import Result, detect_language, unwrap
from .indicators import behaviours, defang, extract

__all__ = ["Result", "behaviours", "defang", "detect_language", "extract", "unwrap"]

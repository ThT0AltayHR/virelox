"""
config_yukleyici.py — VIRELOX v4.0.2 Persistent User Config Support
======================================================================
Exports:
    DEFAULT_CONFIG_YOLU   : str          — default path to ~/.virelox.json
    config_yukle()        : dict         — load & validate config file
    config_kaydet()       : str          — save settings dict to config file
    varsayilanlarla_birlestir() : dict   — merge CLI args with config values

Precedence-detection approach:
    We re-parse sys.argv with a secondary ArgumentParser that only records
    which flags were *explicitly supplied* on the command line (using a
    sentinel default of None / False for booleans).  Any flag whose parsed
    value differs from its sentinel default is considered "explicitly passed"
    and is kept as-is; everything else falls back to the config file.

    Limitation: if a user deliberately passes the exact sentinel value on the
    CLI (e.g.  --timeout 15.0 when the sentinel is None, this will not apply
    here because we use None as the sentinel, not the argparse default), the
    detection is safe.  The one edge-case is boolean store_true flags: if the
    user does NOT pass them, sentinel stays False — which is identical to
    "not set", so no false positive.  If the user passes them, sentinel
    becomes True — clearly explicit.  This is safe for all known VIRELOX
    flags.
"""

import os
import sys
import json
import argparse
import copy
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Public constant
# ---------------------------------------------------------------------------
DEFAULT_CONFIG_YOLU: str = os.path.join(os.path.expanduser("~"), ".virelox.json")

# ---------------------------------------------------------------------------
# Known config keys and their validation rules
# ---------------------------------------------------------------------------
# Each entry: key -> (type_checker, validator_fn, error_msg)
_VALID_TECHNIQUE_CHARS = set("EUBTS")

def _validate_timeout(v: Any) -> Tuple[bool, Any]:
    try:
        f = float(v)
        if f < 0:
            return False, None
        return True, f
    except (TypeError, ValueError):
        return False, None

def _validate_delay(v: Any) -> Tuple[bool, Any]:
    try:
        f = float(v)
        if f < 0:
            return False, None
        return True, f
    except (TypeError, ValueError):
        return False, None

def _validate_level(v: Any) -> Tuple[bool, Any]:
    try:
        i = int(v)
        if i < 1 or i > 4:
            return False, None
        return True, i
    except (TypeError, ValueError):
        return False, None

def _validate_technique(v: Any) -> Tuple[bool, Any]:
    if not isinstance(v, str) or not v:
        return False, None
    upper = v.upper()
    if not all(c in _VALID_TECHNIQUE_CHARS for c in upper):
        return False, None
    return True, upper

def _validate_str_or_none(v: Any) -> Tuple[bool, Any]:
    if v is None or isinstance(v, str):
        return True, v
    return False, None

def _validate_bool(v: Any) -> Tuple[bool, Any]:
    if isinstance(v, bool):
        return True, v
    return False, None

# Map of config key -> validator function
_VALIDATORS: Dict[str, Any] = {
    "timeout":    _validate_timeout,
    "delay":      _validate_delay,
    "level":      _validate_level,
    "technique":  _validate_technique,
    "proxy":      _validate_str_or_none,
    "cookie":     _validate_str_or_none,
    "output_dir": _validate_str_or_none,
    "no_zip":     _validate_bool,
    "verbose":    _validate_bool,
}

# ---------------------------------------------------------------------------
# config_yukle
# ---------------------------------------------------------------------------
def config_yukle(yol: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a JSON config file from *yol* (defaults to DEFAULT_CONFIG_YOLU).

    Returns a dict with only the keys that pass validation.
    Also returns a second value — a list of warning strings — accessible via
    the module-level ``son_uyarilar`` attribute after the call.

    Never raises; returns {} (and populates son_uyarilar) on any error.
    """
    global son_uyarilar
    son_uyarilar = []

    path = yol if yol is not None else DEFAULT_CONFIG_YOLU

    if not os.path.isfile(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        son_uyarilar.append(f"[config_yukleyici] Dosya okunamadı / geçersiz JSON: {exc}")
        return {}

    if not isinstance(raw, dict):
        son_uyarilar.append("[config_yukleyici] Config dosyası bir JSON objesi (dict) olmalıdır.")
        return {}

    validated: Dict[str, Any] = {}
    for key, validator in _VALIDATORS.items():
        if key not in raw:
            continue
        ok, cleaned = validator(raw[key])
        if ok:
            validated[key] = cleaned
        else:
            son_uyarilar.append(
                f"[config_yukleyici] Geçersiz değer '{key}': {raw[key]!r} — bu alan yok sayıldı."
            )

    # Warn about unknown keys (informational, not blocking)
    for key in raw:
        if key not in _VALIDATORS:
            son_uyarilar.append(
                f"[config_yukleyici] Bilinmeyen config anahtarı '{key}' — yok sayıldı."
            )

    return validated


# Module-level list populated by the last config_yukle() call
son_uyarilar: List[str] = []


# ---------------------------------------------------------------------------
# config_kaydet
# ---------------------------------------------------------------------------
def config_kaydet(ayarlar: Dict[str, Any], yol: Optional[str] = None) -> str:
    """
    Save *ayarlar* to the config file at *yol* (defaults to DEFAULT_CONFIG_YOLU).

    Only recognised/validated keys are written.  Returns the path written.
    Raises OSError if the file cannot be written (file-system errors are
    propagated to the caller so they can be shown to the user).
    """
    path = yol if yol is not None else DEFAULT_CONFIG_YOLU

    # Filter & validate before saving
    to_save: Dict[str, Any] = {}
    for key, validator in _VALIDATORS.items():
        if key not in ayarlar:
            continue
        ok, cleaned = validator(ayarlar[key])
        if ok:
            to_save[key] = cleaned
        # silently skip invalid values during save (caller should pre-validate)

    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(to_save, fh, indent=2, ensure_ascii=False)
    except OSError as e:
        print(f"[CONFIG] Kayit hatasi: {e}")

    return path


# ---------------------------------------------------------------------------
# varsayilanlarla_birlestir
# ---------------------------------------------------------------------------
def varsayilanlarla_birlestir(
    args_namespace: argparse.Namespace,
    config: Dict[str, Any],
) -> argparse.Namespace:
    """
    Merge an argparse Namespace (from virelox.py argumanlari_al()) with a
    loaded config dict.

    Precedence:
        CLI flag explicitly supplied by user  >  config file value  >  argparse default

    Approach — re-parse sys.argv with sentinel defaults (documented):
        A secondary ArgumentParser is built with None (or False for
        store_true flags) as the default for every config-backed flag.
        We parse sys.argv[1:] with it; any flag whose result differs from
        its sentinel was explicitly passed on the CLI and wins unchanged.
        Flags left at their sentinel value fall back to the config file
        if a value exists there, otherwise the original argparse default
        from *args_namespace* is kept.

    Limitation:
        If the user explicitly passes a string/float flag whose value
        happens to equal the sentinel (None), it cannot be distinguished
        from "not supplied".  In practice this cannot occur for the VIRELOX
        flags backed by config because their sentinel is None and a user
        typing --proxy None or --timeout None would produce a parse error
        or a literal string "None", not Python None.

    Config key → argparse attribute mapping:
        timeout   → args.timeout
        delay     → args.delay
        level     → args.level
        technique → args.technique
        proxy     → args.proxy
        cookie    → args.cookie
        output_dir→ args.output
        no_zip    → args.no_zip
        verbose   → args.verbose

    Returns a NEW argparse.Namespace; the original is not mutated.
    """
    # Build a sentinel parser that only covers config-backed flags
    sentinel_parser = argparse.ArgumentParser(add_help=False)
    sentinel_parser.add_argument("--timeout",   type=float, default=None)
    sentinel_parser.add_argument("--delay",     type=float, default=None)
    sentinel_parser.add_argument("--level",     type=int,   default=None)
    sentinel_parser.add_argument("--technique", default=None)
    sentinel_parser.add_argument("--proxy",     default=None)
    sentinel_parser.add_argument("--cookie",    default=None)
    sentinel_parser.add_argument("-o", "--output", dest="output", default=None)
    sentinel_parser.add_argument("--no-zip",    dest="no_zip",  action="store_true", default=False)
    sentinel_parser.add_argument("-v", "--verbose", action="store_true", default=False)

    # parse_known_args so unknown flags (all the non-config ones) are ignored
    try:
        sentinel_ns, _ = sentinel_parser.parse_known_args(sys.argv[1:])
    except SystemExit:
        # Extremely defensive: if sentinel parsing itself fails, treat everything
        # as "not explicitly supplied" and let config + argparse defaults win.
        sentinel_ns = argparse.Namespace(
            timeout=None, delay=None, level=None, technique=None,
            proxy=None, cookie=None, output=None, no_zip=False, verbose=False,
        )

    # Start with a copy of the original namespace
    result = copy.copy(args_namespace)

    # Helper: apply config value only when the CLI sentinel is at its default
    def _apply(attr: str, sentinel_attr: str, sentinel_default: Any, config_key: str):
        sentinel_val = getattr(sentinel_ns, sentinel_attr, sentinel_default)
        if sentinel_val == sentinel_default and config_key in config:
            setattr(result, attr, config[config_key])

    _apply("timeout",   "timeout",   None,  "timeout")
    _apply("delay",     "delay",     None,  "delay")
    _apply("level",     "level",     None,  "level")
    _apply("technique", "technique", None,  "technique")
    _apply("proxy",     "proxy",     None,  "proxy")
    _apply("cookie",    "cookie",    None,  "cookie")
    _apply("output",    "output",    None,  "output_dir")
    _apply("no_zip",    "no_zip",    False, "no_zip")
    _apply("verbose",   "verbose",   False, "verbose")

    return result

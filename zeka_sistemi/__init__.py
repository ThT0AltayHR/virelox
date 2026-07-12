# VIRELOX Zeka Sistemi v4.0
import sys, os
_kok = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _kok not in sys.path:
    sys.path.insert(0, _kok)

# tablo_bulucu v4.0 — brute-force tablo ismi tespiti
try:
    from . import tablo_bulucu
except Exception:
    pass

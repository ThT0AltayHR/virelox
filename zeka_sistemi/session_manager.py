"""
VIRELOX Session Manager v4.0
=============================
Tarama oturumlarını kaydeder ve devam ettirir.
Dosya: ~/.virelox_sessions/<hash>.json
"""

import os
import json
import hashlib
import time
from typing import Optional, Dict, Any, List


_SESSION_DIR = os.path.join(os.path.expanduser("~"), ".virelox_sessions")


def _session_id(url: str, param: str) -> str:
    raw = f"{url}::{param}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _session_yolu(session_id: str) -> str:
    os.makedirs(_SESSION_DIR, exist_ok=True)
    return os.path.join(_SESSION_DIR, f"{session_id}.json")


def tum_sessionlari_listele() -> List[Dict]:
    if not os.path.isdir(_SESSION_DIR):
        return []
    sonuc = []
    for fn in os.listdir(_SESSION_DIR):
        if not fn.endswith(".json"):
            continue
        yol = os.path.join(_SESSION_DIR, fn)
        try:
            with open(yol, "r", encoding="utf-8") as f:
                veri = json.load(f)
            sonuc.append({
                "url":        veri.get("url", "?"),
                "param":      veri.get("param", "?"),
                "dbms":       veri.get("dbms", "?"),
                "aşama":      veri.get("asama", "?"),
                "guncelleme": veri.get("guncelleme", "?"),
                "dosya":      yol,
            })
        except Exception:
            continue
    return sorted(sonuc, key=lambda x: x.get("guncelleme", ""), reverse=True)


class SessionYoneticisi:
    """
    Tek bir (url, param) çifti için session yönetimi.
    Tüm veriler JSON dosyasında saklanır.
    """

    def __init__(self, url: str, param: str, verbose: bool = False):
        self.url     = url
        self.param   = param
        self.verbose = verbose
        self._id     = _session_id(url, param)
        self._yol    = _session_yolu(self._id)
        self._veri: Dict[str, Any] = {
            "url":        url,
            "param":      param,
            "asama":      "baslangic",
            "dbms":       None,
            "waf_adi":    "Yok",
            "tamper":     [],
            "acik_tipler": {},
            "union_kolon": None,
            "union_metin_kolonu": None,
            "union_prefix": "-1",
            "dump":       {},
            "tamamlanan_tablolar": [],
            "guncelleme": "",
        }
        self.asama = "baslangic"

    # ── Yükleme / Başlatma ────────────────────────────────────────────────────
    def yukle_veya_yeni_baslat(self) -> bool:
        """
        Session dosyası varsa yükler → True döner (devam edilebilir).
        Yoksa yeni session başlatır → False döner.
        """
        if os.path.isfile(self._yol):
            try:
                with open(self._yol, "r", encoding="utf-8") as f:
                    kayit = json.load(f)
                if kayit.get("url") == self.url and kayit.get("param") == self.param:
                    self._veri = kayit
                    self.asama = kayit.get("asama", "baslangic")
                    if self.verbose:
                        print(f"[SESSION] Yüklendi — Aşama: {self.asama}")
                    return True
            except Exception:
                pass
        self._kaydet()
        return False

    # ── Getter ────────────────────────────────────────────────────────────────
    def get(self, anahtar: str, varsayilan=None):
        return self._veri.get(anahtar, varsayilan)

    # ── Aşama güncelleme ─────────────────────────────────────────────────────
    def asama_guncelle(self, yeni_asama: str, **kwargs):
        self.asama = yeni_asama
        self._veri["asama"] = yeni_asama
        for k, v in kwargs.items():
            self._veri[k] = v
        self._kaydet()

    # ── Tablo tamamlandı ─────────────────────────────────────────────────────
    def tablo_tamamlandi(self, tablo: str, veri: Dict):
        dump = self._veri.setdefault("dump", {})
        tablolar = dump.setdefault("tablolar", {})
        tablolar[tablo] = veri
        tamamlananlar = self._veri.setdefault("tamamlanan_tablolar", [])
        if tablo not in tamamlananlar:
            tamamlananlar.append(tablo)
        self._kaydet()

    def tablo_tamamlandi_mi(self, tablo: str) -> bool:
        return tablo in self._veri.get("tamamlanan_tablolar", [])

    # ── Temizleme ─────────────────────────────────────────────────────────────
    def temizle(self):
        self._veri = {
            "url":        self.url,
            "param":      self.param,
            "asama":      "baslangic",
            "dbms":       None,
            "waf_adi":    "Yok",
            "tamper":     [],
            "acik_tipler": {},
            "union_kolon": None,
            "union_metin_kolonu": None,
            "union_prefix": "-1",
            "dump":       {},
            "tamamlanan_tablolar": [],
            "guncelleme": "",
        }
        self.asama = "baslangic"
        self._kaydet()

    # ── Kaydet ───────────────────────────────────────────────────────────────
    def _kaydet(self):
        self._veri["guncelleme"] = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self._yol, "w", encoding="utf-8") as f:
                json.dump(self._veri, f, ensure_ascii=False, indent=2, default=str)
        except Exception:
            pass

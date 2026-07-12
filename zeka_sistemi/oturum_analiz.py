"""
VIRELOX Oturum/Cookie Güvenlik Analizi v4.0
Cookie güvenlik bayrakları ve token entropi denetimi
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
import math
import string
from typing import Dict, Callable, Optional


def _entropi(deger: str) -> float:
    """Shannon entropisi — randomness ölçüsü (token güvenliği için)."""
    if not deger:
        return 0.0
    frekans = {}
    for c in deger:
        frekans[c] = frekans.get(c, 0) + 1
    n = len(deger)
    return -sum((k / n) * math.log2(k / n) for k in frekans.values())


# Tahmin edilebilir / zayıf oturum adları
ZAYIF_COOKIE_ADLARI = {
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "session",
    "sid", "user_id", "auth", "token", "remember_me",
    "logged_in", "is_admin", "admin",
}


class OturumAnaliz:
    def __init__(self, log_func: Optional[Callable] = None):
        self.log = log_func or (lambda m: None)

    def tara(self, url: str, http_istemci=None) -> Dict:
        sonuc = {
            "cookieler": [],
            "sorunlu":   0,
            "toplam":    0,
            "uyarilar":  [],
        }
        if not http_istemci:
            return sonuc

        try:
            r = http_istemci.get(url)
            if not r:
                return sonuc
        except Exception:
            return sonuc

        # Cookie'leri al
        ham_cookieler = []
        # requests.Response
        if hasattr(r, 'cookies'):
            for ck in r.cookies:
                ham_cookieler.append({
                    "ad":       ck.name,
                    "deger":    ck.value or "",
                    "httponly": ck.has_nonstandard_attr("HttpOnly"),
                    "secure":   ck.secure,
                    "samesite": ck.get_nonstandard_attr("SameSite", ""),
                    "domain":   ck.domain or "",
                    "path":     ck.path or "/",
                })
        # Set-Cookie başlığından parse
        elif hasattr(r, 'headers'):
            hdrs = getattr(r, 'headers', {})
            for v in ([hdrs.get("Set-Cookie")] if isinstance(hdrs.get("Set-Cookie"), str)
                      else hdrs.get("Set-Cookie", [])):
                if not v:
                    continue
                parca = [p.strip() for p in v.split(";")]
                if not parca:
                    continue
                ad_deger = parca[0].split("=", 1)
                ad   = ad_deger[0].strip()
                deger = ad_deger[1].strip() if len(ad_deger) > 1 else ""
                attrs = {p.lower().split("=")[0].strip() for p in parca[1:]}
                ham_cookieler.append({
                    "ad":       ad,
                    "deger":    deger,
                    "httponly": "httponly" in attrs,
                    "secure":   "secure" in attrs,
                    "samesite": next((p.split("=")[1].strip()
                                      for p in parca[1:]
                                      if p.lower().startswith("samesite")), ""),
                    "domain":   "",
                    "path":     "/",
                })

        sonuc["toplam"] = len(ham_cookieler)

        for ck in ham_cookieler:
            sorunlar = []
            # HttpOnly eksik
            if not ck["httponly"]:
                sorunlar.append("HttpOnly bayrağı eksik")
            # Secure eksik (HTTPS ise)
            if url.startswith("https") and not ck["secure"]:
                sorunlar.append("Secure bayrağı eksik")
            # SameSite eksik
            if not ck.get("samesite"):
                sorunlar.append("SameSite bayrağı eksik")
            # Zayıf değer (kısa, düşük entropi)
            deger = ck["deger"]
            if deger and len(deger) < 16:
                sorunlar.append(f"Çok kısa token ({len(deger)} karakter, en az 16 önerilir)")
            elif deger:
                ent = _entropi(deger)
                if ent < 3.5:
                    sorunlar.append(f"Düşük token entropisi ({ent:.1f} bit/karakter)")
            # Zayıf cookie adı
            if ck["ad"].upper() in ZAYIF_COOKIE_ADLARI:
                sorunlar.append(f"Tahmin edilebilir oturum adı: {ck['ad']}")

            ck_analiz = dict(ck)
            ck_analiz["sorunlar"] = sorunlar
            ck_analiz["guvenli"]  = len(sorunlar) == 0
            sonuc["cookieler"].append(ck_analiz)
            if sorunlar:
                sonuc["sorunlu"] += 1
                for s in sorunlar:
                    self.log(f"[COOKIE] {ck['ad']}: {s}")

        return sonuc

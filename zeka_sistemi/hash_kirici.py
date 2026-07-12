"""
VIRELOX Hash Kırıcı v4.0
Dump verisindeki hash'leri otomatik tanır ve wordlist ile kırar
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
import hashlib
from typing import Dict, List, Callable, Optional


# ── Hash desenleri ─────────────────────────────────────────────────────────────
HASH_DESENLERI = [
    ("MD5",       32, re.compile(r'^[0-9a-fA-F]{32}$')),
    ("SHA1",      40, re.compile(r'^[0-9a-fA-F]{40}$')),
    ("SHA256",    64, re.compile(r'^[0-9a-fA-F]{64}$')),
    ("SHA512",   128, re.compile(r'^[0-9a-fA-F]{128}$')),
    ("MD5 ($P$)", None, re.compile(r'^\$P\$[./0-9A-Za-z]{31}$')),
    ("bcrypt",   None, re.compile(r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$')),
    ("sha512crypt", None, re.compile(r'^\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}$')),
]

# Yerleşik mini wordlist (yaygın parolalar)
MINI_WORDLIST = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome",
    "monkey", "1234567890", "password1", "iloveyou", "sunshine",
    "princess", "dragon", "master", "123456789", "login",
    "hello", "test", "1234", "pass", "root", "toor",
    "admin123", "password123", "changeme", "secret",
    "qwerty123", "pass123", "p@ssword", "P@ssw0rd", "passw0rd",
]


def _hash_turu_tespit(deger: str):
    for ad, uzunluk, desen in HASH_DESENLERI:
        if desen.match(deger.strip()):
            return ad
    return None


def _hash_kirma_dene(hash_degeri: str, hash_turu: str) -> Optional[str]:
    """Wordlist ile MD5/SHA1/SHA256 kırmayı dene."""
    hash_degeri = hash_degeri.strip().lower()
    for kelime in MINI_WORDLIST:
        if hash_turu == "MD5":
            if hashlib.md5(kelime.encode()).hexdigest() == hash_degeri:
                return kelime
            # Yaygın tuzlama: md5(md5(pass))
            if hashlib.md5(hashlib.md5(kelime.encode()).hexdigest().encode()).hexdigest() == hash_degeri:
                return kelime
        elif hash_turu == "SHA1":
            if hashlib.sha1(kelime.encode()).hexdigest() == hash_degeri:
                return kelime
        elif hash_turu == "SHA256":
            if hashlib.sha256(kelime.encode()).hexdigest() == hash_degeri:
                return kelime
        elif hash_turu == "SHA512":
            if hashlib.sha512(kelime.encode()).hexdigest() == hash_degeri:
                return kelime
    return None


class HashKirici:
    def __init__(self, log_func: Optional[Callable] = None):
        self.log = log_func or (lambda m: None)

    def dump_verisi_tara(self, tablolar: Dict) -> List[Dict]:
        """Dump tabloları içinde hash değerleri ara ve kırmayı dene."""
        sonuclar = []
        hash_aday_kolonlar = {
            "password", "passwd", "pass", "pwd", "hash", "password_hash",
            "user_password", "admin_password", "secret", "token",
        }

        for tablo_adi, tablo in tablolar.items():
            kolonlar = tablo.get("kolonlar", [])
            veriler  = tablo.get("veriler", [])

            for kolon in kolonlar:
                if kolon.lower() not in hash_aday_kolonlar:
                    continue

                for satir in veriler:
                    if isinstance(satir, dict):
                        deger = str(satir.get(kolon, ""))
                    elif isinstance(satir, (list, tuple)):
                        idx = kolonlar.index(kolon) if kolon in kolonlar else -1
                        deger = str(satir[idx]) if idx >= 0 and idx < len(satir) else ""
                    else:
                        continue

                    if len(deger) < 16:
                        continue

                    hash_turu = _hash_turu_tespit(deger)
                    if not hash_turu:
                        continue

                    kirildi = None
                    if hash_turu in ("MD5", "SHA1", "SHA256", "SHA512"):
                        self.log(f"[HASH] {tablo_adi}.{kolon}: {hash_turu} tespit edildi — kırılıyor...")
                        kirildi = _hash_kirma_dene(deger, hash_turu)
                    else:
                        self.log(f"[HASH] {tablo_adi}.{kolon}: {hash_turu} (wordlist ile kırılamaz)")

                    sonuclar.append({
                        "tablo":   tablo_adi,
                        "kolon":   kolon,
                        "hash":    deger,
                        "tur":     hash_turu,
                        "parola":  kirildi,
                        "kirildi": kirildi is not None,
                    })

        return sonuclar

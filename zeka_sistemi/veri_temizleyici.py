"""
VIRELOX VeriTemizleyici v4.1
=============================
KRITIK HATA DÜZELTMESİ:
  Sunucu UNION SELECT sonucunu URL-encoded (hatta double/triple-encoded) olarak
  HTML'de yansıtabilir. Bu durumda VLX marker'ları arasından çekilen değer
  gerçek veri yerine encode edilmiş SQL payload gibi görünür.
  Bu modül ham hücre değerlerini temizler: URL-decode, binary temizleme,
  mojibake düzeltme ve geçersiz karakter kaldırma.

Kullanım:
    from zeka_sistemi.veri_temizleyici import VeriTemizleyici
    vt = VeriTemizleyici()
    temiz = vt.yanit_isle(ham_metin)
    hucre = vt.hucre_isle(ham_hucre)
"""

import re
import urllib.parse
import unicodedata
from typing import Optional


class VeriTemizleyici:
    """Merkezi veri normalleştirici — DB yanıtlarını temizler."""

    # Boş/anlamsız değerler
    _BOSLUK_ISARETLER = {"", "NULL", "null", "None", "nil", "(null)", "N/A", "n/a"}

    # URL-encoding tespiti: en az 2 hex encode dizisi varsa encoded sayılır
    _URL_ENC_RE = re.compile(r'%[0-9A-Fa-f]{2}')

    # Binary/garbled karakter aralıkları (yazdırılamaz kontrol karakterleri, BOM vb.)
    _BINARY_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]')

    # MySQL HEX decode için
    _HEX_ONLY_RE = re.compile(r'^[0-9A-Fa-f]+$')

    def __init__(self):
        self._url_decode_cache: dict = {}

    # ── URL-Decode (progressive, multi-layer) ─────────────────────────────────
    @staticmethod
    def url_decode_progressive(deger: str, max_iter: int = 5) -> str:
        """
        URL-encoding'i katman katman çöz.
        %2527 → %27 → ' gibi double/triple encode durumlarını handle eder.
        + karakterini boşluk olarak decode eder (application/x-www-form-urlencoded).
        max_iter iterasyondan sonra durur (sonsuz döngü koruması).
        """
        if not deger or '%' not in deger:
            return deger
        onceki = deger
        for _ in range(max_iter):
            try:
                yeni = urllib.parse.unquote_plus(onceki)
            except Exception:
                break
            if yeni == onceki:
                break
            onceki = yeni
        return onceki

    @staticmethod
    def mysql_hex_coz(hex_str: str) -> str:
        """
        MySQL HEX(GROUP_CONCAT(...)) sonucunu UTF-8 stringe dönüştürür.
        Girdi: saf hex string (büyük/küçük harf karışık olabilir).
        Geçersiz hex → orijinal string döner (sessiz fallback).
        """
        if not hex_str:
            return ""
        temiz = hex_str.strip()
        # Sadece hex karakterleri olan bir string mi?
        if not VeriTemizleyici._HEX_ONLY_RE.match(temiz):
            # Bazı sunucular 0x prefix ile döner
            if temiz.lower().startswith("0x"):
                temiz = temiz[2:]
            else:
                return hex_str  # hex değil, orijinali döndür
        try:
            return bytes.fromhex(temiz).decode("utf-8", errors="replace")
        except (ValueError, AttributeError):
            return hex_str

    # ── Binary / Mojibake Temizleme ───────────────────────────────────────────
    @staticmethod
    def binary_temizle(deger: str) -> str:
        """Yazdırılamaz kontrol karakterlerini ve BOM'u kaldır."""
        if not deger:
            return deger
        # BOM kaldır
        deger = deger.lstrip('\ufeff\ufffe')
        # Yazdırılamaz kontrol karakterleri kaldır (tab ve newline korunur)
        deger = VeriTemizleyici._BINARY_RE.sub('', deger)
        return deger

    @staticmethod
    def unicode_normalize(deger: str) -> str:
        """Unicode NFC normalizasyonu uygula (mojibake önlemi)."""
        try:
            return unicodedata.normalize('NFC', deger)
        except Exception:
            return deger

    # ── SQL Keyword Tespiti (encoded veya plain) ──────────────────────────────
    @staticmethod
    def sql_keyword_iceriyor_mu(deger: str) -> bool:
        """
        Değerin gerçek veri yerine yansıyan SQL payload olup olmadığını kontrol eder.
        Hem plain hem de URL-encoded hali kontrol edilir.

        BUG FIX:
            Önceki kod sadece ham (URL-encoded) string üzerinde arama yapıyordu.
            'SELECT' gibi anahtar kelimeler %2527%257C... gibi encode edildiğinde
            tespit edilemiyordu. Şimdi önce decode edilip sonra kontrol ediliyor.
        """
        if not deger:
            return False
        # Önce decode et
        decoded = VeriTemizleyici.url_decode_progressive(deger)
        # Sonra kontrol et
        return bool(re.search(
            r'\b(SELECT|FROM|WHERE|GROUP_CONCAT|GROUP_CONCAT\s*\(|CONCAT|UNION'
            r'|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE'
            r'|pragma_table_info|sqlite_master|information_schema'
            r'|pg_catalog|sys\.tables|WAITFOR|SLEEP|BENCHMARK)\b',
            decoded, re.IGNORECASE
        ))

    # ── Ana API ───────────────────────────────────────────────────────────────
    def hucre_isle(self, deger: str) -> str:
        """
        Tek bir DB hücresi değerini temizler:
        1. Binary karakterleri kaldır
        2. Unicode normalize
        3. Başı/sonu boşluk temizle
        Dönen değer her zaman str'dir.
        """
        if deger is None:
            return ""
        deger = str(deger)
        deger = self.binary_temizle(deger)
        deger = self.unicode_normalize(deger)
        return deger.strip()

    def yanit_isle(self, ham: str) -> str:
        """
        Tam HTTP yanıt metnini (veya DB yanıtını) işler:
        1. URL-decode (progressive, multi-layer)
        2. Binary temizleme
        3. Unicode normalize
        Garbled/double-encoded yanıtları kurtarmak için kullanılır.
        """
        if not ham:
            return ham
        ham = self.url_decode_progressive(ham)
        ham = self.binary_temizle(ham)
        ham = self.unicode_normalize(ham)
        return ham

    def deger_anlamli_mi(self, deger: str) -> bool:
        """Değerin gerçek veri içerip içermediğini kontrol eder."""
        if not deger or deger.strip() in self._BOSLUK_ISARETLER:
            return False
        if self.sql_keyword_iceriyor_mu(deger):
            return False
        return True

    def tablo_adi_temizle(self, ham: str) -> str:
        """
        Union sorgudan gelen tablo adını temizler.
        URL-encoded SQL payload gelirse (yansıma) boş string döner.
        """
        if not ham:
            return ""
        # Progressive URL decode
        temiz = self.url_decode_progressive(ham.strip())
        # SQL keyword içeriyorsa bu bir yansıma, gerçek tablo adı değil
        if self.sql_keyword_iceriyor_mu(temiz):
            return ""
        # Binary temizle
        temiz = self.binary_temizle(temiz)
        return temiz.strip()

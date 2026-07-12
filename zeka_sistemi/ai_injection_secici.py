"""
VIRELOX AI Injection Seçici v4.1 — Sniper Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Teknoloji tespiti ve HTTP yanıt analizine göre öncelikli injection tiplerini
belirler. v4.1 yenilikleri:
  • HedefProfilleyici entegrasyonu — WAF/hız profili strateji seçimini etkiler
  • hedef_gucu_degerlendir() — hızlı 0–100 güç skoru
  • Hem DBMS sinyallerine hem de hedef profiline göre çift-katmanlı öneri
Mozilla Public License 2.0 — AltayHR Developers
"""
import re
from typing import List, Dict, Optional, Any


class AIInjectionSecici:
    """
    Sunucu yanıtını analiz ederek en uygun injection tiplerini önerir.
    sqlmap'in -level mantığına benzer ama ML-free, kural tabanlı.

    v4.1: profil parametresi ile HedefProfilleyici çıktısını dikkate alır.
    """

    def analiz_et(self, url: str, icerik: str, headers: dict,
                  profil: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Öncelikli injection tip listesi döner.
        profil: HedefProfilleyici.profil_cikart() çıktısı (opsiyonel).
        """
        oncelik_listesi = []
        icerik_lower = icerik.lower()
        server       = headers.get("server", "").lower()
        powered_by   = headers.get("x-powered-by", "").lower()
        birlesik     = powered_by + server + icerik_lower

        # ── DBMS sinyalleri ────────────────────────────────────────────────────
        if re.search(r'mysql|mariadb', birlesik):
            oncelik_listesi += [
                {"tip": "error",   "neden": "MySQL/MariaDB tespit edildi",     "oncelik": 95},
                {"tip": "union",   "neden": "MySQL UNION destekli",            "oncelik": 90},
                {"tip": "boolean", "neden": "MySQL boolean-blind",             "oncelik": 80},
                {"tip": "time",    "neden": "MySQL SLEEP() time-based",        "oncelik": 70},
                {"tip": "stacked", "neden": "MySQL stacked (multi-stmt ON)",   "oncelik": 55},
            ]
        elif re.search(r'postgresql|postgres', birlesik):
            oncelik_listesi += [
                {"tip": "error",   "neden": "PostgreSQL hata kanalı",          "oncelik": 90},
                {"tip": "union",   "neden": "PostgreSQL UNION",                "oncelik": 85},
                {"tip": "boolean", "neden": "PostgreSQL boolean-blind",        "oncelik": 75},
                {"tip": "stacked", "neden": "PostgreSQL stacked (;;)",         "oncelik": 65},
                {"tip": "time",    "neden": "PostgreSQL pg_sleep()",           "oncelik": 60},
            ]
        elif re.search(r'asp\.net|iis|microsoft', birlesik):
            oncelik_listesi += [
                {"tip": "error",   "neden": "MSSQL hata kanalı",              "oncelik": 90},
                {"tip": "stacked", "neden": "MSSQL stacked queries",          "oncelik": 85},
                {"tip": "union",   "neden": "MSSQL UNION",                    "oncelik": 80},
                {"tip": "time",    "neden": "MSSQL WAITFOR DELAY",            "oncelik": 70},
            ]
        elif re.search(r'\boracle\b', birlesik):
            oncelik_listesi += [
                {"tip": "error",   "neden": "Oracle hata kanalı (ORA-)",      "oncelik": 90},
                {"tip": "union",   "neden": "Oracle UNION (FROM DUAL)",       "oncelik": 85},
                {"tip": "boolean", "neden": "Oracle boolean-blind",           "oncelik": 70},
                {"tip": "time",    "neden": "Oracle DBMS_PIPE",               "oncelik": 55},
            ]
        elif re.search(r'sqlite', birlesik):
            oncelik_listesi += [
                {"tip": "error",   "neden": "SQLite hata kanalı",             "oncelik": 90},
                {"tip": "union",   "neden": "SQLite UNION",                   "oncelik": 85},
                {"tip": "boolean", "neden": "SQLite boolean-blind",           "oncelik": 75},
            ]
        elif re.search(r'mongodb|nosql', birlesik):
            oncelik_listesi += [
                {"tip": "nosql",   "neden": "MongoDB/NoSQL tespit edildi",    "oncelik": 95},
                {"tip": "boolean", "neden": "NoSQL boolean injection",        "oncelik": 75},
            ]

        # ── Framework/CMS sinyalleri ───────────────────────────────────────────
        if re.search(r'laravel|symfony|codeigniter|yii', birlesik):
            oncelik_listesi += [
                {"tip": "json",    "neden": "PHP framework — JSON endpoint",  "oncelik": 72},
                {"tip": "boolean", "neden": "PHP framework boolean",          "oncelik": 68},
            ]
        if re.search(r'wp-content|wordpress', birlesik):
            oncelik_listesi += [
                {"tip": "error",   "neden": "WordPress MySQL hata kanalı",   "oncelik": 85},
                {"tip": "union",   "neden": "WordPress UNION",               "oncelik": 80},
            ]
        if re.search(r'graphql', birlesik):
            oncelik_listesi += [
                {"tip": "graphql", "neden": "GraphQL endpoint tespit edildi", "oncelik": 85},
            ]
        if re.search(r'xmlrpc|soap', birlesik):
            oncelik_listesi += [
                {"tip": "xml",     "neden": "XML/SOAP servisi",              "oncelik": 78},
                {"tip": "xxe",     "neden": "XXE saldırısı olası",           "oncelik": 75},
            ]

        # ── Profil tabanlı ayarlamalar ─────────────────────────────────────────
        if profil:
            # Hata-hassas hedefte error-based'i en üste taşı
            if profil.get("hata_hassas"):
                for e in oncelik_listesi:
                    if e["tip"] == "error":
                        e["oncelik"] = min(e["oncelik"] + 10, 100)
                        break

            # WAF varsa encoding bypass tiplerini ekle
            if profil.get("waf"):
                waf_adi = profil.get("waf_adi", "")
                oncelik_listesi += [
                    {"tip": "hex_encoding",    "neden": f"{waf_adi} bypass",  "oncelik": 65},
                    {"tip": "unicode_bypass",  "neden": f"{waf_adi} bypass",  "oncelik": 62},
                    {"tip": "comment_split",   "neden": f"{waf_adi} bypass",  "oncelik": 60},
                    {"tip": "case_mixing",     "neden": f"{waf_adi} bypass",  "oncelik": 58},
                ]

            # Yavaş hedefte time-based'i öne alma
            if profil.get("hiz") == "slow":
                for e in oncelik_listesi:
                    if e["tip"] == "time":
                        e["oncelik"] = max(e["oncelik"] - 15, 30)

            # Profil öneri stratejileri varsa ekle
            for oneri_tip in profil.get("oneri_strateji", []):
                if not any(e["tip"] == oneri_tip for e in oncelik_listesi):
                    oncelik_listesi.append({
                        "tip": oneri_tip,
                        "neden": "Profil önerisi",
                        "oncelik": 50,
                    })

        # ── Varsayılan — DBMS bilinmiyorsa tüm temel tipler ───────────────────
        if not oncelik_listesi:
            oncelik_listesi = [
                {"tip": "error",   "neden": "Genel hata testi",  "oncelik": 80},
                {"tip": "union",   "neden": "Genel UNION testi", "oncelik": 75},
                {"tip": "boolean", "neden": "Boolean-blind",     "oncelik": 65},
                {"tip": "time",    "neden": "Time-based blind",  "oncelik": 55},
                {"tip": "stacked", "neden": "Stacked queries",   "oncelik": 45},
            ]

        # Tekrar gidermeli öncelik sıralaması
        goruldu = set()
        benzersiz = []
        for e in sorted(oncelik_listesi, key=lambda x: x["oncelik"], reverse=True):
            if e["tip"] not in goruldu:
                goruldu.add(e["tip"])
                benzersiz.append(e)

        return benzersiz

    def hedef_gucu_degerlendir(
        self,
        profil: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict] = None,
        icerik: str = "",
    ) -> Dict[str, Any]:
        """
        Hedefin 'güç skorunu' 0–100 arasında hesaplar.

        Skor yorumu:
          0–30  : Zayıf — hızlı agresif tarama yeterli
          31–60 : Orta  — dengeli yaklaşım
          61–100: Güçlü — WAF bypass + yavaş + kapsamlı

        Dönen dict:
            {skor, etiket, aciklama, strateji_onerileri}
        """
        skor = 50  # Başlangıç nötr

        if profil:
            if profil.get("waf"):               skor += 20
            if profil.get("hiz") == "slow":     skor += 10
            elif profil.get("hiz") == "fast":   skor -= 10
            if profil.get("hata_hassas"):        skor -= 15
            if profil.get("hassasiyet") == "weak":   skor -= 20
            elif profil.get("hassasiyet") == "strong": skor += 15

        if headers:
            h = str(headers).lower()
            if re.search(r'cloudflare|sucuri|imperva|akamai', h): skor += 15
            if "x-content-security-policy" in h:                  skor += 5
            if re.search(r'403|forbidden|blocked', h):            skor += 10

        if icerik:
            ic = icerik.lower()
            if re.search(r'blocked|security check|ddos', ic): skor += 10
            if re.search(r'error|sql.*error|warning.*mysql', ic): skor -= 10

        skor = max(0, min(100, skor))

        if skor <= 30:
            etiket, strateji = "Zayıf", ["error", "union", "boolean"]
        elif skor <= 60:
            etiket, strateji = "Orta",  ["error", "union", "boolean", "time"]
        else:
            etiket, strateji = "Güçlü", ["boolean", "time", "hex_encoding",
                                          "unicode_bypass", "error", "union"]

        return {
            "skor":              skor,
            "etiket":            etiket,
            "strateji_onerileri": strateji,
            "aciklama": (
                f"Güç skoru={skor}/100 ({etiket}) — "
                f"WAF={'✔' if (profil or {}).get('waf') else '✗'}, "
                f"hız={(profil or {}).get('hiz','?')}"
            ),
        }

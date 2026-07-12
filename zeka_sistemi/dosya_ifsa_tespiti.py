"""
VIRELOX Hassas Dosya İfşa Tespiti v4.0
Yaygın hassas dosya/dizin yollarını tarar
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
import urllib.parse
from typing import Dict, Callable, Optional, List


# Hassas dosya/dizin listesi
HASSAS_YOLLAR = [
    # Konfigürasyon
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.yaml", "/configuration.php",
    "/settings.php", "/settings.py", "/local_settings.py",
    "/wp-config.php", "/wp-config.php.bak",
    "/database.yml", "/database.php", "/db_config.php",
    "/application.properties", "/application.yml",
    # Git / VCS
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/dirstate",
    # Yedek dosyalar
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db_backup.sql", "/database_backup.sql",
    "/site.zip", "/www.zip", "/htdocs.zip",
    # PHP bilgi
    "/phpinfo.php", "/info.php", "/php_info.php", "/test.php",
    # Log dosyaları
    "/error.log", "/access.log", "/debug.log", "/app.log",
    "/logs/error.log", "/log/error.log",
    # Admin paneli
    "/admin", "/admin/", "/admin/login", "/admin.php",
    "/administrator", "/administrator/",
    "/phpmyadmin", "/phpmyadmin/", "/pma/",
    "/adminer.php", "/adminer/",
    # Kimlik bilgileri
    "/credentials.json", "/credentials.xml", "/credentials.txt",
    "/passwords.txt", "/passwd", "/shadow",
    "/users.txt", "/user.txt",
    # API anahtarları
    "/api_keys.txt", "/api_key.txt", "/apikeys.json",
    "/secrets.yml", "/secrets.json",
    # Çeşitli
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/server-status", "/server-info",
    "/.well-known/security.txt",
    "/composer.json", "/package.json", "/Gemfile",
    "/README.md", "/README.txt",
    "/web.config", "/.htaccess", "/.htpasswd",
]

# Hassas içerik işaretçileri
HASSAS_ICERIK_ISARETLER = [
    r"DB_PASSWORD\s*=",
    r"db_password\s*:",
    r"password\s*=\s*['\"]?[^\s'\"]{4,}",
    r"secret\s*=\s*['\"]?[^\s'\"]{8,}",
    r"api[_-]key\s*[=:]\s*['\"]?[^\s'\"]{10,}",
    r"AWS_SECRET",
    r"STRIPE_SECRET",
    r"private[_-]key",
    r"\[boot loader\]",
    r"root:x:0:0:",
    r"mysql://[^\s]+",
    r"postgres://[^\s]+",
    r"mongodb://[^\s]+",
]


class DosyaIfsaTespiti:
    def __init__(self, http_istemci=None, log_func: Optional[Callable] = None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)

    def tara(self, url: str, ek_yollar: Optional[List[str]] = None) -> Dict:
        parsed   = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        bulunanlar = []
        yollar = HASSAS_YOLLAR + (ek_yollar or [])

        self.log(f"[FILE] {len(yollar)} hassas yol taranıyor...")

        for yol in yollar:
            test_url = base_url + yol
            try:
                r = self.http.get(test_url)
                if not r:
                    continue
                durum = getattr(r, 'status_code', 0)
                if durum not in (200, 206):
                    continue
                icerik = getattr(r, 'text', '')
                boyut  = len(icerik)
                # Çok kısa yanıt muhtemelen redirect/404
                if boyut < 20:
                    continue
                hassas = any(
                    re.search(pat, icerik, re.IGNORECASE)
                    for pat in HASSAS_ICERIK_ISARETLER
                )
                bulunanlar.append({
                    "url":           test_url,
                    "yol":           yol,
                    "durum_kodu":    durum,
                    "boyut":         boyut,
                    "hassas_icerik": hassas,
                })
                seviye = "★ KRİTİK" if hassas else "·"
                self.log(f"[FILE] {seviye} [{durum}] {yol} ({boyut}B)")
            except Exception:
                continue

        return {
            "bulunanlar":  bulunanlar,
            "toplam":      len(yollar),
            "bulunan_say": len(bulunanlar),
        }

"""
VIRELOX Teknoloji Tespiti v4.0
CMS, framework, sunucu ve veritabanı parmak izi
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
from typing import Dict, List, Callable, Optional


# ── Teknoloji imzaları ────────────────────────────────────────────────────────
TEKNOLOJI_IMZALARI = {
    # CMS
    "WordPress":      {"headers": ["x-powered-by.*wordpress"],
                       "body":    [r"wp-content/themes", r"wp-includes", r"/wp-json/"],
                       "url":     [r"/wp-admin", r"/wp-login.php"]},
    "Joomla":         {"headers": [],
                       "body":    [r"Joomla!", r"option=com_", r"/components/com_"],
                       "url":     [r"/administrator/"]},
    "Drupal":         {"headers": ["x-drupal-dynamic-cache", "x-drupal-cache"],
                       "body":    [r"Drupal\.settings", r"/sites/default/files"],
                       "url":     [r"/node/", r"/user/login"]},
    "Magento":        {"headers": [],
                       "body":    [r"Mage\.Cookies", r"Magento", r"/skin/frontend/"],
                       "url":     [r"/index.php/", r"/checkout/cart"]},
    "Shopify":        {"headers": ["x-shopify-stage", "x-shopid"],
                       "body":    [r"Shopify\.theme", r"cdn\.shopify\.com"],
                       "url":     []},
    # Frameworks
    "Laravel":        {"headers": ["set-cookie.*laravel"],
                       "body":    [r"laravel", r"csrf-token"],
                       "url":     []},
    "Django":         {"headers": ["x-frame-options.*sameorigin"],
                       "body":    [r"csrfmiddlewaretoken", r"django"],
                       "url":     [r"/admin/"]},
    "Ruby on Rails":  {"headers": ["x-powered-by.*phusion passenger"],
                       "body":    [r"rails", r"authenticity_token"],
                       "url":     []},
    "ASP.NET":        {"headers": ["x-aspnet-version", "x-aspnetmvc-version",
                                   "x-powered-by.*asp\.net"],
                       "body":    [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net"],
                       "url":     [r"\.aspx", r"\.ashx"]},
    "PHP":            {"headers": ["x-powered-by.*php"],
                       "body":    [r"<\?php", r"PHPSESSID"],
                       "url":     [r"\.php"]},
    "Node.js":        {"headers": ["x-powered-by.*express", "x-powered-by.*node"],
                       "body":    [r"express", r"node\.js"],
                       "url":     []},
    # Web sunucuları
    "Apache":         {"headers": ["server.*apache"],
                       "body":    [r"Apache/\d", r"Powered by Apache"],
                       "url":     []},
    "Nginx":          {"headers": ["server.*nginx"],
                       "body":    [r"nginx"],
                       "url":     []},
    "IIS":            {"headers": ["server.*iis", "x-powered-by.*iis"],
                       "body":    [r"microsoft-iis", r"iis windows"],
                       "url":     []},
    # DB ipuçları
    "MySQL":          {"headers": [],
                       "body":    [r"mysql_fetch", r"You have an error in your SQL syntax.*MySQL"],
                       "url":     []},
    "PostgreSQL":     {"headers": [],
                       "body":    [r"PostgreSQL.*ERROR", r"pg_query"],
                       "url":     []},
    "Microsoft SQL":  {"headers": [],
                       "body":    [r"Unclosed quotation mark", r"ODBC SQL Server Driver",
                                   r"Msg \d+, Level \d+"],
                       "url":     []},
    "SQLite":         {"headers": [],
                       "body":    [r"sqlite_", r"\[SQLITE_ERROR\]", r"sqlite3\.", r"SQLite error"],
                       "url":     []},
    # CDN / Bulut
    "Cloudflare CDN": {"headers": ["cf-ray", "cf-cache-status"],
                       "body":    [],
                       "url":     []},
    "AWS CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop"],
                       "body":    [],
                       "url":     []},
    "Fastly":         {"headers": ["fastly-restarts", "x-fastly-request-id"],
                       "body":    [],
                       "url":     []},
}

# Teknoloji → DBMS önerisi eşlemesi
TECH_DBMS_ONERISI = {
    "MySQL":         "MySQL",
    "PostgreSQL":    "PostgreSQL",
    "Microsoft SQL": "Microsoft SQL Server",
    "SQLite":        "SQLite",
    "WordPress":     "MySQL",
    "Joomla":        "MySQL",
    "Drupal":        "MySQL",
    "Laravel":       "MySQL",
    "Django":        "PostgreSQL",
    "ASP.NET":       "Microsoft SQL Server",
}


class TeknolojiTespiti:
    def __init__(self, http_istemci=None, log_func: Optional[Callable] = None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)

    def tara(self, url: str) -> Dict:
        sonuc = {"teknolojiler": [], "detaylar": {}}
        if not self.http:
            return sonuc

        try:
            r = self.http.get(url)
            if not r:
                return sonuc
            headers = {k.lower(): v.lower() for k, v in getattr(r, 'headers', {}).items()}
            body    = getattr(r, 'text', '').lower()
            hdr_str = " ".join(headers.values())

            for tech, imzalar in TEKNOLOJI_IMZALARI.items():
                skor = 0
                for hdr_pat in imzalar.get("headers", []):
                    if re.search(hdr_pat, hdr_str, re.IGNORECASE):
                        skor += 3
                for body_pat in imzalar.get("body", []):
                    if re.search(body_pat, body, re.IGNORECASE):
                        skor += 2
                for url_pat in imzalar.get("url", []):
                    if re.search(url_pat, url, re.IGNORECASE):
                        skor += 1
                if skor > 0:
                    sonuc["teknolojiler"].append(tech)
                    sonuc["detaylar"][tech] = skor

            # Skora göre sırala
            sonuc["teknolojiler"].sort(
                key=lambda t: sonuc["detaylar"].get(t, 0), reverse=True)
        except Exception as e:
            self.log(f"[TECH] Hata: {e}")

        return sonuc

    @staticmethod
    def dbms_onerisi(teknolojiler: List[str]) -> List[str]:
        """Tespit edilen teknolojilerden DBMS öneri listesi döndürür."""
        oneriler = []
        for tech in teknolojiler:
            dbms = TECH_DBMS_ONERISI.get(tech)
            if dbms and dbms not in oneriler:
                oneriler.append(dbms)
        if not oneriler:
            oneriler = ["MySQL", "PostgreSQL", "Microsoft SQL Server", "SQLite"]
        return oneriler

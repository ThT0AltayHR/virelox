"""
VIRELOX Hedef Tanılama v4.0
URL normalleştirme, parametre çıkarma ve hedef doğrulama yardımcıları.
Mozilla Public License 2.0 — AltayHR Developers
"""

import urllib.parse
from typing import Optional, Tuple


def url_normalize(url: str) -> str:
    """Verilen URL'yi normalize eder; scheme eksikse https:// ekler."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def url_host(url: str) -> str:
    """URL'den host (netloc) kısmını döndürür."""
    try:
        return urllib.parse.urlparse(url).netloc or url
    except Exception:
        return url


def url_domain(url: str) -> str:
    """URL'den saf domain adını döndürür (port ve path olmadan)."""
    try:
        host = urllib.parse.urlparse(url).netloc
        return host.split(":")[0]
    except Exception:
        return url


def url_params(url: str) -> dict:
    """URL'deki GET parametrelerini sözlük olarak döndürür."""
    try:
        qs = urllib.parse.urlparse(url).query
        return dict(urllib.parse.parse_qsl(qs))
    except Exception:
        return {}


def hedef_gecerli_mi(url: str) -> Tuple[bool, Optional[str]]:
    """
    URL'nin taranabilir olup olmadığını kontrol eder.
    (True, None) → geçerli
    (False, sebep) → geçersiz
    """
    url = url.strip()
    if not url:
        return False, "URL boş"
    if not url.startswith(("http://", "https://")):
        return False, "URL http:// veya https:// ile başlamalı"
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        return False, "Geçerli bir host bulunamadı"
    return True, None

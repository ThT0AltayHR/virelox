"""
VIRELOX Web Crawler — Form ve URL keşfi
Mozilla Public License 2.0
Geliştirici: AltayHR | AltayHR Developers
"""

import re
import urllib.parse
from typing import List, Dict, Optional, Set

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

# Pick the best available BS4 parser: lxml is fastest but not always installed
# (e.g. Termux). Fall back to the stdlib html.parser which is always present.
def _bs4_parser() -> str:
    try:
        import lxml  # noqa: F401
        return "lxml"
    except ImportError:
        return "html.parser"

_PARSER = _bs4_parser() if BS4_OK else None


class FormKesfedici:
    """HTML formlarını keşfeder ve parametre listesi çıkarır"""

    @staticmethod
    def formlari_al(html: str, base_url: str) -> List[Dict]:
        formlar = []
        if BS4_OK:
            soup = BeautifulSoup(html, _PARSER)
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                if not action:
                    action = base_url
                elif not action.startswith("http"):
                    action = urllib.parse.urljoin(base_url, action)
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    tip  = inp.get("type", "text")
                    deger = inp.get("value", "test")
                    if name:
                        inputs.append({"isim": name, "tip": tip, "deger": deger})
                formlar.append({"action": action, "method": method, "inputs": inputs})
        else:
            # Regex fallback
            for form_m in re.finditer(r'<form[^>]*>(.*?)</form>', html,
                                      re.DOTALL | re.IGNORECASE):
                form_html = form_m.group(0)
                action_m  = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                method_m  = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                action = action_m.group(1) if action_m else base_url
                method = method_m.group(1).lower() if method_m else "get"
                if not action.startswith("http"):
                    action = urllib.parse.urljoin(base_url, action)
                inputs = []
                for inp_m in re.finditer(r'<input[^>]*name=["\']+([^"\']+)["\']+[^>]*(?:value=["\']+([^"\']*)["\']+)?', form_html, re.IGNORECASE):
                    inputs.append({"isim": inp_m.group(1), "tip": "text", "deger": inp_m.group(2) if inp_m.group(2) is not None else "test"})
                formlar.append({"action": action, "method": method, "inputs": inputs})
        return formlar


class URLToplayici:
    """Sayfadaki URL'leri ve parametreleri toplar"""

    @staticmethod
    def url_topla(html: str, base_url: str) -> List[str]:
        urllar: Set[str] = set()
        base_parsed = urllib.parse.urlparse(base_url)
        base_domain = f"{base_parsed.scheme}://{base_parsed.netloc}"

        # href ve src
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = m.group(1).strip()
            if url.startswith("//"):
                url = base_parsed.scheme + ":" + url
            elif url.startswith("/"):
                url = base_domain + url
            elif not url.startswith("http"):
                url = urllib.parse.urljoin(base_url, url)
            if base_domain in url:
                urllar.add(url)

        return list(urllar)

    @staticmethod
    def parametreleri_cikart(url: str) -> Dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        return dict(urllib.parse.parse_qsl(parsed.query))


class WebCrawler:
    """Basit web crawler — URL ve form keşfi"""

    def __init__(self, http_istemci, max_sayfa: int = 20,
                 ayni_domain: bool = True, log_func=None):
        self.http    = http_istemci
        self.max_s   = max_sayfa
        self.ayni_d  = ayni_domain
        self.log     = log_func or print
        self.ziyaret: Set[str] = set()
        self.formlar: List[Dict] = []
        self.url_parametreler: List[Dict] = []

    def tara(self, baslangic_url: str) -> Dict:
        """Verilen URL'den başlayarak crawl yap"""
        self.log(f"[CRAWLER] Tarama başlıyor: {baslangic_url}")
        base_parsed = urllib.parse.urlparse(baslangic_url)
        base_domain = f"{base_parsed.scheme}://{base_parsed.netloc}"

        kuyruk = [baslangic_url]
        while kuyruk and len(self.ziyaret) < self.max_s:
            url = kuyruk.pop(0)
            if url in self.ziyaret:
                continue
            self.ziyaret.add(url)

            yanit = self.http.get(url)
            if not yanit:
                continue
            html = getattr(yanit, 'text', '')

            # Form keşfi
            yeni_formlar = FormKesfedici.formlari_al(html, url)
            self.formlar.extend(yeni_formlar)

            # URL parametreleri
            params = URLToplayici.parametreleri_cikart(url)
            if params:
                self.url_parametreler.append({"url": url, "params": params})

            # Yeni URL'ler
            yeni_urllar = URLToplayici.url_topla(html, url)
            for yurl in yeni_urllar:
                if self.ayni_d and base_domain not in yurl:
                    continue
                if yurl not in self.ziyaret:
                    kuyruk.append(yurl)

            self.log(f"[CRAWLER] {url} — {len(yeni_formlar)} form, {len(params)} param")

        self.log(f"[CRAWLER] Tamamlandı: {len(self.ziyaret)} sayfa, "
                 f"{len(self.formlar)} form, {len(self.url_parametreler)} URL-param")

        return {
            "ziyaret_edilen": list(self.ziyaret),
            "formlar": self.formlar,
            "url_parametreler": self.url_parametreler,
        }

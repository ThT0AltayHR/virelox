"""
Burp Suite tarzı HTTP istek/yanıt inceleme motoru.
Tüm HTTP trafiğini yakalar, analiz eder, güvenlik açıklarını işaretler.
"""

from __future__ import annotations

import re
import time
import copy
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urljoin, parse_qs

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _Dummy()

# ---------------------------------------------------------------------------
# Modern güvenlik açığı tipleri
# ---------------------------------------------------------------------------
MODERN_VULN_TIPLERI: Dict[str, str] = {
    "jwt_none":           "JWT none algorithm bypass",
    "graphql_introspect": "GraphQL introspection enabled",
    "ssrf_aws":           "AWS metadata SSRF",
    "xxe":                "XML External Entity",
    "ssti":               "Server-Side Template Injection",
    "http_smuggling":     "HTTP Request Smuggling",
    "cache_poisoning":    "Web cache poisoning via unkeyed headers",
    "prototype_pollution":"JS prototype pollution via JSON",
    "mass_assignment":    "Mass assignment via extra JSON fields",
    "nosql_operator":     "NoSQL operator injection ($where, $gt, $regex)",
}

# ---------------------------------------------------------------------------
# Probe tanımları
# ---------------------------------------------------------------------------
SQL_PROBES: List[str] = ["'", '"', "--", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--"]
XSS_PROBES: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
]
PATH_TRAVERSAL_PROBES: List[str] = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
]
SSTI_PROBES: List[str] = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{% 7*7 %}"]
CMD_INJECTION_PROBES: List[str] = [";id", "|id", "`id`", "$(id)", "&& id"]
SSRF_PROBES: List[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
]
XXE_PAYLOAD: str = (
    '<?xml version="1.0"?><!DOCTYPE test '
    '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<test>&xxe;</test>"
)
GRAPHQL_INTROSPECT_PAYLOAD: str = '{"query":"{__schema{types{name}}}"}'

# ---------------------------------------------------------------------------
# Yardımcı renkli print
# ---------------------------------------------------------------------------

def _renkli(metin: str, renk: str = Fore.WHITE) -> str:
    return f"{renk}{metin}{Style.RESET_ALL}"


def _baslik(metin: str) -> None:
    cizgi = "═" * 60
    print(f"\n{Fore.CYAN}{cizgi}")
    print(f"  {Fore.YELLOW}{Style.BRIGHT}{metin}")
    print(f"{Fore.CYAN}{cizgi}{Style.RESET_ALL}")


def _satirlar(cols: List[Tuple[str, int, str]]) -> None:
    """cols: [(deger, genislik, renk), ...]"""
    satirlar = ""
    for deger, genislik, renk in cols:
        satirlar += f"{renk}{str(deger):<{genislik}}{Style.RESET_ALL} "
    print(satirlar)


# ---------------------------------------------------------------------------
# Ana sınıf
# ---------------------------------------------------------------------------

class BurpInspector:
    """
    Burp Suite tarzı HTTP istek/yanıt inceleme motoru.
    Tüm HTTP trafiğini yakalar, analiz eder, güvenlik açıklarını işaretler.
    """

    def __init__(
        self,
        http_istemci: Any,
        log_func: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Args:
            http_istemci: HTTP istekleri yapabilen nesne (requests.Session veya benzeri).
                          get(url, **kwargs) ve post(url, data=..., **kwargs) metodlarına
                          sahip olması beklenir.
            log_func: Opsiyonel loglama fonksiyonu. Verilmezse print kullanılır.
        """
        self.http = http_istemci
        self._log: Callable[[str], None] = log_func if log_func else print

        # Kayıtlı istek/yanıt çiftleri
        self._gecmis: List[Dict[str, Any]] = []
        # Tespit edilen bulgular
        self._bulgular: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 1. İstek kaydet
    # ------------------------------------------------------------------
    def istek_kaydet(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str],
        yanit: Any,
    ) -> None:
        """
        Bir HTTP istek/yanıt çiftini geçmişe kaydeder.

        Args:
            url:     Hedef URL
            method:  HTTP metodu (GET, POST, vb.)
            headers: İstek başlıkları
            body:    İstek gövdesi (None olabilir)
            yanit:   Yanıt nesnesi; .status_code, .text, .headers özellikleri beklenir.
        """
        try:
            kayit: Dict[str, Any] = {
                "zaman":          datetime.now().isoformat(timespec="seconds"),
                "url":            url,
                "method":         method.upper(),
                "istek_baslik":   dict(headers),
                "istek_govde":    body,
                "yanit_kodu":     getattr(yanit, "status_code", None),
                "yanit_boyut":    len(getattr(yanit, "text", "") or ""),
                "yanit_baslik":   dict(getattr(yanit, "headers", {})),
                "yanit_govde":    getattr(yanit, "text", ""),
            }
            self._gecmis.append(kayit)
            self._log(
                _renkli(
                    f"[BurpInspector] Kayıt #{len(self._gecmis)}: "
                    f"{method.upper()} {url} → {kayit['yanit_kodu']}",
                    Fore.GREEN,
                )
            )
        except Exception as exc:
            self._log(_renkli(f"[BurpInspector] istek_kaydet hatası: {exc}", Fore.RED))

    # ------------------------------------------------------------------
    # 2. Geçmiş göster
    # ------------------------------------------------------------------
    def gecmis_goster(self) -> None:
        """Kayıtlı tüm istek/yanıt çiftlerini renkli tablo formatında gösterir."""
        if not self._gecmis:
            print(_renkli("[BurpInspector] Henüz kayıtlı istek yok.", Fore.YELLOW))
            return

        _baslik(f"HTTP Geçmişi — {len(self._gecmis)} kayıt")

        # Tablo başlığı
        sutunlar = [
            ("#",       4,  Fore.CYAN),
            ("Zaman",   20, Fore.WHITE),
            ("Metod",   8,  Fore.MAGENTA),
            ("Kod",     6,  Fore.YELLOW),
            ("Boyut",   8,  Fore.WHITE),
            ("URL",     55, Fore.GREEN),
        ]
        _satirlar([(ad, gen, renk) for ad, gen, renk in sutunlar])
        print(Fore.CYAN + "─" * 105 + Style.RESET_ALL)

        for idx, kayit in enumerate(self._gecmis, 1):
            kod = kayit["yanit_kodu"]
            if kod is None:
                kod_renk = Fore.RED
            elif kod < 300:
                kod_renk = Fore.GREEN
            elif kod < 400:
                kod_renk = Fore.YELLOW
            elif kod < 500:
                kod_renk = Fore.RED
            else:
                kod_renk = Fore.MAGENTA

            _satirlar([
                (idx,               4,  Fore.CYAN),
                (kayit["zaman"],    20, Fore.WHITE),
                (kayit["method"],   8,  Fore.MAGENTA),
                (str(kod) if kod else "—",   6, kod_renk),
                (kayit["yanit_boyut"], 8, Fore.WHITE),
                (kayit["url"][:55], 55, Fore.GREEN),
            ])

        print(Fore.CYAN + "─" * 105 + Style.RESET_ALL)

    # ------------------------------------------------------------------
    # 3. Aktif tarama
    # ------------------------------------------------------------------
    def aktif_tara(
        self,
        url: str,
        param: str,
        post_data: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Belirtilen URL ve parametreye kapsamlı aktif güvenlik taraması uygular.

        Args:
            url:       Hedef URL
            param:     Test edilecek parametre adı (query string veya POST body)
            post_data: POST verisi sözlüğü; verilirse POST isteği kullanılır.

        Returns:
            Bu tarama oturumunda bulunan güvenlik açıklarının listesi.
        """
        _baslik(f"Aktif Tarama → {url}  [param={param}]")
        oturum_bulgular: List[Dict[str, Any]] = []

        # Temel yanıtı al (baseline)
        temel = self._istek_gonder(url, param, "BASELINE_VALUE", post_data)

        # --- a. SQL Injection ---
        print(_renkli("\n[*] SQL Injection probeleri...", Fore.CYAN))
        for probe in SQL_PROBES:
            yanit = self._istek_gonder(url, param, probe, post_data)
            if yanit and self._sql_hata_var_mi(yanit):
                bulgu = self._bulgu_ekle("sql_injection", url, param, probe, "SQL hata mesajı tespit edildi")
                oturum_bulgular.append(bulgu)
                print(_renkli(f"  [!] SQL Injection: probe={probe!r}", Fore.RED))

        # --- b. XSS ---
        print(_renkli("\n[*] XSS probeleri...", Fore.CYAN))
        for probe in XSS_PROBES:
            yanit = self._istek_gonder(url, param, probe, post_data)
            if yanit and probe.lower() in (yanit.text or "").lower():
                bulgu = self._bulgu_ekle("xss", url, param, probe, "XSS yansıması tespit edildi")
                oturum_bulgular.append(bulgu)
                print(_renkli(f"  [!] XSS: probe={probe!r}", Fore.RED))

        # --- c. Path Traversal ---
        print(_renkli("\n[*] Path Traversal probeleri...", Fore.CYAN))
        for probe in PATH_TRAVERSAL_PROBES:
            yanit = self._istek_gonder(url, param, probe, post_data)
            if yanit and re.search(r"root:.*:0:0:", yanit.text or ""):
                bulgu = self._bulgu_ekle("path_traversal", url, param, probe, "/etc/passwd içeriği tespit edildi")
                oturum_bulgular.append(bulgu)
                print(_renkli(f"  [!] Path Traversal: probe={probe!r}", Fore.RED))

        # --- d. SSTI ---
        print(_renkli("\n[*] SSTI probeleri...", Fore.CYAN))
        for probe in SSTI_PROBES:
            yanit = self._istek_gonder(url, param, probe, post_data)
            if yanit and "49" in (yanit.text or ""):
                bulgu = self._bulgu_ekle("ssti", url, param, probe, "7*7=49 SSTI yanıtı tespit edildi")
                oturum_bulgular.append(bulgu)
                print(_renkli(f"  [!] SSTI: probe={probe!r}", Fore.RED))

        # --- e. Command Injection ---
        print(_renkli("\n[*] Command Injection probeleri...", Fore.CYAN))
        for probe in CMD_INJECTION_PROBES:
            yanit = self._istek_gonder(url, param, probe, post_data)
            if yanit and re.search(r"uid=\d+\(", yanit.text or ""):
                bulgu = self._bulgu_ekle("cmd_injection", url, param, probe, "id komutu çıktısı tespit edildi")
                oturum_bulgular.append(bulgu)
                print(_renkli(f"  [!] Command Injection: probe={probe!r}", Fore.RED))

        # --- f. SSRF ---
        print(_renkli("\n[*] SSRF probeleri...", Fore.CYAN))
        for probe in SSRF_PROBES:
            yanit = self._istek_gonder(url, param, probe, post_data)
            if yanit and yanit.status_code == 200 and len(yanit.text or "") > 0:
                bulgu = self._bulgu_ekle("ssrf_aws", url, param, probe, "SSRF yanıtı alındı — metadata erişimi olası")
                oturum_bulgular.append(bulgu)
                print(_renkli(f"  [!] SSRF: probe={probe!r}", Fore.RED))

        # --- g. HTTP Request Smuggling ---
        print(_renkli("\n[*] HTTP Request Smuggling kontrolü...", Fore.CYAN))
        smuggling_tespit = self._http_smuggling_kontrol(url)
        if smuggling_tespit:
            bulgu = self._bulgu_ekle("http_smuggling", url, param, "CL+TE conflict", "HTTP Request Smuggling işareti tespit edildi")
            oturum_bulgular.append(bulgu)
            print(_renkli("  [!] HTTP Request Smuggling işareti var!", Fore.RED))

        # --- h. JWT none algorithm ---
        print(_renkli("\n[*] JWT none algorithm kontrolü...", Fore.CYAN))
        jwt_tespit = self._jwt_none_kontrol(url)
        if jwt_tespit:
            bulgu = self._bulgu_ekle("jwt_none", url, param, "alg=none", "JWT none algorithm bypass kabul ediliyor")
            oturum_bulgular.append(bulgu)
            print(_renkli("  [!] JWT none algorithm açığı!", Fore.RED))

        # --- i. XXE ---
        print(_renkli("\n[*] XXE probeleri...", Fore.CYAN))
        yanit = self._istek_gonder(url, param, XXE_PAYLOAD, post_data, content_type="application/xml")
        if yanit and re.search(r"root:.*:0:0:", yanit.text or ""):
            bulgu = self._bulgu_ekle("xxe", url, param, XXE_PAYLOAD[:40], "/etc/passwd XXE ile okundu")
            oturum_bulgular.append(bulgu)
            print(_renkli("  [!] XXE açığı!", Fore.RED))

        # --- j. GraphQL Introspection ---
        print(_renkli("\n[*] GraphQL Introspection kontrolü...", Fore.CYAN))
        parsed = urlparse(url)
        gql_url = f"{parsed.scheme}://{parsed.netloc}/graphql"
        try:
            gql_yanit = self.http.post(gql_url, json={"query": "{__schema{types{name}}}"}, timeout=8)
            if gql_yanit.status_code == 200 and "__schema" in (gql_yanit.text or ""):
                bulgu = self._bulgu_ekle("graphql_introspect", gql_url, "body", GRAPHQL_INTROSPECT_PAYLOAD, "GraphQL introspection açık")
                oturum_bulgular.append(bulgu)
                print(_renkli("  [!] GraphQL Introspection açık!", Fore.RED))
        except Exception:
            pass

        if not oturum_bulgular:
            print(_renkli("\n[+] Bu taramada açık tespit edilmedi.", Fore.GREEN))

        return oturum_bulgular

    # ------------------------------------------------------------------
    # 4. Fark analizi
    # ------------------------------------------------------------------
    def fark_analiz(self, url: str, param: str, probe: str) -> Dict[str, Any]:
        """
        Normal yanıt ile probe yanıtını karşılaştırarak fark tespiti yapar.

        Args:
            url:   Hedef URL
            param: Test edilecek parametre
            probe: Karşılaştırılacak probe değeri

        Returns:
            Fark bilgilerini içeren sözlük.
        """
        temel_yanit = self._istek_gonder(url, param, "BASELINE_SAFE_VALUE_12345", None)
        probe_yanit  = self._istek_gonder(url, param, probe, None)

        if not temel_yanit or not probe_yanit:
            return {"hata": "Yanıt alınamadı"}

        temel_metin = temel_yanit.text or ""
        probe_metin  = probe_yanit.text or ""

        kod_farki   = probe_yanit.status_code != temel_yanit.status_code
        boyut_farki = abs(len(probe_metin) - len(temel_metin))
        icerik_farki = temel_metin != probe_metin

        fark: Dict[str, Any] = {
            "url":              url,
            "param":            param,
            "probe":            probe,
            "temel_kod":        temel_yanit.status_code,
            "probe_kod":        probe_yanit.status_code,
            "kod_farki":        kod_farki,
            "temel_boyut":      len(temel_metin),
            "probe_boyut":      len(probe_metin),
            "boyut_farki":      boyut_farki,
            "icerik_farki":     icerik_farki,
            "anomali":          kod_farki or boyut_farki > 50,
        }

        _baslik("Fark Analizi")
        for k, v in fark.items():
            renk = Fore.RED if (k == "anomali" and v) else Fore.WHITE
            print(_renkli(f"  {k:<20}: {v}", renk))

        return fark

    # ------------------------------------------------------------------
    # 5. Rapor oluştur
    # ------------------------------------------------------------------
    def rapor_olustur(self) -> Dict[str, Any]:
        """
        Tüm bulgulardan kapsamlı bir rapor üretir.

        Returns:
            Rapor bilgilerini içeren sözlük.
        """
        ozet: Dict[str, int] = {}
        for bulgu in self._bulgular:
            tip = bulgu.get("tip", "bilinmeyen")
            ozet[tip] = ozet.get(tip, 0) + 1

        rapor: Dict[str, Any] = {
            "olusturma_zamani":  datetime.now().isoformat(),
            "toplam_istek":      len(self._gecmis),
            "toplam_bulgu":      len(self._bulgular),
            "bulgu_ozeti":       ozet,
            "desteklenen_vuln":  MODERN_VULN_TIPLERI,
            "bulgular":          copy.deepcopy(self._bulgular),
            "gecmis":            copy.deepcopy(self._gecmis),
        }

        _baslik("Güvenlik Raporu")
        print(_renkli(f"  Toplam İstek : {rapor['toplam_istek']}", Fore.CYAN))
        print(_renkli(f"  Toplam Bulgu : {rapor['toplam_bulgu']}", Fore.RED if rapor["toplam_bulgu"] > 0 else Fore.GREEN))
        if ozet:
            print(_renkli("\n  Bulgu Özeti:", Fore.YELLOW))
            for tip, adet in ozet.items():
                aciklama = MODERN_VULN_TIPLERI.get(tip, tip)
                print(_renkli(f"    [{adet}x] {tip:<25} — {aciklama}", Fore.RED))

        return rapor

    # ------------------------------------------------------------------
    # Yardımcı / dahili metodlar
    # ------------------------------------------------------------------

    def _istek_gonder(
        self,
        url: str,
        param: str,
        deger: str,
        post_data: Optional[Dict[str, str]],
        content_type: str = "application/x-www-form-urlencoded",
    ) -> Any:
        """Parametre değerini değiştirerek GET veya POST isteği gönderir."""
        try:
            if post_data is not None:
                data = dict(post_data)
                data[param] = deger
                headers = {"Content-Type": content_type}
                yanit = self.http.post(url, data=data, headers=headers, timeout=10)
            else:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [deger]
                flat_qs = {k: v[0] for k, v in qs.items()}
                tam_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat_qs)}"
                yanit = self.http.get(tam_url, timeout=10)
            return yanit
        except Exception as exc:
            self._log(_renkli(f"[BurpInspector] İstek hatası ({url}): {exc}", Fore.RED))
            return None

    def _sql_hata_var_mi(self, yanit: Any) -> bool:
        """Yanıt metninde bilinen SQL hata kalıplarını arar."""
        sql_hata_kaliplari = [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"pg_query\(\)",
            r"sqlite_",
            r"ora-\d{4,5}",
            r"microsoft sql server",
            r"odbc sql server driver",
        ]
        metin = (yanit.text or "").lower()
        return any(re.search(pat, metin) for pat in sql_hata_kaliplari)

    def _http_smuggling_kontrol(self, url: str) -> bool:
        """
        Content-Length + Transfer-Encoding çakışmasını tespit etmeye çalışır.
        Gerçek smuggling saldırısı yapmak yerine sunucu davranışını gözlemler.
        """
        try:
            cakisma_basliklar = {
                "Content-Length":    "6",
                "Transfer-Encoding": "chunked",
                "Content-Type":      "application/x-www-form-urlencoded",
            }
            yanit = self.http.post(
                url,
                data="0\r\n\r\n",
                headers=cakisma_basliklar,
                timeout=10,
            )
            # 400 Bad Request veya beklenmedik davranış işaret olabilir
            return yanit.status_code in (400, 408, 500, 502, 503)
        except Exception:
            return False

    def _jwt_none_kontrol(self, url: str) -> bool:
        """
        Authorization başlığına alg=none JWT göndererek kabul edilip edilmediğini test eder.
        """
        import base64
        import json

        try:
            header  = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            payload = base64.urlsafe_b64encode(json.dumps({"sub": "burp_test", "role": "admin"}).encode()).rstrip(b"=").decode()
            token   = f"{header}.{payload}."
            yanit = self.http.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            # 200 döndürmesi kabul edildiğini işaret edebilir
            return yanit.status_code == 200
        except Exception:
            return False

    def _bulgu_ekle(
        self,
        tip: str,
        url: str,
        param: str,
        probe: str,
        aciklama: str,
    ) -> Dict[str, Any]:
        """Yeni bir güvenlik bulgusunu iç listeye ekler ve döndürür."""
        bulgu: Dict[str, Any] = {
            "tip":        tip,
            "url":        url,
            "param":      param,
            "probe":      probe,
            "aciklama":   aciklama,
            "zaman":      datetime.now().isoformat(timespec="seconds"),
            "onem":       self._onem_seviyesi(tip),
        }
        self._bulgular.append(bulgu)
        return bulgu

    def _onem_seviyesi(self, tip: str) -> str:
        """Zafiyet tipine göre önem seviyesi döndürür."""
        kritik = {"sql_injection", "cmd_injection", "xxe", "path_traversal", "http_smuggling", "ssrf_aws"}
        yuksek = {"xss", "ssti", "jwt_none"}
        orta   = {"graphql_introspect", "nosql_operator", "prototype_pollution", "mass_assignment"}
        if tip in kritik:
            return "KRİTİK"
        if tip in yuksek:
            return "YÜKSEK"
        if tip in orta:
            return "ORTA"
        return "DÜŞÜK"

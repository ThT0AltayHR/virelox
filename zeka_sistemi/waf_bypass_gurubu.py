"""
VIRELOX WAF Bypass Grubu v2 — Geriye uyumlu sarmalayıcı
Mozilla Public License 2.0 — AltayHR Developers
"""
from .waf_bypass_stratejileri import WAFBypassGrubu, WafBypassStrateji
from .waf_bypass_havuzu import WAFTespitMotoru

class WAFBypassGrubuV2(WAFBypassGrubu):
    """WAF tespiti + otomatik bypass zinciri"""

    def __init__(self, http_istemci, log_func=None):
        super().__init__()
        self.http        = http_istemci
        self.log         = log_func or (lambda m: None)
        self._tespit_mot = WAFTespitMotoru(http_istemci, log_func)
        self.aktif_waf: str = "Generic"

    def waf_tespit_ve_bypass_hazirla(self, url: str) -> dict:
        self.log("[WAF-BYPASS] WAF tespiti yapılıyor...")
        sonuc = self._tespit_mot.tespit_et(url)
        if sonuc["waf_var"]:
            self.aktif_waf = sonuc["waf_adi"]
            self.log(f"[WAF-BYPASS] {self.aktif_waf} tespit edildi — bypass hazırlanıyor")
        else:
            self.log("[WAF-BYPASS] WAF bulunamadı")
        return sonuc

    def payload_bypass_et(self, payload: str, waf_adi: str = None) -> str:
        return super().payload_bypass_et(payload, waf_adi or self.aktif_waf)

"""
VIRELOX WAF Tespit Grubu — Pasif + Aktif Çift Kanal
Mozilla Public License 2.0 — AltayHR Developers
"""
from .waf_bypass_havuzu import WAFTespitMotoru

class WAFTespitGrubu:
    def __init__(self, http_istemci, log_func=None):
        self.http  = http_istemci
        self.log   = log_func or (lambda m: None)
        self._motor = WAFTespitMotoru(http_istemci, log_func)

    def tam_tespit(self, url: str) -> dict:
        self.log("[WAF] Tespit başlatılıyor...")
        sonuc = self._motor.tespit_et(url)
        durum = "TESPIT EDILDI" if sonuc["waf_var"] else "WAF YOK"
        self.log(f"[WAF] {durum} — {sonuc.get('waf_adi','')}")
        return sonuc

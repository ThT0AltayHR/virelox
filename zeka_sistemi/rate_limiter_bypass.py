"""VIRELOX Rate Limiter Bypass Teknikleri v4.0"""
import random
import time


class RateLimiterBypass:
    """Hedef rate limit'ini atlatmak için teknikler."""

    TEKNIKLER = ["ip_rotate", "header_spoof", "slow_drip", "case_variation", "encoding_variation"]

    def __init__(self, http_istemci, gecikme=0.5):
        self.http = http_istemci
        self.gecikme = gecikme

    def ip_spoof_header(self) -> dict:
        """X-Forwarded-For, X-Real-IP vb ile IP sahteciliği headerları döner."""
        def rastgele_ip():
            return ".".join(str(random.randint(1, 254)) for _ in range(4))

        return {
            "X-Forwarded-For": rastgele_ip(),
            "X-Real-IP": rastgele_ip(),
            "X-Originating-IP": rastgele_ip(),
            "X-Remote-IP": rastgele_ip(),
            "X-Client-IP": rastgele_ip(),
            "CF-Connecting-IP": rastgele_ip(),
            "True-Client-IP": rastgele_ip(),
        }

    def yavash_tarama(self, url, parametreler, gecikme_araliği=(1, 3)):
        """Rate limit'e takılmamak için parametreler arasında random gecikme ile tara."""
        sonuclar = []
        for param in parametreler:
            time.sleep(random.uniform(*gecikme_araliği))
            sonuclar.append({"param": param, "tarama_zamani": time.time()})
        return sonuclar

    def bypass_dene(self, url, param, payload, yontem="ip_rotate") -> dict:
        """Seçili bypass yöntemiyle injection dener."""
        yanit_kodu = 0
        basarili = False
        try:
            if yontem == "ip_rotate":
                spoof = self.ip_spoof_header()
                yanit = self.http.post(url, data={param: payload}, headers=spoof, timeout=10)
                yanit_kodu = yanit.status_code
                basarili = yanit_kodu not in (429, 503)
            elif yontem == "slow_drip":
                time.sleep(random.uniform(1, 3))
                yanit = self.http.post(url, data={param: payload}, timeout=15)
                yanit_kodu = yanit.status_code
                basarili = yanit_kodu not in (429, 503)
            elif yontem == "header_spoof":
                spoof = self.ip_spoof_header()
                spoof["User-Agent"] = "Mozilla/5.0 (compatible; Googlebot/2.1)"
                yanit = self.http.post(url, data={param: payload}, headers=spoof, timeout=10)
                yanit_kodu = yanit.status_code
                basarili = yanit_kodu not in (429, 503)
            elif yontem == "case_variation":
                payload_var = "".join(
                    c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
                )
                yanit = self.http.post(url, data={param: payload_var}, timeout=10)
                yanit_kodu = yanit.status_code
                basarili = yanit_kodu not in (429, 503)
            elif yontem == "encoding_variation":
                from urllib.parse import quote
                payload_enc = quote(payload, safe="")
                yanit = self.http.post(url, data={param: payload_enc}, timeout=10)
                yanit_kodu = yanit.status_code
                basarili = yanit_kodu not in (429, 503)
            else:
                yanit = self.http.post(url, data={param: payload}, timeout=10)
                yanit_kodu = yanit.status_code
                basarili = yanit_kodu not in (429, 503)
        except Exception:
            basarili = False
        return {"basarili": basarili, "yontem": yontem, "yanit_kodu": yanit_kodu}

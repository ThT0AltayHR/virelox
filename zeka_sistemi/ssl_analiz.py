"""
VIRELOX SSL/TLS Analiz Modülü v4.0
SSL sertifika geçerliliği, protokol ve güvenlik uyarıları
Mozilla Public License 2.0 — AltayHR Developers
"""

import ssl
import socket
import datetime
import urllib.parse
from typing import Dict, Callable, Optional


class SSLAnaliz:
    def __init__(self, log_func: Optional[Callable] = None):
        self.log = log_func or (lambda m: None)

    def analiz_et(self, url: str) -> Dict:
        parsed = urllib.parse.urlparse(url)
        host   = parsed.hostname or parsed.netloc.split(':')[0]
        port   = parsed.port or (443 if parsed.scheme == 'https' else 443)

        sonuc = {
            "guvenli": False,
            "protokol": None,
            "kalan_gun": None,
            "bitis_tarihi": None,
            "konu": None,
            "veren": None,
            "uyarilar": [],
        }

        if parsed.scheme != 'https':
            sonuc["uyarilar"].append("HTTPS kullanılmıyor — trafik şifrelenmemiş!")
            return sonuc

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    sonuc["protokol"] = proto

                    # Zayıf protokol kontrolü
                    if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        sonuc["uyarilar"].append(
                            f"Zayıf TLS protokolü: {proto} (en az TLS 1.2 önerilir)")

                    # Sertifika bitiş tarihi
                    bitis = cert.get('notAfter')
                    if bitis:
                        try:
                            bitis_dt = datetime.datetime.strptime(bitis, "%b %d %H:%M:%S %Y %Z")
                            kalan = (bitis_dt - datetime.datetime.utcnow()).days
                            sonuc["kalan_gun"]    = kalan
                            sonuc["bitis_tarihi"] = bitis_dt.strftime("%Y-%m-%d")
                            if kalan < 0:
                                sonuc["uyarilar"].append("Sertifika SÜRESİ DOLMUŞ!")
                            elif kalan < 30:
                                sonuc["uyarilar"].append(
                                    f"Sertifika {kalan} gün içinde dolacak!")
                        except Exception:
                            pass

                    # Konu ve veren
                    subj = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    sonuc["konu"]  = subj.get("commonName", "?")
                    sonuc["veren"] = issuer.get("organizationName", "?")

                    # Self-signed uyarısı
                    if subj == issuer:
                        sonuc["uyarilar"].append("Self-signed sertifika tespit edildi!")

                    if not sonuc["uyarilar"]:
                        sonuc["guvenli"] = True

        except ssl.SSLCertVerificationError as e:
            sonuc["uyarilar"].append(f"Sertifika doğrulama hatası: {e}")
        except ssl.SSLError as e:
            sonuc["uyarilar"].append(f"SSL hatası: {e}")
        except ConnectionRefusedError:
            sonuc["uyarilar"].append(f"SSL bağlantısı reddedildi ({host}:{port})")
        except Exception as e:
            sonuc["uyarilar"].append(f"SSL analiz hatası: {e}")

        return sonuc

"""VIRELOX Fingerprint Bypass + Honeypot Tespiti v4.0"""
import random


class FingerprintBypass:
    TARAYICI_USERAGENTLAR = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "python-requests/2.31.0",  # baseline
        "curl/7.88.1",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]
    KABUL_DILLERI = [
        "tr-TR,tr;q=0.9,en-US;q=0.8",
        "en-US,en;q=0.9",
        "de-DE,de;q=0.9,en;q=0.8",
    ]

    def gizli_header_olustur(self) -> dict:
        """Bot tespitini önleyen gerçekçi header seti oluşturur."""
        ua = random.choice(self.TARAYICI_USERAGENTLAR[:3])  # sadece gerçek tarayıcılar
        dil = random.choice(self.KABUL_DILLERI)
        return {
            "User-Agent": ua,
            "Accept-Language": dil,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0",
        }

    def honeypot_tespit(self, http_istemci, url) -> bool:
        """
        Honeypot/trap tespiti: sunucunun garip yanıt verip vermediğini kontrol eder.
        Tuzak belirtileri: her isteğe 200 OK + aynı içerik, sonsuz redirect,
        olağandışı büyük boş yanıt, ya da robot.txt'de listelenmemiş izinler.
        """
        sari_bayraklar = 0
        try:
            # Test 1: Rastgele olmayan bir path için bile 200 dönüyorsa şüpheli
            sahte_yol = url.rstrip("/") + "/honeypot_olmayan_yol_xyzabc123"
            y1 = http_istemci.get(sahte_yol, timeout=8, allow_redirects=False)
            if y1.status_code == 200:
                sari_bayraklar += 1

            # Test 2: Farklı iki istek için yanıt boyutu tamamen aynıysa şüpheli
            y2a = http_istemci.get(url, timeout=8)
            y2b = http_istemci.get(url, timeout=8)
            if abs(len(y2a.content) - len(y2b.content)) == 0 and len(y2a.content) < 50:
                sari_bayraklar += 1

            # Test 3: Aşırı yönlendirme zinciri
            y3 = http_istemci.get(url, timeout=8, allow_redirects=True)
            gecmis = getattr(y3, "history", [])
            if len(gecmis) > 5:
                sari_bayraklar += 1

        except Exception:
            pass

        return sari_bayraklar >= 2

    def cdn_bypass(self, url) -> str:
        """CDN origin IP tespiti için subdomain enum ve ipucu döner."""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]
        adaylar = [
            f"origin.{host}",
            f"direct.{host}",
            f"backend.{host}",
            f"www.{host}",
            f"mail.{host}",
            f"ftp.{host}",
        ]
        ipucu = (
            f"CDN origin tespiti için şu subdomain'leri dene: {', '.join(adaylar)}. "
            "Ayrıca SecurityTrails/Shodan/Censys üzerinde geçmiş DNS kayıtlarını kontrol et."
        )
        return ipucu

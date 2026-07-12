"""
yanit_dogrulayici.py — VIRELOX v4.0 Keskin Nişancı (Sniper) Yanıt Doğrulayıcı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ResponseValidator  : HTTP yanıtının HTML/JS gürültüsü mü yoksa gerçek SQLi
                     imzası mı içerdiğini tespit eder. Sadece aşağıdakileri
                     kabul eder:
                       • Gerçek DB hata mesajları  (SQL Syntax Error vb.)
                       • Anlamlı boolean TRUE/FALSE uzunluk farkları
                       • Marker'ı yanıtta görüp HTML/JS oranı düşük veriler
                     <script>, <html>, <div> gibi yapılar içerip DB imzası
                     taşımayan yanıtları reddeder.

ConsistencyChecker : Hash/OOB/zaman-tabanlı payload'lar için 3 ardışık sorgu
                     tutarlılık testi — arka arkaya 3 sorguda veri tutarlılığı
                     sağlanamazsa payload otomatik discard edilir.

HedefProfilleyici  : WAF durumu, yanıt hızı ve ani açık hassasiyetine bakarak
                     "zayıf / orta / güçlü" profil çıkarır; motor bu profile
                     göre payload miktarı ve strateji kalibrasyon yapar.

Mozilla Public License 2.0 — AltayHR Developers
"""
import re
import time
import statistics
from typing import Optional, Callable, Dict, Any, Tuple, List


# ─────────────────────────────────────────────────────────────────────────────
# Yardımcı regex'ler
# ─────────────────────────────────────────────────────────────────────────────
_HTML_TAG_RE = re.compile(
    r'<(?:html|head|body|div|span|section|article|nav|header|footer|main|aside'
    r'|p|a|ul|ol|li|table|thead|tbody|tr|td|th|form|input|button|select|option'
    r'|textarea|label|script|style|link|meta|iframe|img|video|audio|canvas'
    r'|template|svg|path|br|hr)[^>]*>',
    re.IGNORECASE
)
_JS_BLOCK_RE = re.compile(r'<script[\s\S]*?</script>', re.IGNORECASE)
_CSS_BLOCK_RE = re.compile(r'<style[\s\S]*?</style>', re.IGNORECASE)

# SQL hata kalıpları — HataDeseniTespiti ile örtüşen kısa özet
_SQL_ERR_RE = re.compile(
    r'(SQL syntax.*?error|ORA-\d{4,5}|SQLSTATE|Unclosed quotation mark'
    r'|Warning.*?mysql|MySQLSyntaxError|PostgreSQL.*?ERROR|PG::SyntaxError'
    r'|Incorrect syntax near|ODBC.*?Driver|SQLite.*?Exception|sqlite3\.\w+Error'
    r'|DB2 SQL error|invalid input syntax|Conversion failed|dynamic sql error'
    r'|operand should contain|com\.mysql\.jdbc|System\.Data\.SqlClient'
    r'|Zend_Db|PSQLException|OperationalError|ProgrammingError)',
    re.IGNORECASE | re.DOTALL
)

# Boolean-TRUE imzası aranacak minimal içerik belirteci
_POSITIVE_SIGNALS = re.compile(
    r'(True|1=1|admin|welcome|success|authenticated|logged in|dashboard)',
    re.IGNORECASE
)


class ResponseValidator:
    """
    Keskin Nişancı Yanıt Doğrulayıcı.

    Kullanım:
        rv = ResponseValidator(html_esik=0.35, log_func=log)
        if rv.veri_blogu_mu(yanit.text, marker="VLX_ABC"):
            ...
        if rv.sqli_imzasi_var_mi(yanit.text):
            ...
    """

    # HTML etiket oranı bu eşiği aşarsa yanıt "gürültü" sayılır (0.0–1.0)
    _HTML_ESIK = 0.35

    def __init__(self, html_esik: float = 0.35, log_func=None):
        self._html_esik = html_esik
        self.log = log_func or (lambda m: None)

    # ── Yardımcılar ──────────────────────────────────────────────────────────

    @staticmethod
    def html_gurultu_orani(icerik: str) -> float:
        """
        İçerikteki HTML etiket karakterlerinin toplam içeriğe oranını döner.
        JS ve CSS blokları önceden soyulur; saf metin oranını ölçer.
        Dönen değer: 0.0 (saf metin) — 1.0 (tamamen HTML).
        """
        if not icerik:
            return 0.0
        temiz = _JS_BLOCK_RE.sub("", icerik)
        temiz = _CSS_BLOCK_RE.sub("", temiz)
        etiketler = _HTML_TAG_RE.findall(temiz)
        etiket_karakter = sum(len(e) for e in etiketler)
        toplam = max(len(temiz), 1)
        return etiket_karakter / toplam

    @staticmethod
    def sqli_imzasi_var_mi(icerik: str) -> bool:
        """Gerçek bir DB hata mesajı veya SQL hata deseni var mı?"""
        return bool(_SQL_ERR_RE.search(icerik))

    def html_gurultusunu_filtrele(self, icerik: str) -> str:
        """JS ve CSS bloklarını soyarak geri kalan metin gövdesini döner."""
        temiz = _JS_BLOCK_RE.sub(" ", icerik)
        temiz = _CSS_BLOCK_RE.sub(" ", temiz)
        temiz = re.sub(r'<[^>]+>', " ", temiz)
        temiz = re.sub(r'\s{2,}', " ", temiz)
        return temiz.strip()

    # ── Ana doğrulama metodları ───────────────────────────────────────────────

    def veri_blogu_mu(self, icerik: str, marker: str = "",
                      dbms: str = "") -> bool:
        """
        Yanıt gerçek bir DB veri bloğu mu?

        Kabul kriterleri (herhangi biri yeterliyse True):
          1. İçerik DB hata imzası taşıyor (SQL error)
          2. Marker varsa ve HTML gürültü oranı eşiğin altında
          3. HTML etiket oranı çok düşük (< 0.05) → saf metin → muhtemelen veri

        Red kriterleri:
          • Marker yok VE HTML gürültü oranı eşiğin üstünde (gürültü sayfa)
          • İçerik sadece JS/HTML bloklarından oluşuyor
        """
        if not icerik:
            return False

        # 1. DB hata imzası — her zaman geçerli
        if self.sqli_imzasi_var_mi(icerik):
            return True

        oran = self.html_gurultu_orani(icerik)

        # 2. Marker varsa ve gürültü düşükse
        if marker and marker in icerik:
            if oran <= self._html_esik:
                return True
            # Marker var ama yoğun HTML; marker HTML attribute'da mı yansıtılıyor?
            # Eğer marker bir SQL anahtar kelimesi içermiyorsa bu bir yansıma,
            # gerçek veri değil — reddet.
            self.log(f"[VALIDATOR] Marker bulundu ama HTML oranı yüksek ({oran:.2f}) — reddedildi")
            return False

        # 3. Saf metin yanıt (REST API benzeri, düşük HTML)
        if oran < 0.05:
            return True

        return False

    def boolean_fark_anlamli_mi(
        self,
        dogru_len: int,
        yanlis_len: int,
        referans_len: int,
        tolerans_oran: float = 0.02,
        min_fark: int = 8,
    ) -> bool:
        """
        Boolean-blind testte TRUE/FALSE yanıt farkı anlamlı mı?

        Anlamlı sayılma koşulları:
          • TRUE yanıtı referansa yakın (tolerans_oran dahilinde)
          • FALSE yanıtı referanstan belirgin farklı (> min_fark VE > tolerans)
          • TRUE ile FALSE arasındaki fark hem min_fark'tan hem de toleranstan büyük
        """
        tolerans = max(min_fark, int(referans_len * tolerans_oran))
        dogru_ref_fark  = abs(dogru_len  - referans_len)
        yanlis_ref_fark = abs(yanlis_len - referans_len)
        dogru_yanlis_fark = abs(dogru_len - yanlis_len)

        return (
            dogru_ref_fark  <= tolerans and
            yanlis_ref_fark  > tolerans and
            dogru_yanlis_fark > min_fark
        )

    def union_veri_temiz_mi(self, deger: str) -> bool:
        """
        UNION sorgusundan dönen değer gerçek bir DB verisi mi yoksa
        yansıtılmış SQL/payload mı?

        SQL anahtar kelimesi içeriyorsa (yansıma) → False.
        HTML tag içeriyorsa → False (HTML çıktısına gömülü, gerçek değil).
        """
        if not deger:
            return False
        # SQL yansıması kontrolü
        if re.search(
            r'\b(SELECT|FROM|WHERE|GROUP_CONCAT|CONCAT|UNION|INSERT|UPDATE'
            r'|INFORMATION_SCHEMA|pragma_table_info|sqlite_master'
            r'|pg_catalog|sys\.tables|information_schema)\b',
            deger, re.IGNORECASE
        ):
            return False
        # HTML tag gömülüyse (değer bir HTML sayfasından geliyorsa)
        if _HTML_TAG_RE.search(deger[:500]):
            return False
        return True

    def yanit_puanla(self, icerik: str) -> Dict[str, Any]:
        """
        Yanıtı puanla ve bir özet döner — debug/loglama için kullanışlı.
        Dönen dict: {sql_imzasi, html_orani, uzunluk, temiz_metin_uzunluk, puan}
        """
        sql = self.sqli_imzasi_var_mi(icerik)
        oran = self.html_gurultu_orani(icerik)
        temiz = self.html_gurultusunu_filtrele(icerik)
        puan = (1.0 if sql else 0.0) + max(0.0, (1.0 - oran) * 0.5)
        return {
            "sql_imzasi": sql,
            "html_orani": round(oran, 3),
            "uzunluk": len(icerik),
            "temiz_metin_uzunluk": len(temiz),
            "puan": round(puan, 2),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Tutarlılık Denetçisi — OOB / Hash tabanlı payload'lar için
# ─────────────────────────────────────────────────────────────────────────────

class ConsistencyChecker:
    """
    3-Sorgu Tutarlılık Denetçisi.

    Hash/OOB tabanlı payload'larda aynı sorguyu 3 kez çalıştırır ve:
      • 3 sonuç da aynıysa (veya boş değilse) → tutarlı → payload KABUL
      • 3 sorguda tutarlı veri sağlanamazsa      → payload DİSCARD

    Kullanım:
        cc = ConsistencyChecker(log_func=log)
        tutarli, deger = cc.kontrol(
            sorgu_func=lambda: motor.union_sorgu_calistir(url, param, "SELECT user()"),
            deneme=3
        )
    """

    def __init__(self, log_func=None):
        self.log = log_func or (lambda m: None)

    def kontrol(
        self,
        sorgu_func: Callable[[], Optional[str]],
        deneme: int = 3,
        bos_gecerli: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """
        sorgu_func'u `deneme` kez çağırır.

        Parametreler:
            sorgu_func  : Sorguyu çalıştıran ve string/None dönen fonksiyon.
            deneme      : Kaç kez çalıştırılacak (varsayılan 3).
            bos_gecerli : Boş/None sonuç tutarlı sayılsın mı? (varsayılan False)

        Dönüş: (tutarli: bool, referans_deger: str|None)
        """
        sonuclar: List[Optional[str]] = []
        for i in range(deneme):
            try:
                val = sorgu_func()
                sonuclar.append(val)
                self.log(f"[CONSISTENCY #{i+1}/{deneme}] → {str(val)[:40] if val else 'None'}")
            except Exception as e:
                self.log(f"[CONSISTENCY #{i+1}/{deneme}] İstisna: {e}")
                sonuclar.append(None)

        gecerli = [s for s in sonuclar if s is not None and (bos_gecerli or s != "")]
        if len(gecerli) < max(1, deneme // 2 + 1):
            self.log(f"[CONSISTENCY] BAŞARISIZ — yeterli geçerli sonuç yok ({len(gecerli)}/{deneme})")
            return False, None

        # En sık tekrarlanan değeri bul
        from collections import Counter
        sayim = Counter(gecerli)
        en_sik, tekrar = sayim.most_common(1)[0]
        esik = max(1, deneme // 2 + 1)  # çoğunluk kuralı

        if tekrar >= esik:
            self.log(f"[CONSISTENCY] BAŞARILI — {tekrar}/{deneme} tutarlı → '{str(en_sik)[:40]}'")
            return True, en_sik

        self.log(f"[CONSISTENCY] BAŞARISIZ — tutarsız sonuçlar: {dict(sayim)}")
        return False, None

    def coklu_kontrol(
        self,
        sorgu_listesi: List[Callable[[], Optional[str]]],
        her_biri_icin_deneme: int = 3,
    ) -> List[Tuple[bool, Optional[str]]]:
        """Birden fazla sorgu fonksiyonunu sırayla kontrol eder."""
        return [self.kontrol(sf, her_biri_icin_deneme) for sf in sorgu_listesi]


# ─────────────────────────────────────────────────────────────────────────────
# Hedef Profilleyici — payload miktarı ve strateji kalibrasyonu
# ─────────────────────────────────────────────────────────────────────────────

class HedefProfilleyici:
    """
    Hedefin 'saldırı yüzeyi profilini' çıkarır:
      • Yanıt hızı   : fast (< 1s) / medium (1-3s) / slow (> 3s)
      • WAF varlığı  : True / False
      • Hassasiyet   : weak (kolay kırılır) / medium / strong (WAF+hızlı engel)
      • Öneri strateji: error_first / union_first / blind_first / time_last

    Bu bilgi InjectionMotor.tam_tara() içinde kullanılarak:
      - Zayıf hedefte → hızlı agresif tarama
      - Güçlü hedefte → dikkatli, tamper + zaman gecikmeli tarama
      - WAF varsa → bypass tamperlarını ilk kullan
    """

    _WAF_BELIRTECLERI = re.compile(
        r'(cloudflare|sucuri|barracuda|incapsula|imperva|f5|bigip|modsecurity'
        r'|akamai|aws.*waf|azure.*waf|wordfence|blocked|forbidden|access denied'
        r'|security check|ddos.?guard|bot detected|challenge page)',
        re.IGNORECASE
    )

    _SQL_HASSAS_RE = re.compile(
        r'(SQL syntax|mysql_fetch|pg_query|ORA-\d|sqlite_\w|Warning.*sql)',
        re.IGNORECASE
    )

    def __init__(self, http_istemci, log_func=None):
        self.http = http_istemci
        self.log  = log_func or (lambda m: None)

    def profil_cikart(self, url: str, param: str = "",
                      hizli_mod: bool = True) -> Dict[str, Any]:
        """
        Hedefi 3–5 istekle hızlıca profilleyip strateji önerisi döner.

        Dönüş örneği::
            {
              "hiz": "fast",          # "fast" | "medium" | "slow"
              "waf": False,
              "waf_adi": None,
              "hassasiyet": "weak",   # "weak" | "medium" | "strong"
              "oneri_strateji": ["error", "union", "boolean", "time"],
              "hata_hassas": True,    # error-based'e yanıt veriyor mu?
              "ortalama_sure": 0.42,
              "profil_aciklama": "Hızlı yanıt, WAF yok, hata tabanlıya hassas"
            }
        """
        self.log("[PROFIL] Hedef profillemesi başlatıldı...")
        profil: Dict[str, Any] = {
            "hiz": "medium",
            "waf": False,
            "waf_adi": None,
            "hassasiyet": "medium",
            "oneri_strateji": ["error", "union", "boolean", "time"],
            "hata_hassas": False,
            "ortalama_sure": 1.0,
            "profil_aciklama": "",
        }

        # ── 1. Yanıt hızı ölç ──────────────────────────────────────────────
        sureler = []
        for _ in range(3 if hizli_mod else 5):
            try:
                t0 = time.time()
                r  = self.http.get(url, timeout=10)
                dt = time.time() - t0
                if r:
                    sureler.append(dt)
            except Exception:
                pass

        if sureler:
            ortalama = statistics.median(sureler)
            profil["ortalama_sure"] = round(ortalama, 3)
            if ortalama < 1.0:
                profil["hiz"] = "fast"
            elif ortalama < 3.0:
                profil["hiz"] = "medium"
            else:
                profil["hiz"] = "slow"
            self.log(f"[PROFIL] Yanıt hızı: {profil['hiz']} ({ortalama:.2f}s)")

        # ── 2. WAF tespiti (basit probe) ───────────────────────────────────
        try:
            probe_url = f"{url}{'&' if '?' in url else '?'}{param or 'id'}=1%27"
            r = self.http.get(probe_url, timeout=8)
            if r:
                icerik = getattr(r, 'text', '')
                kod    = getattr(r, 'status_code', 200)
                if kod in (403, 406, 429, 503) or self._WAF_BELIRTECLERI.search(icerik):
                    profil["waf"] = True
                    # WAF adı bul
                    m = self._WAF_BELIRTECLERI.search(icerik)
                    if m:
                        profil["waf_adi"] = m.group(1).title()
                    self.log(f"[PROFIL] WAF tespit edildi: {profil['waf_adi'] or 'Bilinmeyen'}")
        except Exception:
            pass

        # ── 3. Hata hassasiyeti testi ──────────────────────────────────────
        try:
            hata_url = f"{url}{'&' if '?' in url else '?'}{param or 'id'}='"
            r = self.http.get(hata_url, timeout=8)
            if r:
                icerik = getattr(r, 'text', '')
                if self._SQL_HASSAS_RE.search(icerik):
                    profil["hata_hassas"] = True
                    self.log("[PROFIL] Hata tabanlı SQLi'ye hassas!")
        except Exception:
            pass

        # ── 4. Hassasiyet skoru ────────────────────────────────────────────
        if profil["waf"]:
            profil["hassasiyet"] = "strong"
        elif profil["hata_hassas"] and profil["hiz"] == "fast":
            profil["hassasiyet"] = "weak"
        elif not profil["waf"] and profil["hiz"] in ("fast", "medium"):
            profil["hassasiyet"] = "medium"
        else:
            profil["hassasiyet"] = "strong"

        # ── 5. Strateji önerisi ────────────────────────────────────────────
        if profil["hata_hassas"]:
            profil["oneri_strateji"] = ["error", "union", "boolean", "time", "stacked"]
        elif profil["waf"]:
            # WAF varsa: bypass gerektiren teknikler önce
            profil["oneri_strateji"] = ["boolean", "time", "error", "union", "stacked"]
        elif profil["hassasiyet"] == "weak":
            profil["oneri_strateji"] = ["error", "union", "boolean", "time"]
        else:
            profil["oneri_strateji"] = ["error", "union", "boolean", "time", "stacked"]

        # ── 6. Açıklama ────────────────────────────────────────────────────
        parcalar = []
        parcalar.append(f"Hız: {profil['hiz']} ({profil['ortalama_sure']}s)")
        parcalar.append(f"WAF: {'✔ ' + (profil['waf_adi'] or 'var') if profil['waf'] else '✗ yok'}")
        parcalar.append(f"Hassasiyet: {profil['hassasiyet']}")
        parcalar.append(f"Hata-tabanlı: {'✔' if profil['hata_hassas'] else '✗'}")
        profil["profil_aciklama"] = " | ".join(parcalar)
        self.log(f"[PROFIL] {profil['profil_aciklama']}")

        return profil

    def max_payload_sayisi(self, profil: Dict[str, Any]) -> int:
        """
        Profile göre tarama başına maksimum payload sayısını döner.
        Zayıf hedefler için daha az istek, güçlü/WAF'lı hedefler için
        yeterli bypass varyantı.
        """
        h = profil.get("hassasiyet", "medium")
        if h == "weak":
            return 20   # Zayıf: ilk 20 payload yeterli
        elif h == "medium":
            return 50
        else:
            return 120  # Güçlü/WAF: kapsamlı tarama gerekli

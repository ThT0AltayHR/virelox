"""
VIRELOX İlerleme Takibi — Progress / ETA helper
Mozilla Public License 2.0 — AltayHR Developers

Bağımsız, yalnızca stdlib kullanan yardımcı modül.
Brute-force tablo/kolon taramalarında kullanıcıya gerçek zamanlı
ilerleme, hız ve tahmini süre (ETA) bilgisi verir.

Kullanım örneği:
    from yonetim_sistemi.ilerleme import IlerlemeTakibi

    ilerleme = IlerlemeTakibi(toplam=668, etiket="BRUTE", log_func=self.log)
    for tablo in BRUTE_TABLO_LISTESI:
        # ... HTTP isteği ...
        ilerleme.adim(bulundu_sayisi=len(bulunan), ek_bilgi=tablo)
    ilerleme.bitir(ozet="Tablo taraması tamamlandı")
"""

import time

# Bir satırda gösterilecek azami karakter sayısı (ek_bilgi kırpma için)
_MAX_EK_BILGI_UZUNLUGU = 30


def _sure_biçimle(saniye: float) -> str:
    """Saniyeyi MM:SS biçimine dönüştürür (≥ 1 saat: HH:MM:SS)."""
    saniye = max(0, int(saniye))
    saat, kalan = divmod(saniye, 3600)
    dakika, sn = divmod(kalan, 60)
    if saat:
        return f"{saat:02d}:{dakika:02d}:{sn:02d}"
    return f"{dakika:02d}:{sn:02d}"


class IlerlemeTakibi:
    """
    Kaydırmalı terminal logları için tek satırlık ilerleme / ETA yardımcısı.

    Parametreler
    ------------
    toplam   : Toplam adım sayısı (0 verilirse kenar durum güvenli çalışır).
    etiket   : Log satırı öneki, örn. 'BRUTE' → '[BRUTE-İLERLEME]'.
    log_func : Tek str argüman alan çağrılabilir; varsayılan print.
    min_aralik_sn : Ardışık log satırları arasındaki minimum süre (sn).
    her_n_adimda  : En fazla bu kadar adımda bir log basar (throttle yedek).
    """

    def __init__(
        self,
        toplam: int,
        etiket: str = '',
        log_func=None,
        min_aralik_sn: float = 0.3,
        her_n_adimda: int = 50,
    ):
        self.toplam         = max(0, int(toplam))
        self.etiket         = etiket.strip() if etiket else ''
        self._log           = log_func if callable(log_func) else print
        self._min_aralik_sn = float(min_aralik_sn)
        self._her_n         = max(1, int(her_n_adimda))

        self._baslangic     = time.monotonic()
        self._son_log_zaman = 0.0   # monotonic; 0 → henüz hiç basılmadı
        self._adim_sayisi   = 0     # kaç kez adim() çağrıldı
        self._tamamlandi    = False

        # Başlık satırı
        if self.toplam > 0:
            self._log(self._on_ek() + f"{self.toplam} adım başlatıldı.")
        else:
            self._log(self._on_ek() + "toplam=0, takip atlanıyor.")

    # ------------------------------------------------------------------
    # Dahili yardımcılar
    # ------------------------------------------------------------------

    def _on_ek(self) -> str:
        if self.etiket:
            return f"[{self.etiket}-İLERLEME] "
        return "[İLERLEME] "

    def _gecen_sn(self) -> float:
        return time.monotonic() - self._baslangic

    def _hiz_ve_eta(self, gecen: float):
        """(hiz_str, eta_str) döndürür; ZeroDivisionError korumalı."""
        if gecen <= 0 or self._adim_sayisi == 0:
            return "—/sn", "—"

        hiz = self._adim_sayisi / gecen          # adım/sn

        if self.toplam > 0:
            kalan_adim = self.toplam - self._adim_sayisi
            eta_sn     = kalan_adim / hiz if hiz > 0 else 0.0
            eta_str    = _sure_biçimle(eta_sn)
        else:
            eta_str = "—"

        if hiz >= 1.0:
            hiz_str = f"{hiz:.1f}/sn"
        else:
            # 1'den az adım/sn → adım/dk göster
            hiz_str = f"{hiz * 60:.1f}/dk"

        return hiz_str, eta_str

    def _yuzde(self) -> int:
        if self.toplam <= 0:
            return 0
        return min(100, int(self._adim_sayisi * 100 / self.toplam))

    def _log_satiri_yaz(self, bulundu_sayisi, ek_bilgi: str):
        gecen    = self._gecen_sn()
        hiz_str, eta_str = self._hiz_ve_eta(gecen)
        yuzde    = self._yuzde()

        # Temel parça
        if self.toplam > 0:
            konum = f"{self._adim_sayisi}/{self.toplam} ({yuzde}%)"
        else:
            konum = f"{self._adim_sayisi}/? (—%)"

        parcalar = [konum]

        if bulundu_sayisi is not None:
            parcalar.append(f"{bulundu_sayisi} bulundu")

        parcalar.append(hiz_str)
        parcalar.append(f"ETA: {eta_str}")

        if ek_bilgi:
            kisaltilmis = (
                ek_bilgi[:_MAX_EK_BILGI_UZUNLUGU] + "…"
                if len(ek_bilgi) > _MAX_EK_BILGI_UZUNLUGU
                else ek_bilgi
            )
            parcalar.append(kisaltilmis)

        satir = self._on_ek() + " — ".join(parcalar)
        self._log(satir)
        self._son_log_zaman = time.monotonic()

    # ------------------------------------------------------------------
    # Genel API
    # ------------------------------------------------------------------

    def adim(self, bulundu_sayisi: int = None, ek_bilgi: str = ''):
        """
        Her işlenen öğe için bir kez çağrılır.

        Parametreler
        ------------
        bulundu_sayisi : Şimdiye dek bulunan eşleşme sayısı (opsiyonel).
        ek_bilgi       : Mevcut öğe etiketi, örn. tablo adı (opsiyonel).
        """
        if self._tamamlandi:
            return

        self._adim_sayisi += 1

        simdi = time.monotonic()
        gecen_son_logdan = simdi - self._son_log_zaman

        # Throttle: zaman eşiği VEYA N-adım eşiği — hangisi daha önce tetiklenirse
        zaman_esigi    = gecen_son_logdan >= self._min_aralik_sn
        adim_esigi     = (self._adim_sayisi % self._her_n) == 0
        son_adim       = (self.toplam > 0 and self._adim_sayisi >= self.toplam)

        if zaman_esigi or adim_esigi or son_adim:
            self._log_satiri_yaz(bulundu_sayisi, ek_bilgi)

    def bitir(self, ozet: str = ''):
        """
        Tarama bittiğinde çağrılır; toplam süre özet satırı basar.

        Parametreler
        ------------
        ozet : Ek açıklama metni (opsiyonel).
        """
        self._tamamlandi = True
        gecen = self._gecen_sn()
        sure_str = _sure_biçimle(gecen)

        parcalar = [f"Tamamlandı — {self._adim_sayisi} adım — {sure_str} sürdü"]
        if ozet:
            parcalar.append(ozet)

        self._log(self._on_ek() + " — ".join(parcalar))

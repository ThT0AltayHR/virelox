"""
AkıllıGecikme v1.0 — WAF/Rate-Limit Adaptif Gecikme Yöneticisi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Payload gönderimlerindeki gecikmeyi HTTP yanıt kodlarına göre
dinamik olarak ayarlar.  sqlmap'in --delay mantığını genişletir:

  • HTTP 429 / 503  → gecikmeyi 2× arttır (exponential back-off)
  • HTTP 403 / 406  → gecikmeyi 1.5× arttır + ±%30 jitter ekle
  • HTTP 200 zincirleri → kademeli azaltma (÷1.2)
  • Uzun başarı serisi → min_gecikme'ye yaklaş

InjectionMotor ve SQLInjectionMotoru her istek sonrası
  `gecikme.guncelle(durum_kodu)` + `gecikme.bekle()`
çağırır; bu da aracın WAF tarafından yakalanma riskini düşürür.

Kullanım:
    from zeka_sistemi.akilli_gecikme import AkılliGecikme
    ag = AkılliGecikme(min_gecikme=0.3, max_gecikme=20.0, log_func=log_bilgi)
    ag.guncelle(yanit.status_code)
    ag.bekle()

Mozilla Public License 2.0 — AltayHR Developers
"""

import time
import random
from typing import Optional, Callable


class AkılliGecikme:
    """
    Adaptif gecikme yöneticisi.

    Parametreler
    ────────────
    min_gecikme  : Başarılı isteklerde ulaşılacak alt sınır (saniye).
    max_gecikme  : Hiçbir zaman aşılmayacak üst sınır (saniye).
    baslangic    : İlk gecikme değeri (saniye, varsayılan: min_gecikme).
    jitter       : True → her beklemeye ±%20 rastgele ofsset ekle.
    log_func     : İsteğe bağlı log callback (lambda m: None).
    """

    # Başarılı yanıt sayacı eşiği — bu kadar ard arda başarı → gecikme azalt
    _AZALTMA_ESIGI = 3

    def __init__(
        self,
        min_gecikme: float = 0.0,
        max_gecikme: float = 30.0,
        baslangic: Optional[float] = None,
        jitter: bool = True,
        log_func: Optional[Callable] = None,
    ):
        self._min        = max(0.0, min_gecikme)
        self._max        = max(self._min, max_gecikme)
        self._mevcut     = baslangic if baslangic is not None else self._min
        self._jitter     = jitter
        self.log         = log_func or (lambda m: None)

        self._basari_say = 0   # ard arda başarı sayacı (azaltma için)
        self._engel_say  = 0   # toplam WAF/rate-limit engel sayısı

    # ── Güncelleme ─────────────────────────────────────────────────────────────

    def guncelle(self, durum_kodu: int) -> None:
        """
        HTTP yanıt koduna göre mevcut gecikmeyi günceller.

        Parametreler
        ────────────
        durum_kodu : HTTP status code (200, 403, 429 …)
        """
        if durum_kodu in (429, 503):
            # Rate-limiting veya servis dışı — sert artış
            onceki = self._mevcut
            self._mevcut = min(self._max, self._mevcut * 2.0)
            self._basari_say = 0
            self._engel_say += 1
            self.log(
                f"[DELAY] HTTP {durum_kodu} → gecikme arttı "
                f"{onceki:.2f}s → {self._mevcut:.2f}s  "
                f"(toplam engel={self._engel_say})"
            )

        elif durum_kodu in (403, 406):
            # WAF bloğu — orta artış + jitter
            onceki = self._mevcut
            self._mevcut = min(self._max, self._mevcut * 1.5)
            self._basari_say = 0
            self._engel_say += 1
            self.log(
                f"[DELAY] HTTP {durum_kodu} (WAF) → gecikme arttı "
                f"{onceki:.2f}s → {self._mevcut:.2f}s"
            )

        elif durum_kodu in (200, 301, 302, 304):
            # Başarılı yanıt — sayacı arttır, eşikte azalt
            self._basari_say += 1
            if self._basari_say >= self._AZALTMA_ESIGI and self._mevcut > self._min:
                onceki = self._mevcut
                self._mevcut = max(self._min, self._mevcut / 1.2)
                self._basari_say = 0
                if abs(onceki - self._mevcut) > 0.05:
                    self.log(
                        f"[DELAY] {self._AZALTMA_ESIGI} başarılı istek "
                        f"→ gecikme azaldı {onceki:.2f}s → {self._mevcut:.2f}s"
                    )

    def bekle(self) -> None:
        """Mevcut gecikme kadar bekler.  Jitter aktifse ±%20 rastgele ofset."""
        if self._mevcut <= 0:
            return
        bekleme = self._mevcut
        if self._jitter and bekleme > 0:
            ofset   = bekleme * 0.20
            bekleme = bekleme + random.uniform(-ofset, ofset)
            bekleme = max(0.0, bekleme)
        time.sleep(bekleme)

    def reset(self) -> None:
        """Gecikmeyi min_gecikme değerine sıfırlar."""
        self._mevcut     = self._min
        self._basari_say = 0
        self.log(f"[DELAY] Sıfırlandı → {self._mevcut:.2f}s")

    def mevcut(self) -> float:
        """Şu anki gecikme değerini döner (saniye)."""
        return self._mevcut

    @property
    def engel_sayisi(self) -> int:
        """Toplam kaç kez WAF/rate-limit engeline çarptı."""
        return self._engel_say

    def profil_ozeti(self) -> dict:
        """
        Mevcut gecikme durumunun özetini döner — loglama/raporlama için.
        """
        return {
            "mevcut_gecikme": round(self._mevcut, 3),
            "min_gecikme":    self._min,
            "max_gecikme":    self._max,
            "engel_sayisi":   self._engel_say,
            "basari_sayaci":  self._basari_say,
        }

    # ── Context manager desteği ────────────────────────────────────────────────
    # `with AkılliGecikme(...) as ag:` sözdizimini mümkün kılar.

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def __repr__(self) -> str:
        return (f"AkılliGecikme("
                f"mevcut={self._mevcut:.2f}s, "
                f"engel={self._engel_say})")

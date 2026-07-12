"""
VIRELOX Korelasyon Motoru v4.0
HTTP yanıt parmak izleri ile blind injection doğruluğunu artırır.
Yanıt benzerlik skorlaması, diferansiyel analiz ve anomali tespiti.
Mozilla Public License 2.0 — AltayHR Developers
"""
import re
import hashlib
import difflib
from typing import Dict, List, Optional, Tuple


class KorelasyonMotoru:
    """
    İki HTTP yanıtı arasındaki farkı ölçer ve injection tespit kararına
    katkıda bulunur.

    Kullanım::

        motor = KorelasyonMotoru()
        motor.referans_al(baz_yanit_metni)

        fark = motor.farki_olc(yeni_yanit_metni)
        if fark["injection_olasiligi"] > 0.7:
            # Yüksek injection ihtimali
    """

    # Gürültülü dinamik içerik kalıpları — çıkar, karşılaştırmayı kirletme
    _DINAMIK_KALIPLAR = [
        r'\d{2}:\d{2}:\d{2}',                       # Saat
        r'\d{4}-\d{2}-\d{2}',                        # Tarih
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # UUID
        r'csrfmiddlewaretoken=[^\'"&\s]+',            # CSRF token
        r'XSRF-TOKEN=[^\'"&\s]+',
        r'nonce=[^\'"&\s]{8,}',
        r'_=[0-9]+',                                  # Cache-buster
        r'<script[^>]*>[^<]{0,50}Math\.random',      # RNG script
        r'(?:session|sess)(?:id)?=[a-zA-Z0-9+/]{20,}',
        r'<!--.*?-->',                                 # HTML yorumları
    ]

    def __init__(self):
        self._referans:     Optional[str] = None
        self._referans_boy: int = 0
        self._referans_parmak: Optional[str] = None

    # ── Yardımcılar ──────────────────────────────────────────────────────────

    def _normalize(self, metin: str) -> str:
        """Dinamik içerikleri çıkararak normalize et."""
        for desen in self._DINAMIK_KALIPLAR:
            metin = re.sub(desen, "DYNAMIC", metin, flags=re.IGNORECASE | re.DOTALL)
        # Fazla boşlukları sıkıştır
        metin = re.sub(r'\s+', ' ', metin).strip()
        return metin

    def _parmak_iz(self, metin: str) -> str:
        """Normalize edilmiş metnin MD5 parmak izi."""
        return hashlib.md5(self._normalize(metin).encode(
            "utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _benzerlik(a: str, b: str) -> float:
        """SequenceMatcher ile hızlı benzerlik skoru (0.0 – 1.0)."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()

    # ── Referans kurma ───────────────────────────────────────────────────────

    def referans_al(self, baz_metin: str):
        """Normal (enjeksiyonsuz) yanıtı referans olarak kaydet."""
        self._referans     = baz_metin
        self._referans_boy = len(baz_metin)
        self._referans_parmak = self._parmak_iz(baz_metin)

    def referans_var_mi(self) -> bool:
        return self._referans is not None

    # ── Fark ölçümü ──────────────────────────────────────────────────────────

    def farki_olc(self, yeni_metin: str) -> Dict:
        """
        Yeni yanıtı referansla karşılaştır.

        Returns:
            {
                "boy_farki": int,
                "boy_orani": float,          # yeni/referans
                "benzerlik": float,          # 0.0–1.0
                "parmak_eslesimi": bool,
                "injection_olasiligi": float, # 0.0–1.0
                "anomali": bool,
                "detay": str,
            }
        """
        if self._referans is None:
            return {"hata": "Referans henüz alınmadı"}

        yeni_boy       = len(yeni_metin)
        boy_farki      = abs(yeni_boy - self._referans_boy)
        boy_orani      = yeni_boy / max(self._referans_boy, 1)
        benzerlik      = self._benzerlik(self._referans, yeni_metin)
        parmak_eslesimi = self._parmak_iz(yeni_metin) == self._referans_parmak

        # Injection olasılığı hesaplama
        puan = 0.0

        # Boyut farkı
        if boy_farki > 500:
            puan += 0.35
        elif boy_farki > 100:
            puan += 0.20
        elif boy_farki > 30:
            puan += 0.10

        # Benzerlik düşükse
        if benzerlik < 0.85:
            puan += 0.30
        elif benzerlik < 0.95:
            puan += 0.15

        # Parmak izi farklıysa
        if not parmak_eslesimi:
            puan += 0.15

        # Boy oranı belirgin sapma
        if boy_orani < 0.5 or boy_orani > 2.0:
            puan += 0.20

        puan = min(1.0, puan)

        detay_parcalar = []
        if boy_farki > 30:
            detay_parcalar.append(f"boyut Δ={boy_farki}")
        if benzerlik < 0.95:
            detay_parcalar.append(f"benzerlik={benzerlik:.2f}")
        if not parmak_eslesimi:
            detay_parcalar.append("parmak iz farklı")
        detay = ", ".join(detay_parcalar) or "yanıtlar benzer"

        return {
            "boy_farki":           boy_farki,
            "boy_orani":           round(boy_orani, 3),
            "benzerlik":           round(benzerlik, 3),
            "parmak_eslesimi":     parmak_eslesimi,
            "injection_olasiligi": round(puan, 3),
            "anomali":             puan >= 0.5,
            "detay":               detay,
        }

    def iki_yanit_karsilastir(self,
                               yanit_a: str, yanit_b: str) -> Dict:
        """
        İki yanıtı (true/false payload gibi) birbiriyle karşılaştır.
        Boolean-blind injection tespitinde kullanılır.
        """
        boy_a, boy_b   = len(yanit_a), len(yanit_b)
        boy_farki      = abs(boy_a - boy_b)
        benzerlik      = self._benzerlik(yanit_a, yanit_b)
        norm_a         = self._normalize(yanit_a)
        norm_b         = self._normalize(yanit_b)
        norm_benzerlik = self._benzerlik(norm_a, norm_b)

        ayirt_edilebilir = boy_farki > 15 or benzerlik < 0.95

        return {
            "boy_a":              boy_a,
            "boy_b":              boy_b,
            "boy_farki":          boy_farki,
            "benzerlik":          round(benzerlik, 3),
            "norm_benzerlik":     round(norm_benzerlik, 3),
            "ayirt_edilebilir":   ayirt_edilebilir,
            "guven":              round(1.0 - benzerlik, 3),
        }

    # ── Zaman bazlı yardımcı ─────────────────────────────────────────────────

    @staticmethod
    def zaman_anomali_mi(sureler: List[float],
                          beklenen_gecikme: float,
                          tolerans: float = 0.7) -> Tuple[bool, float]:
        """
        Süre listesinden istatistiksel anomali tespiti.
        beklenen_gecikme saniye cinsinden (ör. SLEEP(5) → 5.0).
        Tolerans: gecikmenin en az bu oranı karşılanmalı (varsayılan %70).

        Returns: (anomali_mi, ortalama_sure)
        """
        if not sureler:
            return False, 0.0
        ortalama = sum(sureler) / len(sureler)
        esik = beklenen_gecikme * tolerans
        return ortalama >= esik, round(ortalama, 2)

    # ── Sayfa yapısı parmak izi ───────────────────────────────────────────────

    @staticmethod
    def yapi_parmak_izi(html: str) -> Dict:
        """
        HTML yapısını tag istatistiğiyle özetler.
        Yanıt içeriği değişse bile yapı aynı kalıyorsa ayrıştırılabilir.
        """
        tag_sayac: Dict[str, int] = {}
        for m in re.finditer(r'<([a-zA-Z][a-zA-Z0-9]*)', html):
            tag = m.group(1).lower()
            tag_sayac[tag] = tag_sayac.get(tag, 0) + 1
        return {
            "toplam_tag": sum(tag_sayac.values()),
            "benzersiz_tag": len(tag_sayac),
            "en_cok": sorted(tag_sayac.items(), key=lambda x: -x[1])[:5],
            "parmak": hashlib.md5(
                str(sorted(tag_sayac.items())).encode()
            ).hexdigest()[:8],
        }

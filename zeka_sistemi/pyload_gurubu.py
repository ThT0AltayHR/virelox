"""
VIRELOX Payload Grubu — 10 Ajanlı Payload Yönetimi
Mozilla Public License 2.0 — AltayHR Developers
"""
import concurrent.futures
import urllib.parse
from typing import Dict, List, Optional
from .pyload_havuzu.tamper_teknikleri import TamperMotoru, tamper_zinciri_uygula
from .pyload_havuzu.injection_kutuphanesi import tum_payloadlari_al


class PayloadGrubu:
    AJAN_SAYISI = 10

    def __init__(self, http_istemci, log_func=None):
        self.http   = http_istemci
        self.log    = log_func or print
        self.tamper = TamperMotoru()
        self.aktif_zincir: List[str] = []

    def bypass_ayarla(self, zincir: List[str]):
        self.aktif_zincir = zincir

    def akilli_payload_sec(self, kategori: str = "ERROR_BASED") -> List[str]:
        payloadlar = tum_payloadlari_al(kategori)
        if self.aktif_zincir:
            return [tamper_zinciri_uygula(p, self.aktif_zincir) for p in payloadlar]
        return payloadlar

    def toplu_payload_gonder(self, url: str, param: str,
                              payloadlar: List[str],
                              yanit_kontrol=None) -> List[Dict]:
        calisma_listesi = payloadlar[:50]
        toplam = len(calisma_listesi)
        self.log(f"[PAYLOAD] {toplam} payload → {self.AJAN_SAYISI} ajan ile eşzamanlı gönderiliyor...")
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        sonuclar = []
        tamamlanan = 0
        isaretlenen = 0

        def _kisa(p, n=55):
            p = str(p)
            return p[:n] + "…" if len(p) > n else p

        def _test(payload, ajan_no):
            p = params.copy(); p[param] = payload
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                '', urllib.parse.urlencode(p), ''
            ))
            self.log(f"[PAYLOAD] [ajan-{ajan_no}] → PYLD: {_kisa(payload)}")
            yanit = self.http.get(test_url)
            if not yanit:
                self.log(f"[PAYLOAD] [ajan-{ajan_no}]   MISS: yanıt yok")
                return None
            s = {"payload": payload,
                 "durum":   getattr(yanit, 'status_code', 0),
                 "uzunluk": len(getattr(yanit, 'text', ''))}
            if yanit_kontrol and yanit_kontrol(getattr(yanit, 'text', '')):
                s["isaretlendi"] = True
                self.log(f"[PAYLOAD] [ajan-{ajan_no}] ✔ ONAY: {_kisa(payload)} "
                         f"(durum={s['durum']}, uzunluk={s['uzunluk']})")
            else:
                self.log(f"[PAYLOAD] [ajan-{ajan_no}]   MISS: {_kisa(payload)} "
                         f"(durum={s['durum']})")
            return s

        # BUG FIX (kritik — Ctrl+C aracı durdurmuyordu): context manager (`with ... as ex`)
        # kullanıldığında Ctrl+C as_completed() döngüsünü kesse bile __exit__ otomatik
        # shutdown(wait=True) çağırıp tüm thread'lerin bitmesini bekliyordu. Artık elle
        # yönetiliyor; KeyboardInterrupt'ta bekleyen görevler iptal edilip hemen çıkılıyor.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=self.AJAN_SAYISI)
        try:
            gelecekler = {
                ex.submit(_test, p, (idx % self.AJAN_SAYISI) + 1): p
                for idx, p in enumerate(calisma_listesi)
            }
            for s in concurrent.futures.as_completed(gelecekler):
                tamamlanan += 1
                try:
                    r = s.result()
                    if r:
                        sonuclar.append(r)
                        if r.get("isaretlendi"):
                            isaretlenen += 1
                except Exception as e:
                    self.log(f"[PAYLOAD] [{tamamlanan}/{toplam}] HATA: {str(e)[:30]}")
                if tamamlanan % 10 == 0 or tamamlanan == toplam:
                    self.log(f"[PAYLOAD] İlerleme: {tamamlanan}/{toplam} tamamlandı, "
                             f"{isaretlenen} işaretlendi")
        except KeyboardInterrupt:
            self.log("[PAYLOAD] Kullanıcı tarafından durduruldu (Ctrl+C) — ajanlar iptal ediliyor...")
            ex.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

        self.log(f"[PAYLOAD] ═══ TAMAMLANDI: {len(sonuclar)}/{toplam} yanıt alındı, "
                 f"{isaretlenen} işaretlendi ═══")
        return sonuclar

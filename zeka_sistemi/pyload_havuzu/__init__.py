"""
VIRELOX Payload Havuzu — Injection & Tamper Kütüphanesi
Mozilla Public License 2.0
"""
from .xss_payloads import XSSPayloadHavuzu
from .lfi_payloads import LFIPayloadHavuzu
from .tamper_teknikleri import TamperMotoru, TAMPER_HARITASI, tamper_zinciri_uygula
from .injection_kutuphanesi import (
    INJECTION_SAYISI, tum_payloadlari_al, kategori_filtrele,
    INJECTION_KUTUPHANESI,
)

__all__ = [
    "XSSPayloadHavuzu", "LFIPayloadHavuzu",
    "TamperMotoru", "TAMPER_HARITASI", "tamper_zinciri_uygula",
    "INJECTION_SAYISI", "tum_payloadlari_al", "kategori_filtrele",
    "INJECTION_KUTUPHANESI",
]

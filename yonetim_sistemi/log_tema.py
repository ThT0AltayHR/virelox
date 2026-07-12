"""
VIRELOX Log Tema v6.0 — SQLMap Tarzı Profesyonel Log Motoru
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sade, yüksek kontrastlı, terminal dostu log sistemi.
SQLMap felsefesi:
  • Sadece kritik durumlarda renk (Kırmızı, Yeşil, Sarı, Mavi)
  • Siyah arka plan / parlak beyaz ana metin
  • Kutu, çerçeve, gradient YOK — net, okunaklı satırlar
  • Format: [HH:MM:SS] [LEVEL] mesaj

Mozilla Public License 2.0 — AltayHR Developers
"""

import sys
import time
from datetime import datetime

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    RENK = True
except ImportError:
    RENK = False
    class _Dummy:
        def __getattr__(self, _): return ""
        def __add__(self, other): return str(other)
        def __radd__(self, other): return str(other)
    Fore = Style = Back = _Dummy()

_BASLANGIC = time.time()


# ── Zaman yardımcıları ────────────────────────────────────────────────────────

def _saat() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _sure() -> str:
    g = time.time() - _BASLANGIC
    return f"{int(g)//60:02d}:{int(g)%60:02d}.{int((g % 1) * 1000):03d}"


# ── Çekirdek log fonksiyonu ───────────────────────────────────────────────────

def _log(level_color: str, level_text: str, msg: str,
         msg_color: str = None, stderr: bool = False) -> None:
    """
    [HH:MM:SS] [LEVEL] mesaj

    level_color : seviye etiketinin rengi
    level_text  : kısa büyük harf etiket (OK, ERROR, INFO …)
    msg         : log mesajı
    msg_color   : mesaj rengi (None → parlak beyaz)
    stderr      : True → sys.stderr'e yaz (hata seviyesi için)
    """
    t = _saat()
    stream = sys.stderr if stderr else sys.stdout
    if RENK:
        zaman  = (f"{Fore.WHITE}{Style.DIM}[{Style.RESET_ALL}"
                  f"{Style.BRIGHT}{Fore.WHITE}{t}{Style.RESET_ALL}"
                  f"{Fore.WHITE}{Style.DIM}]{Style.RESET_ALL}")
        etiket = (f"{level_color}{Style.BRIGHT}[{level_text}]{Style.RESET_ALL}")
        metin  = ((msg_color + str(msg) + Style.RESET_ALL)
                  if msg_color else
                  (Fore.WHITE + Style.BRIGHT + str(msg) + Style.RESET_ALL))
        print(f"{zaman} {etiket} {metin}", file=stream)
    else:
        lw = max(9, len(level_text) + 2)
        print(f"[{t}] [{level_text}]".ljust(lw + 12) + f" {msg}", file=stream)


# ── Temel seviyeler ───────────────────────────────────────────────────────────

def log_basari(m: str) -> None:
    """Başarı — parlak yeşil."""
    _log(Fore.GREEN, "OK", m, Fore.GREEN + Style.BRIGHT)

def log_hata(m: str) -> None:
    """Hata — parlak kırmızı, stderr'e."""
    _log(Fore.RED + Style.BRIGHT, "ERROR", m,
         Fore.RED + Style.BRIGHT, stderr=True)

def log_bilgi(m: str) -> None:
    """Bilgi — parlak beyaz."""
    _log(Fore.CYAN, "INFO", m)

def log_uyari(m: str) -> None:
    """Uyarı — parlak sarı."""
    _log(Fore.YELLOW + Style.BRIGHT, "WARNING", m, Fore.YELLOW)

def log_kritik(m: str) -> None:
    """Kritik — kırmızı arka plan + beyaz metin."""
    if RENK:
        t = _saat()
        print(
            f"{Fore.WHITE}{Style.DIM}[{Style.RESET_ALL}"
            f"{Style.BRIGHT}{Fore.WHITE}{t}{Style.RESET_ALL}"
            f"{Fore.WHITE}{Style.DIM}]{Style.RESET_ALL} "
            f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL} "
            f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} {m} {Style.RESET_ALL}",
            file=sys.stderr
        )
    else:
        print(f"[{_saat()}] [CRITICAL] {m}", file=sys.stderr)


# ── Operasyon seviyeler ───────────────────────────────────────────────────────

def log_dump(m: str) -> None:
    """Dump adımları — magenta."""
    _log(Fore.MAGENTA + Style.BRIGHT, "DUMP", m, Fore.MAGENTA)

def log_payload(m: str) -> None:
    """Payload gönderimi — mavi, 80 karakter limit."""
    kisa = str(m)[:80] + ("…" if len(str(m)) > 80 else "")
    _log(Fore.BLUE + Style.BRIGHT, "PAYLOAD", kisa, Fore.BLUE)

def log_waf(m: str) -> None:
    """WAF tespiti — parlak kırmızı."""
    _log(Fore.RED + Style.BRIGHT, "WAF", m, Fore.RED + Style.BRIGHT)

def log_session(m: str) -> None:
    """Session olayları — soluk cyan."""
    _log(Fore.CYAN, "SESSION", m, Fore.CYAN + Style.DIM)

def log_ai(m: str) -> None:
    """AI kararları — magenta."""
    _log(Fore.MAGENTA + Style.BRIGHT, "AI", m, Fore.MAGENTA + Style.BRIGHT)

def log_test(m: str) -> None:
    """Test adımları — beyaz dim."""
    _log(Fore.WHITE + Style.DIM, "TEST", m, Fore.WHITE + Style.DIM)

def log_dogrulama(m: str) -> None:
    """Doğrulama adımları — parlak yeşil."""
    _log(Fore.GREEN + Style.BRIGHT, "VERIFY", m, Fore.GREEN)

def log_bulundu(m: str) -> None:
    """Açık/veri bulundu — parlak yeşil bold."""
    _log(Fore.GREEN + Style.BRIGHT, "FOUND", m, Fore.GREEN + Style.BRIGHT)

def log_bulunamadi(m: str) -> None:
    """Bulunamadı — soluk kırmızı."""
    _log(Fore.RED, "NOT-FOUND", m, Fore.RED)

def log_tablo(m: str) -> None:
    """Tablo yapısı/listesi — cyan."""
    _log(Fore.CYAN + Style.BRIGHT, "TABLE", m, Fore.CYAN)

def log_hedef(m: str) -> None:
    """Hedef URL — parlak sarı."""
    _log(Fore.YELLOW + Style.BRIGHT, "TARGET", m, Fore.YELLOW + Style.BRIGHT)

def log_veri(m: str) -> None:
    """Dump verisi — parlak beyaz."""
    _log(Fore.WHITE + Style.BRIGHT, "DATA", m, Fore.WHITE + Style.BRIGHT)

def log_dbms(m: str) -> None:
    """DBMS tespiti — sarı."""
    _log(Fore.YELLOW + Style.BRIGHT, "DBMS", m, Fore.YELLOW)

def log_sniper(m: str) -> None:
    """Sniper Mode olayları — cyan bold."""
    _log(Fore.CYAN + Style.BRIGHT, "SNIPER", m, Fore.CYAN + Style.BRIGHT)

def log_profil(m: str) -> None:
    """Hedef profil bilgisi — mavi."""
    _log(Fore.BLUE + Style.BRIGHT, "PROFILE", m, Fore.BLUE)


# ── Uzmanlık logları ──────────────────────────────────────────────────────────

def log_ssl(m: str) -> None:
    _log(Fore.CYAN,                    "SSL",    m, Fore.CYAN)

def log_tech(m: str) -> None:
    _log(Fore.BLUE,                    "TECH",   m, Fore.BLUE)

def log_dosya(m: str) -> None:
    _log(Fore.YELLOW,                  "FILE",   m, Fore.YELLOW)

def log_hash(m: str) -> None:
    _log(Fore.MAGENTA,                 "HASH",   m, Fore.MAGENTA)

def log_param(m: str) -> None:
    _log(Fore.WHITE + Style.BRIGHT,    "PARAM",  m, Fore.WHITE)

def log_cookie(m: str) -> None:
    _log(Fore.YELLOW,                  "COOKIE", m, Fore.YELLOW)

def log_sqli(m: str) -> None:
    _log(Fore.GREEN + Style.BRIGHT,    "SQLI",   m, Fore.GREEN + Style.BRIGHT)

def log_xss(m: str) -> None:
    _log(Fore.RED + Style.BRIGHT,      "XSS",    m, Fore.RED)

def log_lfi(m: str) -> None:
    _log(Fore.RED + Style.BRIGHT,      "LFI",    m, Fore.RED)

def log_deneme(m: str) -> None:
    _log(Fore.WHITE + Style.DIM,       "TRY",    m, Fore.WHITE + Style.DIM)

def log_ilerleme(m: str) -> None:
    _log(Fore.BLUE,                    "PROGR",  m, Fore.BLUE)


# ── Yapısal yardımcılar ───────────────────────────────────────────────────────

def log_separator(etiket: str = "") -> None:
    """SQLMap tarzı tek çizgi ayırıcı — opsiyonel kısa etiket."""
    if RENK:
        cizgi = Fore.WHITE + Style.DIM + ("─" * 72) + Style.RESET_ALL
        if etiket:
            kisa = f" {etiket.upper()} "
            print(f"{Fore.WHITE}{Style.DIM}──{Style.RESET_ALL}"
                  f"{Fore.YELLOW}{Style.BRIGHT}{kisa}{Style.RESET_ALL}"
                  f"{cizgi[len(kisa)+6:]}")
        else:
            print(cizgi)
    else:
        if etiket:
            print(f"─── {etiket.upper()} " + "─" * (60 - len(etiket)))
        else:
            print("─" * 72)


def log_baslik(m: str) -> None:
    """Bölüm başlığı — iki çizgi arasında bold sarı metin."""
    genislik = max(len(str(m)) + 4, 72)
    if RENK:
        ic_cizgi = Fore.WHITE + Style.DIM + ("─" * genislik) + Style.RESET_ALL
        print()
        print(ic_cizgi)
        print(f"  {Fore.YELLOW}{Style.BRIGHT}{m}{Style.RESET_ALL}")
        print(ic_cizgi)
    else:
        print()
        print("─" * genislik)
        print(f"  {m}")
        print("─" * genislik)


def log_injection_bas(tip: str, url: str, param: str) -> None:
    """Injection tip taraması başlangıcı."""
    _log(Fore.CYAN + Style.BRIGHT, "SCAN",
         f"testing {tip.upper()} injection on parameter '{param}'")

def log_injection_bitti(tip: str, basarili: bool) -> None:
    """Injection tip taraması bitiş."""
    if basarili:
        _log(Fore.GREEN + Style.BRIGHT, "VULN",
             f"{tip.upper()} injection CONFIRMED", Fore.GREEN + Style.BRIGHT)
    else:
        _log(Fore.WHITE + Style.DIM, "NEG",
             f"{tip.upper()} — not vulnerable")


# ── İlerleme çubuğu (sqlmap tarzı: [=====>    ] XX%) ────────────────────────

def log_ilerleme_cubuk(mevcut: int, toplam: int, etiket: str = "") -> None:
    """Tek satır ilerleme çubuğu — ANSI \r ile yerinde günceller."""
    if toplam <= 0:
        return
    oran   = mevcut / toplam
    dolu   = int(oran * 40)
    bos    = 40 - dolu
    cubuk  = "=" * dolu + (">" if dolu < 40 else "") + " " * (bos - (1 if dolu < 40 else 0))
    yuzde  = int(oran * 100)
    suf    = f" {etiket}" if etiket else ""
    if RENK:
        line = (f"{Fore.WHITE + Style.DIM}[{Style.RESET_ALL}"
                f"{Fore.GREEN + Style.BRIGHT}{cubuk}{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.DIM}]{Style.RESET_ALL}"
                f" {Fore.YELLOW + Style.BRIGHT}{yuzde:3d}%{Style.RESET_ALL}"
                f" {Fore.WHITE + Style.DIM}({mevcut}/{toplam}){suf}{Style.RESET_ALL}")
    else:
        line = f"[{cubuk}] {yuzde:3d}% ({mevcut}/{toplam}){suf}"
    print(f"\r{line}", end="", flush=True)
    if mevcut >= toplam:
        print()  # tamamlandığında yeni satır


# ── Özet tabloları ────────────────────────────────────────────────────────────

def log_ssl_sonuc(host: str, guvenli: bool, kalan_gun: int,
                  protokol: str = "") -> None:
    if guvenli:
        _log(Fore.GREEN + Style.BRIGHT, "SSL",
             f"{host}: OK — {protokol}, {kalan_gun} gün kaldı",
             Fore.GREEN)
    else:
        _log(Fore.RED + Style.BRIGHT, "SSL",
             f"{host}: SORUNLU — {protokol}, {kalan_gun} gün",
             Fore.RED + Style.BRIGHT)


def log_tech_sonuc(teknolojiler: list) -> None:
    techs = ", ".join(str(t) for t in teknolojiler[:10])
    _log(Fore.BLUE, "TECH", f"detected: {techs}", Fore.BLUE + Style.BRIGHT)


def log_hash_tespit(hash_deger: str, hash_tip: str,
                    parola: str = None) -> None:
    kisa = hash_deger[:32] + ("…" if len(hash_deger) > 32 else "")
    if parola:
        _log(Fore.GREEN + Style.BRIGHT, "HASH",
             f"{hash_tip} cracked: '{parola}'  ← {kisa}",
             Fore.GREEN + Style.BRIGHT)
    else:
        _log(Fore.YELLOW, "HASH",
             f"{hash_tip} identified: {kisa}", Fore.YELLOW)


def log_burp_bulgu(tip: str, ciddiyet: str, url: str, aciklama: str = "") -> None:
    renk = {
        "Kritik": Fore.RED + Style.BRIGHT,
        "Yüksek": Fore.RED,
        "Orta":   Fore.YELLOW + Style.BRIGHT,
        "Düşük":  Fore.YELLOW,
    }.get(ciddiyet, Fore.WHITE)
    _log(renk, "BURP",
         f"[{ciddiyet.upper()}] {tip} — {url[:60]} {aciklama[:40]}", renk)


def log_ozet_rapor(veriler: dict) -> None:
    """Tarama sonu özet tablosu — SQLMap tarzı düz metin."""
    log_separator("ÖZET")
    satirlar = [
        ("Hedef",      veriler.get("url",      "?")),
        ("DBMS",       veriler.get("dbms",     "?")),
        ("WAF",        veriler.get("waf",       "Yok")),
        ("Açıklar",    str(veriler.get("aciklar", 0))),
        ("Tablolar",   str(veriler.get("tablolar", 0))),
        ("Kolonlar",   str(veriler.get("kolonlar",  0))),
        ("Satırlar",   str(veriler.get("satirlar",  0))),
        ("Süre",       veriler.get("sure",     "?")),
    ]
    for ad, deger in satirlar:
        if RENK:
            print(f"  {Fore.WHITE + Style.DIM}{ad:<10}{Style.RESET_ALL}: "
                  f"{Fore.WHITE + Style.BRIGHT}{deger}{Style.RESET_ALL}")
        else:
            print(f"  {ad:<10}: {deger}")
    log_separator()


# ── Geriye dönük uyumluluk takma adları ──────────────────────────────────────
# (eski log_tema.py'de farklı isimle export edilmiş fonksiyonlar)

log_xss      = log_xss
log_lfi      = log_lfi
log_sqli     = log_sqli
log_dosya    = log_dosya
log_hash     = log_hash
log_param    = log_param
log_cookie   = log_cookie
log_ssl      = log_ssl
log_tech     = log_tech
log_deneme   = log_deneme
log_ilerleme = log_ilerleme

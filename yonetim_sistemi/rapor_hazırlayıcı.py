"""
VIRELOX Rapor Hazırlayıcı — JSON / TXT / HTML
Mozilla Public License 2.0 — AltayHR Developers
"""
import html as html_mod
import json
import os
from datetime import datetime
from typing import Dict


class RaporHazırlayıcı:

    def __init__(self, sonuclar: Dict):
        self.sonuclar = sonuclar
        self.zaman    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _tablolar(self) -> Dict:
        """
        BUG FIX (Schema mismatch): the dump module stores tables under the
        top-level "tablolar" key, NOT under "dump" → "tablolar".  Support both
        layouts so older and newer callers both work.
        """
        dump_block = self.sonuclar.get("dump", {})
        # Prefer the nested layout; fall back to top-level for direct dump results.
        return dump_block.get("tablolar", None) or self.sonuclar.get("tablolar", {})

    def _guvenli_dosya_yolu(self, dosya: str) -> str:
        """BUG FIX: ensure parent directory exists before writing."""
        klasor = os.path.dirname(dosya)
        if klasor:
            os.makedirs(klasor, exist_ok=True)
        return dosya

    def json_kaydet(self, dosya: str):
        self._guvenli_dosya_yolu(dosya)
        try:
            with open(dosya, "w", encoding="utf-8") as f:
                json.dump(self.sonuclar, f, ensure_ascii=False, indent=2, default=str)
            print(f"[RAPOR] JSON: {dosya}")
        except OSError as exc:
            print(f"[RAPOR] JSON KAYIT HATASI — {dosya}: {exc}")
            raise

    def txt_kaydet(self, dosya: str):
        self._guvenli_dosya_yolu(dosya)
        try:
            with open(dosya, "w", encoding="utf-8") as f:
                f.write(f"VIRELOX v4.0 Raporu — {self.zaman}\n{'='*60}\n")
                f.write(f"Hedef : {self.sonuclar.get('url','?')}\n")
                f.write(f"DBMS  : {self.sonuclar.get('dbms','?')}\n\n")
                for tablo, data in self._tablolar().items():
                    f.write(f"\n[TABLO: {tablo}]\n")
                    f.write(f"Kolonlar: {', '.join(data.get('kolonlar',[]))}\n")
                    for i, satir in enumerate(data.get("veriler",[]), 1):
                        f.write(f"  {i}: {satir}\n")
            print(f"[RAPOR] TXT: {dosya}")
        except OSError as exc:
            print(f"[RAPOR] TXT KAYIT HATASI — {dosya}: {exc}")
            raise

    def html_kaydet(self, dosya: str):
        self._guvenli_dosya_yolu(dosya)
        tablolar_html = ""
        for tablo, data in self._tablolar().items():
            kolonlar = data.get("kolonlar", [])
            # BUG FIX: escape column names to prevent HTML injection.
            th = "".join(f"<th>{html_mod.escape(str(k))}</th>" for k in kolonlar)
            rows = ""
            for satir in data.get("veriler", []):
                # BUG FIX: satir may be a list instead of a dict.
                if isinstance(satir, dict):
                    cells = "".join(
                        # BUG FIX: escape cell values to prevent XSS from
                        # malicious database content injecting scripts into
                        # the HTML report.
                        f"<td>{html_mod.escape(str(satir.get(k, '')))}</td>"
                        for k in kolonlar
                    )
                elif isinstance(satir, (list, tuple)):
                    cells = "".join(
                        f"<td>{html_mod.escape(str(v))}</td>" for v in satir
                    )
                else:
                    cells = f"<td>{html_mod.escape(str(satir))}</td>"
                rows += f"<tr>{cells}</tr>"
            tablolar_html += f"""
            <h2>📋 {html_mod.escape(str(tablo))} <span class="cnt">({data.get('satir_sayisi',0)} satır)</span></h2>
            <div class="tbl-wrap"><table><thead><tr>{th}</tr></thead><tbody>{rows}</tbody></table></div>"""

        html = f"""<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<title>VIRELOX Raporu</title><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#0a0a0f;color:#c9d1d9;padding:24px}}
h1{{color:#ff4757;font-size:1.8rem;margin-bottom:8px}}
h2{{color:#00b4d8;margin:20px 0 6px;font-size:1.1rem}}
.meta{{color:#8b949e;font-size:.9rem;margin-bottom:20px}}
.cnt{{background:#21262d;padding:2px 8px;border-radius:10px;font-size:.8rem}}
.badge{{background:#ff4757;color:#fff;padding:3px 10px;border-radius:4px;font-weight:bold}}
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:.85rem}}
th{{background:#161b22;color:#58a6ff;padding:8px 12px;border:1px solid #30363d;text-align:left}}
td{{padding:6px 12px;border:1px solid #21262d;color:#e6edf3}}
tr:nth-child(even){{background:#0d1117}}
tr:hover{{background:#161b22}}
</style></head><body>
<h1>🔴 VIRELOX v4.0 — SQL Injection Raporu</h1>
<p class="meta">
  Hedef: <code>{html_mod.escape(str(self.sonuclar.get('url','?')))}</code> |
  DBMS: <span class="badge">{html_mod.escape(str(self.sonuclar.get('dbms','?')))}</span> |
  Zaman: {self.zaman}
</p>
{tablolar_html}
</body></html>"""
        try:
            with open(dosya, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[RAPOR] HTML: {dosya}")
        except OSError as exc:
            print(f"[RAPOR] HTML KAYIT HATASI — {dosya}: {exc}")
            raise

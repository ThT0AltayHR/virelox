"""
VIRELOX v4.0.2 — Premium HTML Report Generator
Mozilla Public License 2.0 — AltayHR Developers

Exports:
    html_rapor_olustur(sonuc: dict, dosya: str) -> None

'sonuc' dict shape:
    url    : str
    param  : str
    dbms   : str
    waf    : str
    zaman  : str
    vulns  : {vuln_type: [{"payload": str, ...}, ...]}
    dump   : {"tablolar": {tablo_adi: {"kolonlar": [...], "veriler": [...], "satir_sayisi": int}}}
"""

import html
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_VULN_META = {
    "error_based":    {"label": "Error-Based Injection",    "color": "#e63946", "icon": "⚠"},
    "union_based":    {"label": "UNION-Based Injection",    "color": "#f4a261", "icon": "⛓"},
    "boolean_blind":  {"label": "Boolean Blind Injection",  "color": "#e9c46a", "icon": "🔍"},
    "time_based":     {"label": "Time-Based Blind Injection","color": "#a8dadc", "icon": "⏱"},
    "stacked":        {"label": "Stacked Queries Injection", "color": "#c77dff", "icon": "📚"},
}
_DEFAULT_VULN = {"label": "SQL Injection", "color": "#94a3b8", "icon": "💉"}

_MAX_CELL = 120   # characters before truncate+title

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
/* ── Reset & base ── */
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
  background:#0f172a;color:#cbd5e1;
  min-height:100vh;padding:0 0 60px;
  line-height:1.6;
}

/* ── Cover / header ── */
.cover{
  background:linear-gradient(135deg,#1e293b 0%,#0f172a 60%,#1a1040 100%);
  border-bottom:2px solid #334155;
  padding:48px 56px 40px;
  position:relative;overflow:hidden;
}
.cover::before{
  content:'';position:absolute;right:-60px;top:-60px;
  width:320px;height:320px;border-radius:50%;
  background:radial-gradient(circle,rgba(220,38,38,.12),transparent 70%);
  pointer-events:none;
}
.cover-eyebrow{
  font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;
  color:#64748b;font-weight:600;margin-bottom:10px;
}
.cover-title{
  font-size:2.2rem;font-weight:800;letter-spacing:-.5px;
  color:#f1f5f9;margin-bottom:6px;
}
.cover-title span{color:#dc2626}
.cover-subtitle{color:#94a3b8;font-size:1rem;margin-bottom:28px}
.cover-meta{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start}
.meta-pill{
  display:inline-flex;align-items:center;gap:6px;
  background:#1e293b;border:1px solid #334155;
  border-radius:8px;padding:7px 14px;font-size:.82rem;
  color:#94a3b8;word-break:break-all;
}
.meta-pill b{color:#e2e8f0;white-space:nowrap}
.badge{
  display:inline-block;
  padding:2px 10px;border-radius:20px;font-size:.75rem;font-weight:700;
  letter-spacing:.04em;vertical-align:middle;
}
.badge-dbms{background:#1d4ed8;color:#bfdbfe}
.badge-waf{background:#059669;color:#a7f3d0}
.badge-waf-none{background:#374151;color:#9ca3af}
.badge-danger{background:#dc2626;color:#fecaca}

/* ── Main content wrapper ── */
.content{max-width:1100px;margin:0 auto;padding:40px 40px 0}

/* ── Section headings ── */
.section-title{
  font-size:.65rem;letter-spacing:.2em;text-transform:uppercase;
  color:#475569;font-weight:700;margin-bottom:14px;
  display:flex;align-items:center;gap:8px;
}
.section-title::after{content:'';flex:1;height:1px;background:#1e293b}

/* ── Dashboard / summary cards ── */
.dashboard{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:14px;margin-bottom:36px;
}
.stat-card{
  background:#1e293b;border:1px solid #334155;
  border-radius:12px;padding:18px 20px;
  display:flex;flex-direction:column;gap:4px;
  position:relative;overflow:hidden;
}
.stat-card::before{
  content:'';position:absolute;left:0;top:0;bottom:0;
  width:3px;border-radius:2px 0 0 2px;
}
.stat-card.accent-red::before{background:#dc2626}
.stat-card.accent-blue::before{background:#3b82f6}
.stat-card.accent-green::before{background:#10b981}
.stat-card.accent-orange::before{background:#f59e0b}
.stat-card.accent-purple::before{background:#8b5cf6}
.stat-icon{font-size:1.3rem;margin-bottom:4px}
.stat-value{font-size:1.9rem;font-weight:800;color:#f1f5f9;line-height:1}
.stat-label{font-size:.75rem;color:#64748b;font-weight:600;letter-spacing:.05em;text-transform:uppercase}

/* ── Executive summary line ── */
.exec-summary{
  background:#1e293b;border:1px solid #334155;border-left:4px solid #dc2626;
  border-radius:8px;padding:14px 20px;margin-bottom:36px;
  color:#94a3b8;font-size:.92rem;line-height:1.7;
}
.exec-summary strong{color:#e2e8f0}

/* ── Vulnerability cards ── */
.vuln-grid{display:flex;flex-direction:column;gap:12px;margin-bottom:36px}
.vuln-card{
  background:#1e293b;border:1px solid #334155;
  border-radius:10px;overflow:hidden;
}
.vuln-header{
  display:flex;align-items:center;gap:10px;
  padding:13px 18px;font-weight:700;font-size:.9rem;
  border-bottom:1px solid #334155;
  color:#f1f5f9;
}
.vuln-icon{font-size:1.1rem}
.vuln-type-label{flex:1}
.vuln-count{
  background:#0f172a;border:1px solid #334155;
  border-radius:20px;padding:1px 10px;font-size:.74rem;
  color:#94a3b8;font-weight:600;
}
.vuln-body{padding:14px 18px;display:flex;flex-direction:column;gap:8px}
.payload-row{display:flex;align-items:flex-start;gap:10px}
.payload-index{
  color:#475569;font-size:.72rem;font-weight:700;
  min-width:22px;padding-top:3px;
}
.payload-code{
  font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
  font-size:.8rem;background:#0f172a;color:#a5f3fc;
  border:1px solid #1e3a5f;border-radius:6px;
  padding:7px 12px;word-break:break-all;flex:1;
  white-space:pre-wrap;
}

/* ── Empty state ── */
.empty-state{
  text-align:center;padding:40px 20px;
  color:#475569;font-size:.9rem;
  background:#1e293b;border:1px dashed #334155;
  border-radius:10px;margin-bottom:36px;
}
.empty-icon{font-size:2.2rem;margin-bottom:8px}

/* ── Data tables ── */
.table-section{margin-bottom:36px}
.table-header{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:10px;flex-wrap:wrap;gap:8px;
}
.table-name{
  font-size:1rem;font-weight:700;color:#e2e8f0;
  display:flex;align-items:center;gap:8px;
}
.table-name .tbl-icon{color:#64748b;font-size:.9rem}
.row-badge{
  background:#1d4ed8;color:#bfdbfe;
  padding:2px 10px;border-radius:20px;
  font-size:.74rem;font-weight:700;
}
.tbl-wrap{
  overflow-x:auto;border:1px solid #1e293b;
  border-radius:10px;
}
table{
  width:100%;border-collapse:collapse;
  font-size:.82rem;min-width:400px;
}
thead th{
  position:sticky;top:0;z-index:2;
  background:#162032;color:#93c5fd;
  padding:10px 14px;border-bottom:2px solid #1e3a5f;
  text-align:left;font-weight:700;letter-spacing:.03em;
  white-space:nowrap;
}
thead th.num{text-align:right}
tbody td{
  padding:8px 14px;border-bottom:1px solid #1a2744;
  color:#cbd5e1;max-width:260px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  vertical-align:top;
}
tbody td.num{text-align:right;font-variant-numeric:tabular-nums}
tbody tr:nth-child(even) td{background:#162032}
tbody tr:hover td{background:#1e3358;color:#f1f5f9}
tbody tr:last-child td{border-bottom:none}

/* ── Footer ── */
.report-footer{
  text-align:center;margin-top:60px;
  font-size:.72rem;color:#334155;letter-spacing:.06em;text-transform:uppercase;
}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(v: object) -> str:
    """html.escape a value to string."""
    return html.escape(str(v))


def _is_numeric(value: str) -> bool:
    """Heuristic: right-align if the stripped value looks like a number."""
    s = value.strip()
    if not s:
        return False
    try:
        float(s.replace(",", ""))
        return True
    except ValueError:
        return False


def _cell(value: str) -> str:
    escaped = _e(value)
    raw = str(value)
    if len(raw) > _MAX_CELL:
        short = _e(raw[:_MAX_CELL]) + "…"
        num_cls = ' class="num"' if _is_numeric(raw[:_MAX_CELL]) else ""
        return f'<td{num_cls} title="{escaped}">{short}</td>'
    num_cls = ' class="num"' if _is_numeric(raw) else ""
    return f'<td{num_cls}>{escaped}</td>'


def _build_cover(sonuc: dict) -> str:
    url   = _e(sonuc.get("url",   "—"))
    param = _e(sonuc.get("param", "—"))
    dbms  = _e(sonuc.get("dbms",  "Unknown"))
    waf   = sonuc.get("waf", "")
    zaman = _e(sonuc.get("zaman", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    waf_badge = (
        f'<span class="badge badge-waf">{_e(waf)}</span>'
        if waf and waf.strip() and waf.strip().lower() not in ("yok", "none", "—", "-", "")
        else '<span class="badge badge-waf-none">WAF: None Detected</span>'
    )

    return f"""
<div class="cover">
  <div class="cover-eyebrow">Security Assessment Report</div>
  <div class="cover-title">VIRE<span>LOX</span> v4.0.2</div>
  <div class="cover-subtitle">SQL Injection Vulnerability Report</div>
  <div class="cover-meta">
    <div class="meta-pill"><b>🎯 Target</b>{url}</div>
    <div class="meta-pill"><b>🔑 Parameter</b><code style="background:none;color:#7dd3fc">{param}</code></div>
    <div class="meta-pill"><b>🗄 DBMS</b><span class="badge badge-dbms">{dbms}</span></div>
    <div class="meta-pill"><b>🛡 WAF</b>{waf_badge}</div>
    <div class="meta-pill"><b>🕐 Scan Time</b>{zaman}</div>
  </div>
</div>
"""


def _build_dashboard(sonuc: dict) -> str:
    vulns  = sonuc.get("vulns", {})
    dump   = sonuc.get("dump", {})
    tablolar = dump.get("tablolar", {})

    total_vulns = sum(
        len(v) if isinstance(v, list) else 0
        for v in vulns.values()
    )
    vuln_types  = len([k for k, v in vulns.items() if isinstance(v, list) and v])
    table_count = len(tablolar)
    row_count   = sum(t.get("satir_sayisi", 0) for t in tablolar.values())
    dbms = _e(sonuc.get("dbms", "—"))

    cards = [
        ("accent-red",    "💥", str(total_vulns),  "Vulnerabilities Found"),
        ("accent-orange", "🧩", str(vuln_types),   "Injection Techniques"),
        ("accent-blue",   "📋", str(table_count),  "Tables Dumped"),
        ("accent-green",  "📊", str(row_count),    "Rows Extracted"),
        ("accent-purple", "🗄", dbms,              "Database Engine"),
    ]

    html_cards = ""
    for accent, icon, value, label in cards:
        html_cards += f"""
    <div class="stat-card {accent}">
      <div class="stat-icon">{icon}</div>
      <div class="stat-value">{value}</div>
      <div class="stat-label">{label}</div>
    </div>"""

    return f'<div class="dashboard">{html_cards}\n</div>'


def _build_exec_summary(sonuc: dict) -> str:
    vulns    = sonuc.get("vulns", {})
    dump     = sonuc.get("dump", {})
    tablolar = dump.get("tablolar", {})

    total_vulns = sum(
        len(v) if isinstance(v, list) else 0
        for v in vulns.values()
    )
    vuln_types  = len([k for k, v in vulns.items() if isinstance(v, list) and v])
    table_count = len(tablolar)
    row_count   = sum(t.get("satir_sayisi", 0) for t in tablolar.values())

    if total_vulns == 0:
        finding = "No SQL injection vulnerabilities were confirmed during this scan."
    else:
        v_word = "vulnerability" if total_vulns == 1 else "vulnerabilities"
        t_word = "table" if table_count == 1 else "tables"
        r_word = "row" if row_count == 1 else "rows"
        technique_note = (
            f" across <strong>{vuln_types} injection technique{'s' if vuln_types!=1 else ''}</strong>"
        )
        dump_note = (
            f", with <strong>{table_count} {t_word}</strong> and <strong>{row_count} {r_word}</strong> successfully extracted from the database"
            if table_count > 0 else ""
        )
        finding = (
            f"This scan confirmed <strong>{total_vulns} SQL injection {v_word}</strong>"
            f"{technique_note}{dump_note}. "
            "Immediate remediation is strongly recommended."
        )

    return f'<div class="exec-summary">📋 <strong>Executive Summary</strong> — {finding}</div>'


def _build_vulns_section(sonuc: dict) -> str:
    vulns = sonuc.get("vulns", {})
    if not vulns or all(not (isinstance(v, list) and v) for v in vulns.values()):
        return f"""
<p class="section-title">Vulnerability Details</p>
<div class="empty-state">
  <div class="empty-icon">✅</div>
  <div>No SQL injection vulnerabilities were detected.</div>
</div>"""

    cards = ""
    for tip, items in vulns.items():
        if not isinstance(items, list) or not items:
            continue
        meta = _VULN_META.get(tip, _DEFAULT_VULN)
        color = meta["color"]
        icon  = meta["icon"]
        label = meta["label"]
        count = len(items)

        payloads_html = ""
        for idx, item in enumerate(items, 1):
            payload = item.get("payload", "") if isinstance(item, dict) else str(item)
            payloads_html += f"""
      <div class="payload-row">
        <div class="payload-index">#{idx}</div>
        <div class="payload-code">{_e(payload)}</div>
      </div>"""

        cards += f"""
  <div class="vuln-card" style="border-left:4px solid {color}">
    <div class="vuln-header" style="border-left:none">
      <span class="vuln-icon">{icon}</span>
      <span class="vuln-type-label">{label}</span>
      <span class="vuln-count">{count} payload{'s' if count != 1 else ''}</span>
    </div>
    <div class="vuln-body">{payloads_html}
    </div>
  </div>"""

    return f"""
<p class="section-title">Vulnerability Details</p>
<div class="vuln-grid">{cards}
</div>"""


def _build_tables_section(sonuc: dict) -> str:
    tablolar = sonuc.get("dump", {}).get("tablolar", {})

    if not tablolar:
        return f"""
<p class="section-title">Extracted Data</p>
<div class="empty-state">
  <div class="empty-icon">📭</div>
  <div>No database tables were dumped during this scan.</div>
</div>"""

    out = '<p class="section-title">Extracted Data</p>'

    for tablo_adi, data in tablolar.items():
        kolonlar     = data.get("kolonlar", [])
        veriler      = data.get("veriler",  [])
        satir_sayisi = data.get("satir_sayisi", len(veriler))

        # ── header row ──
        th_cells = "".join(
            f'<th>{_e(k)}</th>' for k in kolonlar
        )

        # ── body rows ──
        row_html = ""
        for satir in veriler:
            if isinstance(satir, dict):
                cells = "".join(_cell(satir.get(k, "")) for k in kolonlar)
            elif isinstance(satir, (list, tuple)):
                cells = "".join(_cell(v) for v in satir)
            else:
                cells = _cell(satir)
            row_html += f"<tr>{cells}</tr>"

        if not row_html:
            row_html = f'<tr><td colspan="{max(len(kolonlar),1)}" style="color:#475569;text-align:center;font-style:italic">No rows returned</td></tr>'

        r_word = "row" if satir_sayisi == 1 else "rows"
        out += f"""
<div class="table-section">
  <div class="table-header">
    <div class="table-name"><span class="tbl-icon">📋</span>{_e(tablo_adi)}</div>
    <span class="row-badge">{satir_sayisi} {r_word}</span>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>{th_cells}</tr></thead>
      <tbody>{row_html}</tbody>
    </table>
  </div>
</div>"""

    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def html_rapor_olustur(sonuc: dict, dosya: str) -> None:
    """
    Generate a premium self-contained HTML5 security report from a VIRELOX
    scan result dict and write it to *dosya*.

    Args:
        sonuc : Scan result dict (keys: url, param, dbms, waf, zaman, vulns, dump).
        dosya : Output file path (parent directories are created if missing).
    """
    # Ensure output directory exists
    parent = os.path.dirname(dosya)
    if parent:
        os.makedirs(parent, exist_ok=True)

    cover     = _build_cover(sonuc)
    dashboard = _build_dashboard(sonuc)
    exec_sum  = _build_exec_summary(sonuc)
    vulns_sec = _build_vulns_section(sonuc)
    tables    = _build_tables_section(sonuc)

    scan_ts = _e(
        sonuc.get("zaman", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    doc = f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VIRELOX v4.0.2 — Security Report</title>
  <style>{_CSS}</style>
</head>
<body>

{cover}

<div class="content">

  {dashboard}
  {exec_sum}

  {vulns_sec}

  {tables}

</div>

<div class="report-footer">
  Generated by VIRELOX v4.0.2 &nbsp;·&nbsp; {scan_ts} &nbsp;·&nbsp; For authorized security testing only
</div>

</body>
</html>
"""

    with open(dosya, "w", encoding="utf-8") as fh:
        fh.write(doc)

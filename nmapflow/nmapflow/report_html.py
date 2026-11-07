"""Self-contained HTML report: no external files, fonts, scripts or CDNs; works offline.

Every string that originates from a scan (banners, script output, hostnames) is HTML-escaped,
the page carries a restrictive Content-Security-Policy, and the inline JavaScript only uses
textContent / hidden / dataset (never innerHTML).
"""

from __future__ import annotations

import html
from pathlib import Path

from . import aggregate as agg_mod
from .aggregate import Aggregate, HostAgg
from .models import COMPLETED, FAILED, ScanTask
from .session import Session
from .utils import (TOOL_NAME, TOOL_VERSION, atomic_write_text, fix_ownership, human_duration, now_iso,
                    strip_control)


def e(text, quote: bool = True) -> str:
    """HTML-escape any scan-derived text (after removing control characters)."""
    return html.escape(strip_control(str(text)), quote=quote)

CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#1a2330;--muted:#5a6676;--line:#d8dde4;--accent:#0d6a6a;--accent-ink:#fff;
--open:#12703f;--open-bg:#e1f3e9;--warn:#7a5200;--warn-bg:#fdf1d6;--bad:#9d1f25;--bad-bg:#fbe3e4;--grey:#4a5462;--grey-bg:#e9ecf0;
--code:#eef1f5;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root{--bg:#10151b;--card:#18202a;--ink:#e3e8ee;--muted:#9aa6b5;--line:#2c3744;--accent:#4fb8b0;--accent-ink:#06201f;
--open:#6fd6a0;--open-bg:#143325;--warn:#f0c46b;--warn-bg:#3a2d0f;--bad:#ff9aa0;--bad-bg:#40181b;--grey:#b3bdc9;--grey-bg:#242d38;--code:#202a36}}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent)}a:focus-visible,button:focus-visible,th:focus-visible,summary:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
header.top{background:var(--card);border-bottom:1px solid var(--line);padding:22px 5vw}
header.top h1{margin:0 0 4px;font-size:1.6rem;letter-spacing:-.01em}header.top p{margin:0;color:var(--muted)}
.layout{display:grid;grid-template-columns:230px minmax(0,1fr);gap:28px;max-width:1500px;margin:0 auto;padding:22px 5vw 60px}
nav.toc{position:sticky;top:12px;align-self:start;font-size:.92rem}
nav.toc ol{list-style:none;margin:0;padding:0;border-left:2px solid var(--line)}
nav.toc a{display:block;padding:5px 12px;text-decoration:none;color:var(--muted)}nav.toc a:hover{color:var(--ink);background:var(--grey-bg)}
main section{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:20px 24px;margin:0 0 20px}
h2{margin:0 0 12px;font-size:1.25rem}h3{margin:18px 0 8px;font-size:1.02rem}
.muted{color:var(--muted)}.small{font-size:.88rem}
dl.facts{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0}dl.facts dt{color:var(--muted)}dl.facts dd{margin:0;overflow-wrap:anywhere}
.notice{border-left:4px solid var(--warn);background:var(--warn-bg);color:var(--ink);padding:10px 14px;margin:12px 0;border-radius:0 4px 4px 0}
.notice.bad{border-color:var(--bad);background:var(--bad-bg)}.notice.ok{border-color:var(--open);background:var(--open-bg)}
.counts{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}.counts div{border:1px solid var(--line);border-radius:6px;padding:8px 14px;min-width:120px}
.counts b{display:block;font-size:1.5rem;line-height:1.2}
.controls{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:16px;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2}
.controls input[type=search]{flex:1 1 260px;padding:8px 10px;border:1px solid var(--line);border-radius:4px;background:var(--card);color:var(--ink);font:inherit}
.controls button{padding:7px 12px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);border-radius:4px;font:inherit;cursor:pointer}
.controls button.alt{background:transparent;color:var(--accent)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:4px}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{padding:7px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
thead th{background:var(--grey-bg);position:sticky;top:0;white-space:nowrap}table.sortable thead th{cursor:pointer}
table.sortable thead th[aria-sort=ascending]::after{content:" \\25B2";font-size:.7em}table.sortable thead th[aria-sort=descending]::after{content:" \\25BC";font-size:.7em}
tbody tr:hover{background:var(--grey-bg)}td.num{text-align:right;font-variant-numeric:tabular-nums}
code,pre{font-family:var(--mono);font-size:.84rem}code{background:var(--code);padding:1px 5px;border-radius:3px;overflow-wrap:anywhere}
pre{background:var(--code);padding:10px 12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.8rem;font-weight:600;white-space:nowrap}
.s-open,.s-completed,.s-up,.s-verified{background:var(--open-bg);color:var(--open)}
.s-filtered,.s-open-filtered,.s-timed_out,.s-cancelled,.s-skipped,.s-likely{background:var(--warn-bg);color:var(--warn)}
.s-closed,.s-down,.s-unknown,.s-unfiltered,.s-na{background:var(--grey-bg);color:var(--grey)}
.s-failed,.s-vulnerable,.s-MISMATCH,.s-missing{background:var(--bad-bg);color:var(--bad)}
details{border:1px solid var(--line);border-radius:4px;margin:8px 0;background:var(--card)}details>summary{cursor:pointer;padding:8px 12px;font-weight:600}
details>div.body{padding:4px 14px 12px}details.out>summary{font-weight:400;font-family:var(--mono);font-size:.84rem}
ul.plain{margin:6px 0;padding-left:20px}
footer{max-width:1500px;margin:0 auto;padding:0 5vw 40px;color:var(--muted);font-size:.85rem}
@media (max-width:900px){.layout{grid-template-columns:1fr}nav.toc{position:static}nav.toc ol{display:flex;flex-wrap:wrap;border-left:0;gap:4px}}
@media print{body{background:#fff;color:#000;font-size:11pt}.controls,nav.toc{display:none!important}.layout{display:block;padding:0}
main section{border:0;padding:0;margin:0 0 14px;break-inside:auto}thead th{position:static}.wrap{overflow:visible;border:0}
tr,details{break-inside:avoid}[hidden]{display:block!important}details>summary{list-style:none}}
"""

JS = """
(function(){
var $=function(s,r){return (r||document).querySelector(s)},$$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
function cellVal(row,i){var c=row.cells[i];return ((c.dataset&&c.dataset.sort)||c.textContent).trim()}
function sortTable(t,i,th){var dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';
 $$('thead th',t).forEach(function(h){h.removeAttribute('aria-sort')});th.setAttribute('aria-sort',dir);
 var tb=t.tBodies[0],rows=$$('tr',tb);
 var numeric=rows.every(function(r){var v=cellVal(r,i);return v===''||(!isNaN(parseFloat(v))&&isFinite(v))});
 rows.sort(function(a,b){var x=cellVal(a,i),y=cellVal(b,i),r;
  if(numeric){r=(parseFloat(x)||0)-(parseFloat(y)||0)}else{r=x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'})}
  return dir==='ascending'?r:-r});
 rows.forEach(function(r){tb.appendChild(r)})}
$$('table.sortable').forEach(function(t){$$('thead th',t).forEach(function(th,i){th.tabIndex=0;
 th.addEventListener('click',function(){sortTable(t,i,th)});
 th.addEventListener('keydown',function(ev){if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();sortTable(t,i,th)}})})});
var q=$('#q'),openOnly=$('#onlyopen'),status=$('#filter-status');
function apply(){var term=(q.value||'').toLowerCase(),shown=0,total=0;
 $$('table.filterable tbody tr').forEach(function(r){total++;var ok=!term||r.textContent.toLowerCase().indexOf(term)>=0;
  if(ok&&openOnly&&openOnly.checked&&r.dataset.state&&r.dataset.state!=='open'){ok=false}r.hidden=!ok;if(ok){shown++}});
 $$('details.host').forEach(function(d){d.hidden=!!term&&d.textContent.toLowerCase().indexOf(term)<0});
 status.textContent=term||(openOnly&&openOnly.checked)?('Showing '+shown+' of '+total+' table rows'):''}
if(q){q.addEventListener('input',apply)}if(openOnly){openOnly.addEventListener('change',apply)}
var ex=$('#expand'),co=$('#collapse');
if(ex){ex.addEventListener('click',function(){$$('details').forEach(function(d){d.open=true})})}
if(co){co.addEventListener('click',function(){$$('details').forEach(function(d){d.open=false})})}
window.addEventListener('beforeprint',function(){$$('details').forEach(function(d){d.open=true})});
})();
"""

CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")


def badge(text: str, kind: str | None = None) -> str:
    k = (kind or text).replace("|", "-").replace(" ", "_")
    return f'<span class="badge s-{e(k)}">{e(text)}</span>'


def _status_name(s: str) -> str:
    return s.replace("_", " ")


def table(tid: str, headers: list[str], rows: list[str], *, num_cols: tuple[int, ...] = (), empty: str = "None.") -> str:
    if not rows:
        return f'<p class="muted">{e(empty)}</p>'
    head = "".join(f"<th scope='col'>{e(h)}</th>" for h in headers)
    return (f'<div class="wrap"><table id="{tid}" class="sortable filterable"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def td(content: str, raw: bool = False, num: bool = False, sort: str | None = None) -> str:
    cls = ' class="num"' if num else ""
    ds = f' data-sort="{e(sort)}"' if sort is not None else ""
    return f"<td{cls}{ds}>{content if raw else e(content)}</td>"


def code(text: str) -> str:
    return f"<code>{e(text)}</code>"


def output_block(text: str) -> str:
    first = (text.strip().splitlines() or [""])[0][:90]
    if "\n" not in text.strip() and len(text) <= 90:
        return f"<pre>{e(text.strip())}</pre>"
    return f'<details class="out"><summary>{e(first or "(output)")}</summary><pre>{e(text.strip())}</pre></details>'


def _ver(p) -> str:
    return " ".join(x for x in (p.product, p.version, f"({p.extrainfo})" if p.extrainfo else "") if x)


def _task_files(session_dir: Path, t: ScanTask) -> str:
    if not t.task_dir:
        return ""
    base = e(t.task_dir)
    return (f'<a href="{base}/scan.xml">XML</a> · <a href="{base}/scan.nmap">text</a> · '
            f'<a href="{base}/stdout.log">stdout</a> · <a href="{base}/stderr.log">stderr</a>')


def render(session: Session, ag: Aggregate) -> str:
    d, tasks = session.data, session.tasks
    scope = d.get("scope") or {}
    auth = d.get("authorization") or {}
    cfg = d.get("config") or {}
    by_status: dict[str, int] = {}
    for t in tasks:
        by_status[t.status] = by_status.get(t.status, 0) + 1
    up_hosts = [h for h in ag.hosts.values() if h.up]
    unique_open = {(h.address, p, n) for h in ag.hosts.values() for p, n in h.unique_open()}
    not_done = [t for t in tasks if t.status != COMPLETED]
    mismatches = [tid for tid, v in ag.integrity.items() if v in ("MISMATCH", "missing", "unreadable")]
    dur = ""
    if ag.first_start and ag.last_end:
        try:
            from datetime import datetime
            dur = human_duration((datetime.fromisoformat(ag.last_end) - datetime.fromisoformat(ag.first_start)).total_seconds())
        except ValueError:
            pass

    out: list[str] = []
    w = out.append
    sections = [("summary", "Executive summary"), ("scope", "Scope and authorization"), ("runs", "Scans executed"),
                ("discovery", "Host discovery"), ("ports", "Open ports and services"),
                ("versions", "Version detection"), ("os", "OS detection"), ("scripts", "NSE script results"),
                ("findings", "Vulnerability-related findings"), ("hosts", "Host details"),
                ("errors", "Errors and incomplete scans"), ("notes", "Recommendations and limitations")]
    w("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    w(f'<meta http-equiv="Content-Security-Policy" content="{e(CSP)}">')
    w("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    w(f"<title>Scan report {e(session.id)}</title><style>{CSS}</style></head><body>")
    w(f"<header class='top'><h1>Network scan report</h1><p>Session {e(session.id)} · generated {e(now_iso())} "
      f"by {e(TOOL_NAME)} {e(TOOL_VERSION)} · Nmap {e(str(d.get('nmap_version', '')))}</p></header>")
    w("<div class='layout'><nav class='toc' aria-label='Contents'><ol>")
    for sid, title in sections:
        w(f"<li><a href='#{sid}'>{e(title)}</a></li>")
    w("</ol></nav><main>")
    w("<div class='controls'><input id='q' type='search' placeholder='Filter tables and hosts (address, port, service, script...)' "
      "aria-label='Filter'><label><input id='onlyopen' type='checkbox'> open ports only</label>"
      "<button id='expand' type='button'>Expand all</button><button id='collapse' type='button' class='alt'>Collapse all</button>"
      "<span id='filter-status' class='muted small' role='status'></span></div>")

    # ------------------------------------------------------------ summary
    w("<section id='summary'><h2>Executive summary</h2>")
    if not_done:
        w(f"<div class='notice bad'><b>This report is incomplete.</b> {len(not_done)} of {len(tasks)} requested scans did not "
          "complete normally (see 'Errors and incomplete scans'). Missing results must not be read as 'nothing found'.</div>")
    else:
        w("<div class='notice ok'>All requested scans completed.</div>")
    if d.get("interrupted"):
        w("<div class='notice'>The session was stopped by the user before all scans finished.</div>")
    if mismatches:
        w("<div class='notice bad'><b>Integrity warning.</b> The original Nmap XML of scan(s) "
          + ", ".join(f"#{m}" for m in mismatches) + " no longer matches the fingerprint recorded when it was created.</div>")
    w("<div class='counts'>"
      f"<div><b>{len(scope.get('targets', []))}</b>target entries</div>"
      f"<div><b>{len(up_hosts)}</b>hosts responded</div>"
      f"<div><b>{len(unique_open)}</b>distinct open ports</div>"
      f"<div><b>{by_status.get(COMPLETED, 0)}/{len(tasks)}</b>scans completed</div>"
      f"<div><b>{sum(1 for f in ag.findings if f.label != 'Candidate CVEs listed (version-based, unverified)')}</b>script-reported issues</div></div>")
    w("<dl class='facts'>"
      f"<dt>Started</dt><dd>{e(ag.first_start or '-')}</dd><dt>Finished</dt><dd>{e(ag.last_end or '-')}</dd>"
      f"<dt>Elapsed (first start to last end)</dt><dd>{e(dur or '-')}</dd>"
      f"<dt>Scan status</dt><dd>{', '.join(f'{n} {e(_status_name(s))}' for s, n in by_status.items()) or '-'}</dd></dl>")
    w("<p>These results describe what the scans observed at the time they ran. They do not show that any system is secure, "
      "and they do not list every possible vulnerability. Script findings come from the scripts' own output and need manual verification. "
      "Nmap is not a substitute for a full vulnerability assessment or a manual penetration test.</p></section>")

    # -------------------------------------------------------------- scope
    w("<section id='scope'><h2>Scope and authorization</h2><dl class='facts'>")
    w(f"<dt>Authorization</dt><dd>{e(auth.get('statement', 'not recorded'))}</dd>")
    w(f"<dt>Confirmed by</dt><dd>{e(auth.get('operator', '-'))} typed <code>{e(auth.get('typed', '-'))}</code> at {e(auth.get('timestamp', '-'))}</dd>")
    pc = d.get("plan_confirmation") or {}
    w(f"<dt>Plan confirmed</dt><dd>{e(pc.get('timestamp', '-'))} ({e(str(pc.get('task_count', '-')))} scans)</dd>")
    w(f"<dt>Entered as</dt><dd>{e(', '.join(scope.get('originals', [])) or '-')}</dd>")
    tl = [t.get("normalized", "") for t in scope.get("targets", [])]
    w(f"<dt>Targets scanned</dt><dd>{e(', '.join(tl[:60]) + (f' ... (+{len(tl) - 60} more)' if len(tl) > 60 else '') or '-')}</dd>")
    ex = [t.get("normalized", "") for t in scope.get("exclusions", [])]
    w(f"<dt>Excluded</dt><dd>{e(', '.join(ex) or 'none')}</dd>")
    w(f"<dt>Settings</dt><dd>{e(', '.join(f'{k}={v}' for k, v in cfg.items() if k not in ('default_profiles', 'default_nse')) or '-')}</dd>")
    w(f"<dt>Run by</dt><dd>{e(str(d.get('operator', '')))} on {e(str(d.get('host', '')))} ({e(str(d.get('platform', '')))}); root: {e(str(d.get('privileged')))}</dd>")
    w("</dl>")
    for x in scope.get("warnings", []):
        w(f"<div class='notice'>{e(x)}</div>")
    if d.get("opt_in_confirmations"):
        w("<h3>Explicit opt-ins confirmed</h3><ul class='plain'>" + "".join(f"<li>{e(x)}</li>" for x in d["opt_in_confirmations"]) + "</ul>")
    w("</section>")

    # --------------------------------------------------------------- runs
    rows = []
    for t in tasks:
        integ = ag.integrity.get(t.task_id, "n/a")
        rows.append("<tr>" + td(str(t.task_id), num=True) + td(t.label) + td(t.kind)
                    + td(badge(_status_name(t.status), t.status), raw=True) + td(f"{len(t.targets)}", num=True)
                    + td(code(" ".join(t.command)) if t.command else "(not run)", raw=True)
                    + td(t.started or "-") + td(human_duration(t.duration_s), sort=str(t.duration_s or 0))
                    + td("-" if t.exit_code is None else str(t.exit_code), num=True)
                    + td(badge(integ, integ), raw=True) + td(_task_files(session.dir, t), raw=True) + "</tr>")
    w("<section id='runs'><h2>Scans executed</h2><p class='muted small'>Every requested scan is listed, including skipped, failed and cancelled ones. "
      "Original Nmap XML files are never modified; 'integrity' compares them with a SHA-256 recorded when each scan ended.</p>")
    w(table("t-runs", ["#", "Scan", "Type", "Status", "Targets", "Command", "Started", "Duration", "Exit", "XML integrity", "Files"], rows))
    w("</section>")

    # ---------------------------------------------------------- discovery
    rows = []
    for h in ag.hosts.values():
        rows.append("<tr>" + td(h.address) + td(", ".join(h.hostnames) or "-")
                    + td(badge("up" if h.up else "not up", "up" if h.up else "down"), raw=True)
                    + td((h.mac + (f" ({h.vendor})" if h.vendor else "")) or "-") + td(h.distance or "-")
                    + td(", ".join(f"#{i}" for i in h.task_ids)) + "</tr>")
    w("<section id='discovery'><h2>Host discovery</h2>")
    prow = []
    for tid, ps in ag.parsed.items():
        prow.append(f"<tr><td class='num'>{tid}</td><td class='num'>{ps.hosts_up}</td><td class='num'>{ps.hosts_down}</td>"
                    f"<td class='num'>{ps.hosts_total}</td><td>{e(ps.summary or '-')}</td></tr>")
    w(table("t-disc-runs", ["Scan #", "Up", "Down", "Total", "Nmap summary"], prow, empty="No scan produced readable results."))
    w("<h3>Hosts seen in scan results</h3>")
    w(table("t-hosts", ["Address", "Hostnames", "State", "MAC / vendor", "Hops", "Seen in scans"], rows,
            empty="No host entries were reported. Hosts that did not answer discovery probes do not appear; "
                  "they may be down or filtered (try disabling host discovery to scan them anyway)."))
    w("</section>")

    # -------------------------------------------------------------- ports
    rows = []
    for p in sorted(ag.port_rows, key=lambda x: (agg_mod._ip_key(x.host), x.proto, x.port, x.task_id)):
        rows.append(f'<tr data-state="{e(p.state)}">' + td(p.host) + td(f"{p.port}/{p.proto}", sort=f"{p.port}")
                    + td(badge(p.state), raw=True) + td(p.service or "-") + td(_ver(p) or "-") + td(p.reason or "-")
                    + td(p.source) + "</tr>")
    w("<section id='ports'><h2>Open ports and services</h2><p class='muted small'>One row per observation. The same port can appear "
      "several times when several scans looked at it. 'filtered' and 'open|filtered' mean Nmap could not decide; they are not confirmed open. "
      "Ports not listed were reported as closed or were not scanned.</p>")
    w(table("t-ports", ["Host", "Port", "State", "Service", "Product / version", "Reason", "Scan"], rows,
            empty="No ports were reported in the scan results."))
    w("</section>")

    # ----------------------------------------------------------- versions
    rows = []
    for p in ag.port_rows:
        if p.product or p.version:
            rows.append("<tr>" + td(p.host) + td(f"{p.port}/{p.proto}", sort=str(p.port)) + td(p.service or "-")
                        + td(p.product or "-") + td(p.version or "-") + td(p.extrainfo or "-")
                        + td(", ".join(p.cpes) or "-") + td(f"#{p.task_id}") + "</tr>")
    w("<section id='versions'><h2>Version detection</h2><p class='muted small'>Product and version come from Nmap's service fingerprints "
      "and can be wrong or hidden by the service (patched systems often report an unchanged banner).</p>")
    w(table("t-versions", ["Host", "Port", "Service", "Product", "Version", "Extra info", "CPE", "Scan"], rows,
            empty="No product or version information was collected (version detection may not have been requested)."))
    w("</section>")

    # ----------------------------------------------------------------- os
    rows = []
    for h in ag.hosts.values():
        for name, acc, cls, tid in h.os_rows:
            rows.append("<tr>" + td(h.address) + td(name) + td(acc + "%" if acc else "-", num=True, sort=acc or "0")
                        + td(cls or "-") + td(f"#{tid}") + "</tr>")
    w("<section id='os'><h2>OS detection</h2><p class='muted small'>OS detection is a statistical guess. Up to three best matches per host and scan are shown.</p>")
    w(table("t-os", ["Host", "Best guess", "Accuracy", "Class", "Scan"], rows, empty="No OS detection results (it was not requested, or Nmap had too little to go on)."))
    w("</section>")

    # ------------------------------------------------------------ scripts
    rows = []
    for s in ag.script_rows:
        rows.append("<tr>" + td(s.host) + td(s.location) + td(s.script) + td(output_block(s.output), raw=True) + td(f"#{s.task_id}") + "</tr>")
    w("<section id='scripts'><h2>NSE script results</h2>")
    w(table("t-scripts", ["Host", "Location", "Script", "Output", "Scan"], rows, empty="No NSE script produced output."))
    w("</section>")

    # ----------------------------------------------------------- findings
    w("<section id='findings'><h2>Vulnerability-related findings</h2>")
    if ag.findings:
        w("<p class='muted small'>Listed only where a script's own output states a result. Labels reflect that wording; no severity score "
          "(such as CVSS) is added. Every item needs manual verification.</p>")
        rows = []
        for f in ag.findings:
            kind = "vulnerable" if f.label == "Reported vulnerable" else "likely"
            rows.append("<tr>" + td(badge(f.label, kind), raw=True) + td(f.host) + td(f.location) + td(f.script)
                        + td(", ".join(f.cves) or "-") + td(output_block(f.output), raw=True) + td(f"#{f.task_id}") + "</tr>")
        w(table("t-findings", ["Label", "Host", "Location", "Script", "CVE references", "Script output", "Scan"], rows))
    else:
        w("<p>No script in these scans reported a vulnerable state. That does not mean the systems have no vulnerabilities: "
          "only the scripts that were selected ran, and a script can miss an issue.</p>")
    w("</section>")

    # ------------------------------------------------------- host details
    w("<section id='hosts'><h2>Host details</h2>")
    if not ag.hosts:
        w("<p class='muted'>No hosts to show.</p>")
    for h in ag.hosts.values():
        w(_host_details(h))
    w("</section>")

    # ------------------------------------------------------------- errors
    w("<section id='errors'><h2>Errors and incomplete scans</h2>")
    bad = [t for t in tasks if t.status != COMPLETED or t.warnings]
    if not bad and not any(p.errors for p in ag.parsed.values()):
        w("<p>No errors were recorded.</p>")
    for t in bad:
        w(f"<div class='notice{' bad' if t.status in (FAILED,) else ''}'><b>Scan #{t.task_id}: {e(t.label)}</b> "
          f"{badge(_status_name(t.status), t.status)}")
        if t.error:
            w(f"<br>{e(t.error)}")
        if t.skip_reason:
            w(f"<br>Skipped: {e(t.skip_reason)}")
        for x in t.warnings:
            w(f"<br><span class='muted'>Note: {e(x)}</span>")
        w(f"<br><span class='small'>{_task_files(session.dir, t)}</span></div>")
    for tid, ps in ag.parsed.items():
        for msg in ps.errors:
            w(f"<div class='notice'>Scan #{tid} output: {e(msg)}</div>")
    w("</section>")

    # -------------------------------------------------------------- notes
    w("<section id='notes'><h2>Recommendations and limitations</h2><h3>Suggested next steps</h3><ul class='plain'>"
      "<li>Compare every open port with what should be exposed; close or restrict anything that is not needed.</li>"
      "<li>Verify each script-reported issue manually before acting on it, and check version-based claims against vendor advisories.</li>"
      "<li>Re-run any scan listed under 'Errors and incomplete scans'; treat its hosts as not assessed.</li>"
      "<li>Re-scan after changes to confirm they worked. Keep the original XML files as evidence.</li>"
      "<li>Use authenticated vulnerability scanning and manual testing for a real security assessment.</li></ul>"
      "<h3>Limitations</h3><ul class='plain'>"
      "<li>A scan is a snapshot: it shows what answered at that moment. Firewalls, rate limits and intrusion prevention can hide, delay or alter responses.</li>"
      "<li>'filtered' and 'open|filtered' are uncertain states. UDP results are especially ambiguous.</li>"
      "<li>Service versions and OS names are inferred and can be wrong.</li>"
      "<li>An NSE script that reports nothing, or 'not vulnerable', only means that one check found nothing.</li>"
      "<li>Only the selected scan types, ports and scripts ran. Hosts that did not answer discovery may still exist.</li>"
      "<li>Nmap is not a full vulnerability scanner (for example OpenVAS) and is not a substitute for a manual penetration test.</li>"
      "<li>Intrusive, brute-force, denial-of-service and exploit scripts are deliberately never run by this tool.</li></ul></section>")
    w("</main></div>")
    w(f"<footer>Generated by {e(TOOL_NAME)} {e(TOOL_VERSION)}. Authorized use only. This file is self-contained and works offline.</footer>")
    w(f"<script>{JS}</script></body></html>")
    return "".join(out)


def _host_details(h: HostAgg) -> str:
    opens = h.unique_open()
    summary = f"{e(h.address)}" + (f" ({e(', '.join(h.hostnames))})" if h.hostnames else "")
    st = badge("up" if h.up else "not up", "up" if h.up else "down")
    parts = [f'<details class="host"><summary>{summary} {st} <span class="muted">· {len(opens)} open port(s)</span></summary><div class="body">']
    parts.append("<dl class='facts'>")
    if h.mac:
        parts.append(f"<dt>MAC</dt><dd>{e(h.mac)} {e(h.vendor)}</dd>")
    if h.os_rows:
        best = sorted(h.os_rows, key=lambda r: -float(r[1] or 0))[0]
        parts.append(f"<dt>OS (best guess)</dt><dd>{e(best[0])} ({e(best[1])}%)</dd>")
    parts.append(f"<dt>Open ports</dt><dd>{e(', '.join(f'{n}/{p}' for p, n in opens) or 'none observed')}</dd>")
    if h.extraports:
        parts.append(f"<dt>Other ports</dt><dd>{e('; '.join(h.extraports))}</dd>")
    parts.append(f"<dt>Seen in scans</dt><dd>{e(', '.join(f'#{i}' for i in h.task_ids))}</dd></dl>")
    if h.trace:
        parts.append("<h3>Traceroute</h3><ol>" + "".join(
            f"<li>{e(a)} {e(n)} {e(r)} ms</li>" for _, a, n, r in h.trace) + "</ol>")
    if h.scripts:
        parts.append("<h3>Script output</h3>")
        for s in h.scripts:
            parts.append(f"<p class='small'><b>{e(s.script)}</b> ({e(s.location)}, scan #{s.task_id})</p>{output_block(s.output)}")
    parts.append("</div></details>")
    return "".join(parts)


def write_report(session: Session) -> Path:
    """Build report.html for a session (also used to rebuild a report from saved XML)."""
    ag = agg_mod.build(session)
    text = render(session, ag)
    path = session.dir / "report.html"
    atomic_write_text(path, text, mode=0o600)
    fix_ownership(path)
    return path

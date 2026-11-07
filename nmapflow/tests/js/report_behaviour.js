// Drives a generated report.html in jsdom: sorting, filtering, expand/collapse, print handler.
// Usage: NODE_PATH=/path/to/node_modules node report_behaviour.js report.html
const fs = require("fs");
const { JSDOM } = require("jsdom");
const html = fs.readFileSync(process.argv[2], "utf8");
const errors = [];
const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true,
  virtualConsole: new (require("jsdom").VirtualConsole)().on("jsdomError", e => errors.push(String(e))) });
const { document, window } = dom.window;
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail: ok ? "" : String(detail || "") }); }
const $ = (s) => document.querySelector(s), $$ = (s) => Array.from(document.querySelectorAll(s));
const col = (table, i) => Array.from(table.tBodies[0].rows).map(r => r.cells[i].textContent.trim());
const click = (el) => el.dispatchEvent(new window.Event("click", { bubbles: true }));

check("script ran without errors", errors.length === 0, errors.join("; "));
const ports = $("#t-ports");
check("ports table exists", !!ports);
if (ports) {
  const head = ports.tHead.rows[0].cells;
  const portIdx = Array.from(head).findIndex(h => h.textContent.trim() === "Port");
  check("headers are keyboard focusable", Array.from(head).every(h => h.tabIndex === 0));
  click(head[portIdx]);
  const asc = col(ports, portIdx).map(v => parseInt(v, 10));
  check("numeric ascending sort", asc.every((v, i) => i === 0 || asc[i - 1] <= v), asc.join(","));
  check("aria-sort ascending", head[portIdx].getAttribute("aria-sort") === "ascending");
  click(head[portIdx]);
  const desc = col(ports, portIdx).map(v => parseInt(v, 10));
  check("numeric descending sort", desc.every((v, i) => i === 0 || desc[i - 1] >= v), desc.join(","));
  check("aria-sort descending", head[portIdx].getAttribute("aria-sort") === "descending");
  const hostIdx = Array.from(head).findIndex(h => h.textContent.trim() === "State");
  click(head[hostIdx]);
  check("only one column marked sorted", $$("#t-ports thead th[aria-sort]").length === 1);
  head[portIdx].dispatchEvent(new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  check("Enter key sorts", head[portIdx].getAttribute("aria-sort") === "ascending");

  const total = ports.tBodies[0].rows.length;
  const q = $("#q");
  q.value = "nginx"; q.dispatchEvent(new window.Event("input", { bubbles: true }));
  const visible = Array.from(ports.tBodies[0].rows).filter(r => !r.hidden);
  check("text filter shows only matches", visible.length > 0 && visible.length < total && visible.every(r => /nginx/i.test(r.textContent)), `${visible.length}/${total}`);
  check("filter status text updates", /Showing \d+ of \d+/.test($("#filter-status").textContent));
  q.value = "zzz-no-match"; q.dispatchEvent(new window.Event("input", { bubbles: true }));
  check("no-match hides every row", Array.from(ports.tBodies[0].rows).every(r => r.hidden));
  check("host details are filtered too", $$("details.host").every(d => d.hidden));
  q.value = ""; q.dispatchEvent(new window.Event("input", { bubbles: true }));
  check("clearing the filter restores rows", Array.from(ports.tBodies[0].rows).every(r => !r.hidden));
  check("clearing the filter restores hosts", $$("details.host").every(d => !d.hidden));
  const only = $("#onlyopen"); only.checked = true; only.dispatchEvent(new window.Event("change", { bubbles: true }));
  const shown = Array.from(ports.tBodies[0].rows).filter(r => !r.hidden);
  check("open-only hides filtered/closed rows", shown.length > 0 && shown.every(r => r.dataset.state === "open") && shown.length < total, `${shown.length}/${total}`);
  only.checked = false; only.dispatchEvent(new window.Event("change", { bubbles: true }));
}
click($("#expand"));
check("expand all opens every <details>", $$("details").every(d => d.open));
click($("#collapse"));
check("collapse all closes every <details>", $$("details").every(d => !d.open));
window.dispatchEvent(new window.Event("beforeprint"));
check("print handler opens every <details>", $$("details").every(d => d.open));
check("TOC links point at existing sections", $$("nav.toc a").every(a => document.getElementById(a.getAttribute("href").slice(1))));
check("no external resources", !/(?:src|href)=["']https?:/i.test(html));

const failed = results.filter(r => !r.ok);
console.log(JSON.stringify({ total: results.length, failed }));
process.exit(failed.length ? 1 : 0);

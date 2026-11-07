"""Nmap XML parser (xml.etree.ElementTree). Results come ONLY from the XML files, never
from scraping terminal output.

Safety:
  * files containing an XML entity declaration are rejected (entity-expansion attacks)
  * truncated XML from interrupted scans is repaired in MEMORY; the file on disk is never changed
  * missing attributes/elements are tolerated; problems are collected in ParsedScan.errors
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import (HostResult, OsMatch, ParsedScan, PortResult, ScriptResult, TraceHop)

MAX_XML_BYTES = 512 * 1024 * 1024


def _int(text: str | None, default: int = 0) -> int:
    try:
        return int(text) if text not in (None, "") else default
    except ValueError:
        return default


def _float(text: str | None) -> float | None:
    try:
        return float(text) if text not in (None, "") else None
    except ValueError:
        return None


def _repair(data: bytes) -> bytes | None:
    """Best-effort repair of truncated Nmap XML: keep everything up to the last complete
    </host> and close the document. Returns None when there is nothing usable."""
    start = data.find(b"<nmaprun")
    if start < 0:
        return None
    last = data.rfind(b"</host>")
    if last >= 0:
        cut = last + len(b"</host>")
    else:
        first_host = data.find(b"<host", start)
        cut = first_host if first_host >= 0 else len(data)
        # drop a dangling partial tag at the end if there is no host at all
        if first_host < 0:
            lt = data.rfind(b"<")
            gt = data.rfind(b">")
            if lt > gt:
                cut = lt
    return data[:cut] + b"\n</nmaprun>\n"


def _scripts(parent: ET.Element) -> list[ScriptResult]:
    return [ScriptResult(s.get("id", "?"), s.get("output", "")) for s in parent.findall("script")]


def _parse_host(h: ET.Element) -> HostResult:
    addr, addrtype, mac, vendor = "", "ipv4", "", ""
    for a in h.findall("address"):
        t = a.get("addrtype", "")
        if t == "mac":
            mac, vendor = a.get("addr", ""), a.get("vendor", "")
        elif not addr:
            addr, addrtype = a.get("addr", ""), t or "ipv4"
    if not addr:
        addr = mac or "(unknown)"
    host = HostResult(address=addr, addrtype=addrtype, mac=mac, vendor=vendor)
    st = h.find("status")
    if st is not None:
        host.state, host.reason = st.get("state", "unknown"), st.get("reason", "")
    for hn in h.findall("hostnames/hostname"):
        name = hn.get("name", "")
        if name and name not in host.hostnames:
            host.hostnames.append(name)
    ports = h.find("ports")
    if ports is not None:
        for ep in ports.findall("extraports"):
            reasons = ", ".join(f"{r.get('count', '?')} {r.get('reason', '?')}" for r in ep.findall("extrareasons"))
            host.extraports.append(f"{ep.get('count', '?')} {ep.get('state', '?')}" + (f" ({reasons})" if reasons else ""))
        for p in ports.findall("port"):
            state = p.find("state")
            svc = p.find("service")
            pr = PortResult(
                number=_int(p.get("portid")), protocol=p.get("protocol", "tcp"),
                state=state.get("state", "unknown") if state is not None else "unknown",
                reason=state.get("reason", "") if state is not None else "")
            if svc is not None:
                pr.service, pr.product = svc.get("name", ""), svc.get("product", "")
                pr.version, pr.extrainfo = svc.get("version", ""), svc.get("extrainfo", "")
                pr.tunnel, pr.method = svc.get("tunnel", ""), svc.get("method", "")
                pr.cpes = [c.text for c in svc.findall("cpe") if c.text]
            pr.scripts = _scripts(p)
            host.ports.append(pr)
    os_el = h.find("os")
    if os_el is not None:
        for m in os_el.findall("osmatch"):
            om = OsMatch(m.get("name", ""), m.get("accuracy", ""))
            for c in m.findall("osclass"):
                om.classes.append(" / ".join(x for x in (c.get("type", ""), c.get("vendor", ""),
                                                          c.get("osfamily", ""), c.get("osgen", "")) if x))
                om.cpes += [x.text for x in c.findall("cpe") if x.text]
            host.os_matches.append(om)
    hs = h.find("hostscript")
    if hs is not None:
        host.host_scripts = _scripts(hs)
    for hop in h.findall("trace/hop"):
        host.trace.append(TraceHop(hop.get("ttl", ""), hop.get("ipaddr", ""), hop.get("rtt", ""), hop.get("host", "")))
    d = h.find("distance")
    if d is not None:
        host.distance = d.get("value", "")
    u = h.find("uptime")
    if u is not None:
        host.uptime_s = u.get("seconds", "")
    return host


def parse_bytes(data: bytes, label: str = "") -> ParsedScan:
    res = ParsedScan(path=label)
    if re.search(rb"<!ENTITY", data):
        res.errors.append("XML contains an entity declaration; refused for safety")
        return res
    root = None
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        fixed = _repair(data)
        if fixed is not None:
            try:
                root = ET.fromstring(fixed)
                res.repaired = True
                res.errors.append(f"XML was incomplete ({exc}); parsed what was available "
                                  "(the scan was probably interrupted). The original file is unchanged.")
            except ET.ParseError as exc2:
                res.errors.append(f"XML could not be parsed even after repair: {exc2}")
        else:
            res.errors.append(f"XML could not be parsed: {exc}")
    if root is None:
        return res
    if root.tag != "nmaprun":
        res.errors.append(f"unexpected root element <{root.tag}>")
        return res
    res.nmap_args = root.get("args", "")
    res.nmap_version = root.get("version", "")
    res.start, res.start_str = root.get("start", ""), root.get("startstr", "")
    for si in root.findall("scaninfo"):
        res.scaninfo.append(f"{si.get('type', '?')}/{si.get('protocol', '?')} ({si.get('numservices', '?')} ports)")
    for h in root.findall("host"):
        try:
            res.hosts.append(_parse_host(h))
        except Exception as exc:       # one odd host must not lose the others
            res.errors.append(f"a host entry could not be read: {exc}")
    fin = root.find("runstats/finished")
    if fin is not None:
        res.complete = not res.repaired
        res.end_str = fin.get("timestr", "")
        res.elapsed = _float(fin.get("elapsed"))
        res.summary = fin.get("summary", "")
        res.exit_status = fin.get("exit", "")
    hs = root.find("runstats/hosts")
    if hs is not None:
        res.hosts_up, res.hosts_down, res.hosts_total = _int(hs.get("up")), _int(hs.get("down")), _int(hs.get("total"))
    if not res.hosts_total and res.hosts:
        res.hosts_up = sum(1 for h in res.hosts if h.state == "up")
        res.hosts_total = len(res.hosts)
    if fin is None and not res.repaired:
        res.errors.append("XML has no run summary: the scan did not finish normally")
    return res


def parse_file(path: Path) -> ParsedScan:
    """Parse one Nmap XML file; never raises for bad content, always returns a ParsedScan."""
    try:
        size = path.stat().st_size
        if size > MAX_XML_BYTES:
            r = ParsedScan(path=str(path))
            r.errors.append("XML file is larger than the safety limit")
            return r
        data = path.read_bytes()
    except OSError as exc:
        r = ParsedScan(path=str(path))
        r.errors.append(f"cannot read XML: {exc.strerror or exc}")
        return r
    if not data.strip():
        r = ParsedScan(path=str(path))
        r.errors.append("XML file is empty (the scan produced no output)")
        return r
    return parse_bytes(data, str(path))

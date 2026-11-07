"""Combines the parsed results of every task into per-host and per-finding views for the reports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from .models import ParsedScan
from .parser import parse_file
from .session import Session
from .utils import sha256_file

_STATE_RE = re.compile(r"\b(NOT VULNERABLE|LIKELY VULNERABLE|VULNERABLE)\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_RANK = {"open": 0, "open|filtered": 1, "filtered": 2, "unfiltered": 3, "closed|filtered": 4, "closed": 5}


@dataclass
class PortObs:
    host: str
    proto: str
    port: int
    state: str
    reason: str
    service: str
    product: str
    version: str
    extrainfo: str
    cpes: list[str]
    task_id: int
    source: str


@dataclass
class ScriptRow:
    host: str
    location: str
    script: str
    output: str
    task_id: int
    source: str


@dataclass
class Finding:
    label: str            # Reported vulnerable | Likely vulnerable | Candidate CVEs listed
    host: str
    location: str
    script: str
    cves: list[str]
    output: str
    task_id: int


@dataclass
class HostAgg:
    address: str
    addrtype: str = "ipv4"
    hostnames: list[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    up: bool = False
    task_ids: list[int] = field(default_factory=list)
    ports: list[PortObs] = field(default_factory=list)
    extraports: list[str] = field(default_factory=list)
    os_rows: list[tuple[str, str, str, int]] = field(default_factory=list)  # name, accuracy, classes, task
    scripts: list[ScriptRow] = field(default_factory=list)
    trace: list[tuple[str, str, str, str]] = field(default_factory=list)
    distance: str = ""

    def unique_open(self) -> list[tuple[str, int]]:
        return sorted({(p.proto, p.port) for p in self.ports if p.state == "open"}, key=lambda x: (x[0], x[1]))


@dataclass
class Aggregate:
    parsed: dict[int, ParsedScan]
    hosts: dict[str, HostAgg]
    port_rows: list[PortObs]
    script_rows: list[ScriptRow]
    findings: list[Finding]
    integrity: dict[int, str]          # task id -> verified | MISMATCH | missing | n/a
    first_start: str = ""
    last_end: str = ""


def classify(script_id: str, output: str) -> tuple[str, list[str]] | None:
    """Return (label, cves) only when the script output itself states a result."""
    cves = sorted(set(_CVE_RE.findall(output)))
    states = set(_STATE_RE.findall(output))
    if "VULNERABLE" in states:
        return "Reported vulnerable", cves
    if "LIKELY VULNERABLE" in states:
        return "Likely vulnerable", cves
    if script_id == "vulners" and cves:
        return "Candidate CVEs listed (version-based, unverified)", cves
    return None


def load_parsed(session: Session) -> dict[int, ParsedScan]:
    out: dict[int, ParsedScan] = {}
    for t in session.tasks:
        if not t.task_dir:
            continue
        xml = session.dir / t.task_dir / "scan.xml"
        if xml.exists():
            out[t.task_id] = parse_file(xml)
    return out


def verify_integrity(session: Session) -> dict[int, str]:
    res: dict[int, str] = {}
    for t in session.tasks:
        if not t.task_dir or not t.xml_sha256:
            res[t.task_id] = "n/a"
            continue
        xml = session.dir / t.task_dir / "scan.xml"
        if not xml.exists():
            res[t.task_id] = "missing"
            continue
        try:
            res[t.task_id] = "verified" if sha256_file(xml) == t.xml_sha256 else "MISMATCH"
        except OSError:
            res[t.task_id] = "unreadable"
    return res


def build(session: Session, parsed: dict[int, ParsedScan] | None = None) -> Aggregate:
    parsed = parsed if parsed is not None else load_parsed(session)
    hosts: dict[str, HostAgg] = {}
    port_rows: list[PortObs] = []
    script_rows: list[ScriptRow] = []
    findings: list[Finding] = []
    by_id = {t.task_id: t for t in session.tasks}
    for tid, ps in parsed.items():
        task = by_id.get(tid)
        source = f"#{tid} {task.label}" if task else f"#{tid}"
        for h in ps.hosts:
            agg = hosts.setdefault(h.address, HostAgg(h.address, h.addrtype))
            agg.up = agg.up or h.state == "up"
            if tid not in agg.task_ids:
                agg.task_ids.append(tid)
            for n in h.hostnames:
                if n not in agg.hostnames:
                    agg.hostnames.append(n)
            agg.mac, agg.vendor = agg.mac or h.mac, agg.vendor or h.vendor
            agg.distance = agg.distance or h.distance
            agg.extraports += [f"{e} (scan #{tid})" for e in h.extraports]
            for m in h.os_matches[:3]:
                agg.os_rows.append((m.name, m.accuracy, "; ".join(m.classes[:2]), tid))
            if h.trace and not agg.trace:
                agg.trace = [(x.ttl, x.address, x.host, x.rtt) for x in h.trace]
            for p in h.ports:
                obs = PortObs(h.address, p.protocol, p.number, p.state, p.reason, p.service, p.product,
                              p.version, p.extrainfo, p.cpes, tid, source)
                agg.ports.append(obs)
                port_rows.append(obs)
                for s in p.scripts:
                    row = ScriptRow(h.address, f"{p.protocol}/{p.number}", s.id, s.output, tid, source)
                    agg.scripts.append(row)
                    script_rows.append(row)
                    c = classify(s.id, s.output)
                    if c:
                        findings.append(Finding(c[0], h.address, row.location, s.id, c[1], s.output, tid))
            for s in h.host_scripts:
                row = ScriptRow(h.address, "host", s.id, s.output, tid, source)
                agg.scripts.append(row)
                script_rows.append(row)
                c = classify(s.id, s.output)
                if c:
                    findings.append(Finding(c[0], h.address, "host", s.id, c[1], s.output, tid))
    starts = [t.started for t in session.tasks if t.started]
    ends = [t.finished for t in session.tasks if t.finished]
    return Aggregate(parsed, dict(sorted(hosts.items(), key=lambda kv: _ip_key(kv[0]))), port_rows, script_rows,
                     findings, verify_integrity(session), min(starts) if starts else "", max(ends) if ends else "")


def _ip_key(addr: str):
    import ipaddress
    try:
        ip = ipaddress.ip_address(addr)
        return (0, ip.version, int(ip))
    except ValueError:
        return (1, 0, addr)


def best_state(states: list[str]) -> str:
    return sorted(states, key=lambda s: _RANK.get(s, 9))[0] if states else "unknown"

"""Shared test helpers: a fake `nmap` executable and a small 'lab' harness.

The fake nmap is a real executable script, so the runner exercises real processes, pipes,
signals and timeouts, but it only writes canned output files. It never touches a network.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from nmapflow import nse as nse_mod
from nmapflow import profiles as prof_mod
from nmapflow.config import Config
from nmapflow.nse import Availability, NseSelection
from nmapflow.planner import Plan, PlanOptions, build_plan, targets_digest
from nmapflow.runner import Executor
from nmapflow.session import Session
from nmapflow.targets import TargetSet
from nmapflow.utils import setup_logger

FAKE_SCRIPT = r'''#!__PYTHON__
import ipaddress, json, os, signal, sys, time

MODE = __MODE__
DELAY = __DELAY__
LOG = __LOG__
args = sys.argv[1:]

def opt(flag):
    return args[args.index(flag) + 1] if flag in args else None

def log(event):
    with open(LOG, "a") as fh:
        fh.write(json.dumps({"event": event, "pid": os.getpid(), "t": time.time(), "argv": args}) + "\n")

if args and args[0] == "--version":
    print("Nmap version 7.94 ( https://nmap.org ) [FAKE]")
    sys.exit(0)

xml_path, nmap_path = opt("-oX"), opt("-oN")
targets = args[args.index("--reason") + 1:] if "--reason" in args else []
udp = "-sU" in args
discovery_only = "-sn" in args or "-sL" in args

def addr_for(tok):
    if "/" in tok:
        net = ipaddress.ip_network(tok, strict=False)
        return str(net[1] if net.num_addresses > 1 else net[0])
    try:
        ipaddress.ip_address(tok)
        return tok
    except ValueError:
        return "192.0.2.77"

def host_xml(addr):
    fam = "ipv6" if ":" in addr else "ipv4"
    ports = []
    if not discovery_only:
        if udp:
            ports.append('<port protocol="udp" portid="161"><state state="open" reason="udp-response" reason_ttl="64"/>'
                         '<service name="snmp" product="net-snmp" version="5.9" method="probed" conf="10"/></port>')
        else:
            ports.append('<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/>'
                         '<service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="protocol 2.0" method="probed" conf="10">'
                         '<cpe>cpe:/a:openbsd:openssh:9.2p1</cpe></service></port>')
            http_scripts = ""
            if "--script" in args:
                http_scripts = '<script id="http-title" output="Fake Test Page"/>'
                if MODE == "vuln":
                    http_scripts += ('<script id="ssl-heartbleed" output="&#10;  VULNERABLE:&#10;  State: VULNERABLE&#10;'
                                     '  IDs:  CVE:CVE-2014-0160"/>'
                                     '<script id="smb-vuln-ms17-010" output="&#10;  NOT VULNERABLE: patched"/>')
                if MODE == "hostile":
                    http_scripts += '<script id="http-title" output="&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt;"/>'
            ports.append('<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/>'
                         '<service name="http" product="nginx" version="1.22.1" method="probed" conf="10"/>' + http_scripts + '</port>')
            ports.append('<port protocol="tcp" portid="443"><state state="filtered" reason="no-response" reason_ttl="0"/>'
                         '<service name="https" method="table" conf="3"/></port>')
    extra = '<extraports state="closed" count="997"><extrareasons reason="resets" count="997" proto="tcp" ports="1-21"/></extraports>'
    os_xml = ""
    if "-O" in args:
        os_xml = ('<os><portused state="open" proto="tcp" portid="22"/>'
                  '<osmatch name="Linux 5.15 - 6.1" accuracy="96" line="1"><osclass type="general purpose" vendor="Linux" '
                  'osfamily="Linux" osgen="5.X" accuracy="96"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os>')
    trace = ""
    if "--traceroute" in args:
        trace = '<trace proto="tcp" port="80"><hop ttl="1" ipaddr="10.0.0.1" rtt="0.40"/><hop ttl="2" ipaddr="' + addr + '" rtt="0.90"/></trace>'
    hostscript = ""
    if "--script" in args and MODE == "vuln":
        hostscript = '<hostscript><script id="smb-os-discovery" output="OS: Fake 1.0"/></hostscript>'
    ports_xml = ("<ports>" + extra + "".join(ports) + "</ports>") if ports else ""
    return ('<host starttime="1" endtime="2"><status state="up" reason="syn-ack" reason_ttl="0"/>'
            '<address addr="' + addr + '" addrtype="' + fam + '"/><hostnames/>' + ports_xml + os_xml + hostscript + trace + '</host>')

HEADER = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
          '<nmaprun scanner="nmap" args="nmap fake" start="1700000000" startstr="Tue Nov 14 22:13:20 2023" version="7.94" xmloutputversion="1.05">\n'
          '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>\n')

def footer(n):
    return ('<runstats><finished time="1700000001" timestr="Tue Nov 14 22:13:21 2023" elapsed="1.00" summary="Nmap done: %d IP addresses (%d hosts up) scanned in 1.00 seconds" exit="success"/>'
            '<hosts up="%d" down="0" total="%d"/></runstats>\n</nmaprun>\n') % (n, n, n, n)

def write_full():
    hosts = [addr_for(t) for t in targets] or ["127.0.0.1"]
    with open(xml_path, "w") as fh:
        fh.write(HEADER + "".join(host_xml(a) for a in hosts) + footer(len(hosts)))
    with open(nmap_path, "w") as fh:
        fh.write("Nmap scan report for " + ", ".join(hosts) + "\n")

def write_partial():
    if xml_path:
        hosts = [addr_for(t) for t in targets] or ["127.0.0.1"]
        with open(xml_path, "w") as fh:
            fh.write(HEADER + host_xml(hosts[0]) + '<host starttime="1"><status state="up"')
    if nmap_path:
        with open(nmap_path, "w") as fh:
            fh.write("partial\n")

def on_signal(signum, frame):
    write_partial()
    log("interrupted")
    sys.exit(1)

log("start")
if MODE == "hang":
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    write_partial()
    while True:
        time.sleep(0.05)
signal.signal(signal.SIGINT, on_signal)
signal.signal(signal.SIGTERM, on_signal)

end = time.time() + DELAY
while time.time() < end:
    time.sleep(0.03)

if MODE == "fail":
    sys.stderr.write("Failed to resolve target.\nQUITTING!\n")
    log("end"); sys.exit(1)
if MODE == "noxml":
    log("end"); sys.exit(0)
if MODE == "badxml":
    open(xml_path, "w").write("<nmaprun><host><garbage")
    open(nmap_path, "w").write("x\n")
    log("end"); sys.exit(0)
if MODE == "truncated":
    write_partial(); log("end"); sys.exit(0)
if MODE == "progress":
    print("Initiating SYN Stealth Scan at 10:00", flush=True)
    print("Discovered open port 22/tcp on 127.0.0.1", flush=True)
    print("Discovered open port 80/tcp on 127.0.0.1", flush=True)
    print("SYN Stealth Scan Timing: About 45.20% done; ETC: 10:05 (0:00:21 remaining)", flush=True)
write_full()
log("end")
sys.exit(3 if MODE == "nonzero_xml" else 0)
'''


def make_fake_nmap(directory: Path, mode: str = "ok", delay: float = 0.0) -> tuple[str, Path]:
    """Create an executable fake nmap. Returns (path, invocation_log_path)."""
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / f"fake_nmap_{mode}.log"
    script = (FAKE_SCRIPT.replace("__PYTHON__", sys.executable).replace("__MODE__", repr(mode))
              .replace("__DELAY__", repr(float(delay))).replace("__LOG__", repr(str(log))))
    path = directory / f"nmap_{mode}_{int(delay * 1000)}"
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path), log


def read_log(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def run_intervals(events: list[dict]) -> list[tuple[float, float, list[str]]]:
    """(start, end, argv) per fake-nmap process, from its own log lines."""
    starts: dict[int, dict] = {}
    out = []
    for e in events:
        if e["event"] == "start":
            starts[e["pid"]] = e
        elif e["event"] in ("end", "interrupted") and e["pid"] in starts:
            s = starts.pop(e["pid"])
            out.append((s["t"], e["t"], s["argv"]))
    return out


def max_concurrent(intervals) -> int:
    points = sorted([(s, 1) for s, _, _ in intervals] + [(e, -1) for _, e, _ in intervals], key=lambda x: (x[0], x[1]))
    cur = best = 0
    for _, d in points:
        cur += d
        best = max(best, cur)
    return best


def fake_availability() -> Availability:
    """An Availability that knows every catalog script (ssl-enum-ciphers is labelled intrusive)."""
    db = {}
    for e in nse_mod.catalog():
        for s in e.scripts:
            db[s] = {"safe", "discovery"}
    db["ssl-enum-ciphers"] = {"discovery", "intrusive"}
    db["vulners"] = {"external", "safe", "vuln"}
    return Availability(db, "/fake/script.db")


class Lab:
    """Builds targets, plans and executes them against a fake nmap, all inside a temp folder."""

    def __init__(self, root: Path, mode: str = "ok", delay: float = 0.0) -> None:
        self.root = Path(root)
        self.reports = self.root / "reports"
        self.nmap, self.log = make_fake_nmap(self.root / "bin", mode, delay)
        self.avail = fake_availability()

    def targets(self, *tokens: str, exclude: tuple[str, ...] = ()) -> TargetSet:
        ts = TargetSet()
        ts.add(list(tokens))
        if exclude:
            ts.add_exclusions(list(exclude))
        return ts

    def plan(self, ts: TargetSet, profiles=(), nse: NseSelection | None = None, opt_in=(), **opts) -> Plan:
        return build_plan(ts, list(profiles), nse, self.avail, PlanOptions(**opts), list(opt_in))

    def session(self, plan: Plan, ts: TargetSet, cfg: Config | None = None, confirm: bool = True) -> Session:
        s = Session.create(self.reports)
        s.data.update({"config": dataclasses.asdict(cfg or Config()), "nmap_version": "7.94-fake", "nmap_path": self.nmap,
                       "scope": {"originals": ts.originals, "targets": [t.to_dict() for t in ts.targets],
                                 "exclusions": [t.to_dict() for t in ts.exclusions], "warnings": list(ts.warnings)}})
        if confirm:
            s.set_authorization("AUTHORIZED", targets_digest(ts))
            s.set_plan_confirmation(len([t for t in plan.tasks if t.status == "pending"]))
        return s

    def executor(self, plan: Plan, ts: TargetSet, cfg: Config | None = None, ask_cancel=None, nmap: str | None = None,
                 confirm: bool = True) -> tuple[Session, Executor]:
        cfg = cfg or Config()
        s = self.session(plan, ts, cfg, confirm)
        ex = Executor(plan, s, cfg, nmap or self.nmap, setup_logger(s.dir / "session.log"),
                      say=lambda m: None, ask_cancel=ask_cancel)
        return s, ex

    def run(self, plan: Plan, ts: TargetSet, cfg: Config | None = None, **kw) -> tuple[Session, Executor]:
        s, ex = self.executor(plan, ts, cfg, **kw)
        ex.run()
        return s, ex

    def intervals(self):
        return run_intervals(read_log(self.log))


class ShortMessages:
    """assertIn / assertNotIn that never print a whole HTML page when they fail."""

    def assertIn(self, member, container, msg=None):
        if isinstance(container, str) and isinstance(member, str):
            if member not in container:
                self.fail(msg or f"{member[:90]!r} not found in text of {len(container)} characters")
        else:
            super().assertIn(member, container, msg)

    def assertNotIn(self, member, container, msg=None):
        if isinstance(container, str) and isinstance(member, str):
            if member in container:
                i = container.index(member)
                self.fail(msg or f"unexpected {member[:90]!r} found at offset {i}: ...{container[max(0, i - 40):i + 60]!r}...")
        else:
            super().assertNotIn(member, container, msg)


class LabTestCase(ShortMessages, unittest.TestCase):
    """Base class: temp folder per test, plus a lab factory."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="nmapflow_test_")
        self.tmp = Path(self._tmp)
        self.addCleanup(self._cleanup)
        self._n = 0

    def _cleanup(self) -> None:
        for p in Path(self._tmp).rglob("*"):
            try:
                p.chmod(0o700 if p.is_dir() else 0o600)
            except OSError:
                pass
        shutil.rmtree(self._tmp, ignore_errors=True)

    def lab(self, mode: str = "ok", delay: float = 0.0) -> Lab:
        self._n += 1
        return Lab(self.tmp / f"lab{self._n}", mode, delay)

    @staticmethod
    def profile(pid: str):
        p = prof_mod.by_id(pid)
        assert p is not None, pid
        return p

    @staticmethod
    def sel(*ids: str) -> NseSelection:
        entries = [nse_mod.by_id(i) for i in ids]
        assert all(entries), ids
        return NseSelection(entries, [e.id for e in entries if e.opt_in])


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0

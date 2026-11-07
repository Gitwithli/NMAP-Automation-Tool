"""Scan-profile catalog, generated from reusable parts (technique x port scope x add-ons).

Every profile has: unique ID, name, description, category, Nmap arguments (one tuple per
process/stage), risk label, duration label and notes. `python3 nmapflow.py --list-profiles`
prints the full catalog with the exact arguments; `--export-catalog FILE` writes Markdown.

Risk labels (nothing destructive exists in this catalog):
  Low       few probes; unlikely to be noticed or to disturb anything
  Moderate  many probes or extra detection; visible in logs/IDS, fine for healthy systems
  Elevated  very high probe volume or very long runtime; can stress fragile devices
Duration labels are rough per-host estimates at T3 on a typical LAN; real time varies.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from . import nse
from .customargs import ArgError, valid_port_spec, validate_custom_args
from .models import ScanProfile
from .privileges import root_reasons

DURATIONS = ["Seconds", "Seconds to minutes", "Minutes", "Tens of minutes", "Hours", "Many hours"]
RISKS = ["Low", "Moderate", "Elevated"]

CATEGORIES = [
    ("required", "Required core"),
    ("discovery", "Host discovery"),
    ("tcp", "TCP port scans"),
    ("udp", "UDP port scans"),
    ("combined", "Combined TCP + UDP (two stages)"),
    ("firewall", "Firewall / filtering analysis"),
    ("osinfo", "OS detection and topology"),
    ("services", "Service enumeration"),
    ("vuln", "Safe vulnerability checks"),
    ("bundles", "Bundles"),
    ("custom", "Custom"),
]

COMMON_TCP = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"
COMMON_UDP = "53,67,68,69,123,137,138,161,162,500,514,520,1900,5353"

# key, label, args, base duration tier, risk increment
TCP_SCOPES = [
    ("ALL", "all 65535 TCP ports", ("-p-",), 2, 1),
    ("TOP1000", "top 1000 TCP ports", ("--top-ports", "1000"), 1, 0),
    ("TOP100", "top 100 TCP ports", ("--top-ports", "100"), 0, 0),
    ("TOP10", "top 10 TCP ports", ("--top-ports", "10"), 0, 0),
    ("WK", "well-known TCP ports 1-1023", ("-p", "1-1023"), 1, 0),
    ("COMMON", "a curated list of common TCP ports", ("-p", COMMON_TCP), 0, 0),
]
UDP_SCOPES = [
    ("ALL", "all 65535 UDP ports", ("-p-",), 5, 2),
    ("TOP10000", "top 10000 UDP ports", ("--top-ports", "10000"), 4, 2),
    ("TOP1000", "top 1000 UDP ports", ("--top-ports", "1000"), 3, 1),
    ("TOP100", "top 100 UDP ports", ("--top-ports", "100"), 2, 0),
    ("TOP20", "top 20 UDP ports", ("--top-ports", "20"), 1, 0),
    ("COMMON", "a curated list of common UDP ports", ("-p", COMMON_UDP), 1, 0),
]
# key, label, args
ADDONS = [
    ("", "", ()),
    ("SV", "with version detection", ("-sV",)),
    ("SV-OS", "with version and OS detection", ("-sV", "-O")),
    ("SV-SC", "with version detection and default scripts", ("-sV", "-sC")),
]
TECH_TCP = [
    ("SYN", "SYN scan", "-sS", "Half-open scan: sends SYN, never completes the handshake."),
    ("CONNECT", "connect scan", "-sT", "Completes the full TCP handshake; works without root but is more visible in target logs."),
]

SERVICES = [
    # key, name, tcp ports, udp ports, safe NSE scripts for the Enumerate tier
    ("http", "HTTP", "80,8000,8008,8080,8888", "", ["http-title", "http-headers", "http-methods", "http-server-header", "http-robots.txt", "http-security-headers"]),
    ("https", "HTTPS / TLS", "443,8443,9443", "", ["ssl-cert", "ssl-date", "sslv2", "ssl-heartbleed", "ssl-ccs-injection", "ssl-dh-params"]),
    ("ssh", "SSH", "22,2222", "", ["ssh-hostkey", "ssh2-enum-algos", "sshv1"]),
    ("ftp", "FTP", "21", "", ["ftp-anon", "ftp-syst"]),
    ("dns", "DNS", "53", "53", ["dns-recursion", "dns-nsid"]),
    ("smb", "SMB", "139,445", "", ["smb-protocols", "smb-security-mode", "smb2-security-mode", "smb-os-discovery"]),
    ("smtp", "SMTP", "25,465,587", "", ["smtp-commands", "ssl-cert"]),
    ("mail", "POP3 / IMAP", "110,143,993,995", "", []),
    ("snmp", "SNMP", "", "161", ["snmp-info", "snmp-sysdescr"]),
    ("mysql", "MySQL", "3306", "", ["mysql-info"]),
    ("postgres", "PostgreSQL", "5432", "", []),
    ("mssql", "Microsoft SQL Server", "1433", "1434", ["ms-sql-info", "ms-sql-ntlm-info"]),
    ("oracle", "Oracle TNS", "1521", "", ["oracle-tns-version"]),
    ("mongodb", "MongoDB", "27017", "", ["mongodb-info"]),
    ("redis", "Redis", "6379", "", ["redis-info"]),
    ("elastic", "Elasticsearch", "9200", "", []),
    ("rdp", "RDP", "3389", "", ["rdp-ntlm-info", "rdp-enum-encryption"]),
    ("vnc", "VNC", "5900-5905", "", ["vnc-info"]),
    ("ldap", "LDAP / LDAPS", "389,636,3268,3269", "", ["ldap-rootdse", "ssl-cert"]),
    ("ntp", "NTP", "", "123", ["ntp-info"]),
    ("telnet", "Telnet", "23", "", ["telnet-encryption"]),
    ("nfs", "NFS / RPC", "111,2049", "111", ["nfs-showmount"]),
    ("winrm", "WinRM", "5985,5986", "", []),
    ("mqtt", "MQTT", "1883,8883", "", []),
]


# ----------------------------------------------------------------- helpers
def _tier(n: int) -> str:
    return DURATIONS[max(0, min(len(DURATIONS) - 1, n))]


def _risk(rank: int) -> str:
    return RISKS[max(0, min(2, rank))]


def _mk(pid: str, name: str, desc: str, cat: str, stages, *, risk: str = "Low", tier: int = 1,
        notes: str = "", warnings=(), scripts=(), allow=frozenset(), opt_in: str = "",
        custom: str = "") -> ScanProfile:
    stages_t = tuple(tuple(s) for s in stages)
    all_args = [a for s in stages_t for a in s]
    return ScanProfile(
        id=pid, name=name, description=desc, category=cat, stages=stages_t, risk=risk,
        duration=_tier(tier), needs_root=bool(root_reasons(all_args)), notes=notes,
        warnings=tuple(warnings), scripts=tuple(scripts), allow_labels=frozenset(allow),
        opt_in=opt_in, custom=custom)


def _addon_notes(addons: tuple[str, ...]) -> tuple[str, list[str]]:
    notes = []
    if "-sV" in addons:
        notes.append("Version detection sends extra probes to open ports.")
    if "-O" in addons:
        notes.append("OS detection is a best-effort guess; it works best with at least one open and one closed TCP port.")
    if "-sC" in addons:
        notes.append("-sC runs the 'default' NSE category (non-intrusive checks).")
    return " ".join(notes), []


def _key(stages) -> tuple:
    return tuple(tuple(s) for s in stages)


# --------------------------------------------------------------- generation
def _required() -> list[ScanProfile]:
    R = "required"
    return [
        _mk("REQ-01-TCP-ALL-ACK", "All TCP ports - ACK scan",
            "ACK scan of all 65535 TCP ports. Maps which ports a firewall filters; it cannot tell open from closed.",
            R, [("-sA", "-p-")], risk="Moderate", tier=2,
            notes="Required profile 1. Corrected from the listed '-sT' flags, which is a connect scan, not an ACK scan (the literal version is profile 9). "
                  "Ports are reported 'unfiltered' or 'filtered', never 'open'. Use profile 2 to find open ports."),
        _mk("REQ-02-TCP-ALL-SYN", "All TCP ports - SYN stealth scan",
            "SYN scan of all 65535 TCP ports. The standard fast open-port discovery scan.",
            R, [("-sS", "-p-")], risk="Moderate", tier=2, notes="Required profile 2."),
        _mk("REQ-03-UDP-ALL", "All UDP ports - UDP scan",
            "UDP scan of all 65535 UDP ports.",
            R, [("-sU", "-p-")], risk="Elevated", tier=5,
            notes="Required profile 3. Full UDP scans are very slow: UDP has no handshake and targets often rate-limit ICMP "
                  "'port unreachable' replies (Linux: about one per second), so one host can take many hours.",
            warnings=("Full UDP scans can take many hours per host. Consider UDP top-1000 first.",)),
        _mk("REQ-04-SYN-ALL-UDP-TOP1000", "All TCP ports SYN scan + top 1000 UDP ports",
            "Two separate Nmap processes: SYN scan of all TCP ports, then a UDP scan of the 1000 most common UDP ports.",
            R, [("-sS", "-p-"), ("-sU", "--top-ports", "1000")], risk="Elevated", tier=4,
            notes="Required profile 4. TCP and UDP scans use different scan types and port scopes (--top-ports applies to every scan type "
                  "in one command), so they run as two stages with two XML files, shown together in the report."),
        _mk("REQ-05-TCP-TOP1000-ACK-SV", "Top 1000 TCP ports - ACK scan with version detection",
            "ACK scan of the top 1000 TCP ports with -sV.",
            R, [("-sA", "--top-ports", "1000", "-sV")], risk="Moderate", tier=2,
            notes="Required profile 5. Corrected from the listed '-sT' flags (literal version is profile 10). "
                  "An ACK scan never reports ports as open, and -sV only probes open ports, so version detection will find nothing. "
                  "Run a SYN scan (profile 6) for services.",
            warnings=("ACK scans report ports as 'filtered'/'unfiltered', never 'open'; -sV has nothing to probe. Use profile 6 for versions.",)),
        _mk("REQ-06-TCP-TOP1000-SYN-SV", "Top 1000 TCP ports - SYN scan with version detection",
            "SYN scan of the top 1000 TCP ports plus service/version detection.",
            R, [("-sS", "--top-ports", "1000", "-sV")], risk="Moderate", tier=2, notes="Required profile 6."),
        _mk("REQ-07-TCP-TOP1000-SYN-SV-OS", "Top 1000 TCP ports - SYN scan with version and OS detection",
            "SYN scan of the top 1000 TCP ports with service/version and OS detection.",
            R, [("-sS", "--top-ports", "1000", "-sV", "-O")], risk="Moderate", tier=2,
            notes="Required profile 7. OS detection is a best-effort guess."),
        _mk("REQ-08-UDP-TOP10000-SV", "Top 10000 UDP ports with version detection",
            "UDP scan of the 10000 most common UDP ports with -sV.",
            R, [("-sU", "--top-ports", "10000", "-sV")], risk="Elevated", tier=5,
            notes="Required profile 8. Expect hours to many hours per host. If Nmap's frequency list holds fewer than 10000 UDP "
                  "ports it scans all it knows. open|filtered results are common; version detection helps resolve some.",
            warnings=("Expect hours to many hours per host.",)),
        _mk("REQ-09-TCP-ALL-CONNECT", "All TCP ports - connect scan (literal flags of required item 1)",
            "TCP connect scan of all 65535 TCP ports (-sT -p-). Finds open ports without root.",
            R, [("-sT", "-p-")], risk="Moderate", tier=2,
            notes="Companion of profile 1: the exact flags originally listed. A connect scan completes handshakes (more visible in logs). No root needed."),
        _mk("REQ-10-TCP-TOP1000-CONNECT-SV", "Top 1000 TCP ports - connect scan with version detection (literal flags of required item 5)",
            "TCP connect scan of the top 1000 TCP ports with -sV (-sT --top-ports 1000 -sV).",
            R, [("-sT", "--top-ports", "1000", "-sV")], risk="Moderate", tier=2,
            notes="Companion of profile 5: the exact flags originally listed. No root needed."),
    ]


def _discovery() -> list[ScanProfile]:
    D = "discovery"
    rows = [
        ("PING-DEFAULT", "Ping sweep (default discovery)", "Host discovery only, no port scan. ARP on the local LAN, otherwise ICMP/TCP probes.", ("-sn",),
         "Without root Nmap falls back to TCP connects to ports 80/443."),
        ("PING-ICMP-ECHO", "ICMP echo ping sweep", "Host discovery using ICMP echo requests.", ("-sn", "-PE"),
         "On the local Ethernet segment Nmap still prefers ARP, which is more reliable."),
        ("PING-ICMP-TIMESTAMP", "ICMP timestamp ping sweep", "Host discovery using ICMP timestamp requests.", ("-sn", "-PP"),
         "Useful when echo requests are filtered."),
        ("PING-ICMP-NETMASK", "ICMP netmask ping sweep", "Host discovery using ICMP address-mask requests.", ("-sn", "-PM"),
         "Rarely answered by modern systems."),
        ("PING-TCP-SYN", "TCP SYN ping sweep (22, 80, 443)", "Host discovery using TCP SYN probes to common ports.", ("-sn", "-PS22,80,443"),
         "Works without root through connect()."),
        ("PING-TCP-ACK", "TCP ACK ping sweep (80, 443)", "Host discovery using TCP ACK probes; can pass stateless firewalls.", ("-sn", "-PA80,443"), ""),
        ("PING-UDP", "UDP ping sweep (53, 161)", "Host discovery using UDP probes to DNS and SNMP ports.", ("-sn", "-PU53,161"), ""),
        ("PING-ARP", "ARP ping sweep (local network only)", "Fast, reliable discovery on the local Ethernet segment.", ("-sn", "-PR"),
         "Only works for targets on the same subnet as the scanning machine."),
        ("PING-COMBINED", "Combined TCP + UDP + ICMP discovery", "Host discovery with ICMP echo, TCP SYN/ACK and UDP probes together.",
         ("-sn", "-PE", "-PS22,80,443", "-PA80,443", "-PU53,161"), "Finds more hosts behind selective filtering at the cost of more probes."),
        ("LIST", "List scan (names only)", "Lists targets and their reverse-DNS names without sending any probe to them.", ("-sL",),
         "Sends DNS queries only. The 'resolve DNS names' setting is ignored for this profile."),
    ]
    return [_mk(f"DISC-{k}", n, d, D, [a], risk="Low", tier=0, notes=note) for k, n, d, a, note in rows]


def _tcp_udp_grids() -> list[ScanProfile]:
    out: list[ScanProfile] = []
    for tkey, tname, tflag, tnote in TECH_TCP:
        for skey, slabel, sargs, tier, rinc in TCP_SCOPES:
            for akey, alabel, aargs in ADDONS:
                args = (tflag, *sargs, *aargs)
                rank = rinc + (1 if ("-sV" in aargs or "-sC" in aargs) else 0)
                at = tier + (1 if "-sV" in aargs else 0) + (1 if "-sC" in aargs else 0)
                anote, _ = _addon_notes(aargs)
                pid = f"TCP-{tkey}-{skey}" + (f"-{akey}" if akey else "")
                name = f"TCP {tname}: {slabel}" + (f" {alabel}" if alabel else "")
                desc = f"{tname.capitalize()} of {slabel}" + (f" {alabel}" if alabel else "") + "."
                note = " ".join(x for x in [tnote, anote] if x)
                out.append(_mk(pid, name, desc, "tcp", [args], risk=_risk(rank), tier=at, notes=note))
    for skey, slabel, sargs, tier, rinc in UDP_SCOPES:
        for akey, alabel, aargs in ADDONS[:2]:
            args = ("-sU", *sargs, *aargs)
            rank = rinc + (1 if aargs else 0)
            at = tier + (1 if aargs else 0)
            pid = f"UDP-{skey}" + (f"-{akey}" if akey else "")
            name = f"UDP scan: {slabel}" + (f" {alabel}" if alabel else "")
            desc = f"UDP scan of {slabel}" + (f" {alabel}" if alabel else "") + "."
            note = ("UDP has no handshake: silent ports show as open|filtered, and many systems rate-limit ICMP replies, "
                    "so UDP scans are slow. Needs root.")
            warns = ("Long-running scan.",) if at >= 4 else ()
            out.append(_mk(pid, name, desc, "udp", [args], risk=_risk(rank), tier=at, notes=note, warnings=warns))
    return out


def _combined() -> list[ScanProfile]:
    def tcp(scope, extra=()):
        d = {"ALL": ("-p-",), "TOP1000": ("--top-ports", "1000"), "TOP100": ("--top-ports", "100")}[scope]
        return ("-sS", *d, *extra)

    def udp(n):
        return ("-sU", "--top-ports", str(n))

    rows = [
        ("SYN-TOP1000-UDP-TOP100", "SYN top 1000 + UDP top 100", [tcp("TOP1000"), udp(100)], "Moderate", 3),
        ("SYN-TOP1000-SV-UDP-TOP100", "SYN top 1000 with version detection + UDP top 100", [tcp("TOP1000", ("-sV",)), udp(100)], "Moderate", 3),
        ("SYN-ALL-UDP-TOP100", "SYN all TCP ports + UDP top 100", [tcp("ALL"), udp(100)], "Moderate", 3),
        ("SYN-TOP100-UDP-TOP20", "Quick: SYN top 100 + UDP top 20", [tcp("TOP100"), udp(20)], "Low", 2),
        ("SYN-TOP1000-SV-OS-UDP-TOP100", "SYN top 1000 with version and OS detection + UDP top 100", [tcp("TOP1000", ("-sV", "-O")), udp(100)], "Moderate", 3),
        ("SYN-ALL-SV-UDP-TOP1000", "SYN all TCP ports with version detection + UDP top 1000", [tcp("ALL", ("-sV",)), udp(1000)], "Elevated", 4),
    ]
    return [_mk(f"COMBO-{k}", n, "Two separate Nmap processes (TCP stage, then UDP stage); results are combined in the report.",
                "combined", st, risk=r, tier=t,
                notes="TCP and UDP use different scan types, so they run as two stages with two XML files.")
            for k, n, st, r, t in rows]


def _firewall() -> list[ScanProfile]:
    F = "firewall"
    out = []
    scopes = {"ALL": ("-p-", "all TCP ports", 2, 1), "TOP1000": (("--top-ports", "1000"), "top 1000 TCP ports", 1, 0),
              "TOP100": (("--top-ports", "100"), "top 100 TCP ports", 0, 0)}

    def sc(k):
        a = scopes[k][0]
        return (a,) if isinstance(a, str) else a

    for k in ("TOP1000", "TOP100"):
        _, lab, tier, rinc = scopes[k]
        out.append(_mk(f"FW-ACK-{k}", f"ACK scan: {lab}", f"ACK scan of the {lab}: shows which ports a firewall filters.",
                       F, [("-sA", *sc(k))], risk=_risk(rinc), tier=tier,
                       notes="Reports ports as unfiltered (packet got through, state unknown) or filtered. Cannot find open ports."))
    for k in ("TOP1000", "TOP100"):
        _, lab, tier, rinc = scopes[k]
        out.append(_mk(f"FW-WINDOW-{k}", f"Window scan: {lab}", f"Window scan of the {lab}: like ACK, but inspects the TCP window field.",
                       F, [("-sW", *sc(k))], risk=_risk(rinc), tier=tier,
                       notes="Only some systems expose open/closed through the TCP window; results are often all 'closed'."))
    for flag, nm in (("-sN", "Null"), ("-sF", "FIN"), ("-sX", "Xmas")):
        for k in ("TOP1000", "TOP100"):
            _, lab, tier, rinc = scopes[k]
            out.append(_mk(f"FW-{nm.upper()}-{k}", f"{nm} scan: {lab}",
                           f"{nm} scan of the {lab}: sends unusual flag combinations to probe the TCP stack and stateless filters.",
                           F, [(flag, *sc(k))], risk=_risk(rinc + 1), tier=tier,
                           notes="Relies on RFC-compliant stacks: Windows targets typically answer nothing, shown as open|filtered. IDS often flags these probes."))
    for k in ("TOP1000", "TOP100"):
        _, lab, tier, rinc = scopes[k]
        out.append(_mk(f"FW-SYN-VS-ACK-{k}", f"SYN vs ACK comparison: {lab}",
                       "Two stages: a SYN scan and an ACK scan of the same ports. Comparing them shows which ports are open (SYN) and which are filtered (ACK).",
                       F, [("-sS", *sc(k)), ("-sA", *sc(k))], risk=_risk(rinc), tier=tier + 1,
                       notes="Two Nmap processes; the report lists both."))
    return out


def _osinfo() -> list[ScanProfile]:
    O = "osinfo"
    rows = [
        ("OS-TOP100", "OS detection (top 100 TCP ports)", ("-sS", "--top-ports", "100", "-O"), 1, ""),
        ("OS-TOP100-GUESS", "OS detection with aggressive guessing", ("-sS", "--top-ports", "100", "-O", "--osscan-guess"), 1,
         "--osscan-guess lists less certain matches; treat them as hints."),
        ("OS-TOP1000-LIMIT", "OS detection only for promising hosts", ("-sS", "--top-ports", "1000", "-O", "--osscan-limit"), 2,
         "--osscan-limit skips OS detection on hosts without both an open and a closed TCP port."),
        ("TRACE-PING", "Traceroute (discovery only)", ("-sn", "--traceroute"), 1, "Shows the hop path to each responding host."),
        ("TRACE-WEB", "Traceroute to web ports", ("-sS", "-p", "80,443", "--traceroute"), 1, ""),
        ("OS-TRACE-TOP100", "OS detection + traceroute (top 100)", ("-sS", "--top-ports", "100", "-O", "--traceroute"), 1, ""),
        ("OS-SV-TRACE-TOP1000", "Version + OS detection + traceroute (top 1000)", ("-sS", "--top-ports", "1000", "-sV", "-O", "--traceroute"), 2, ""),
        ("OS-SVLIGHT-TOP100", "Light version + OS detection (top 100)", ("-sS", "--top-ports", "100", "-sV", "--version-light", "-O"), 1,
         "--version-light uses fewer probes (intensity 2): faster, less thorough."),
    ]
    return [_mk(f"OSINFO-{k}", n, "OS fingerprinting and/or topology information.", O, [a],
                risk="Moderate" if "-O" in a or "-sV" in a else "Low", tier=t,
                notes=(note + " OS detection is a best-effort guess and needs at least one open and one closed TCP port for best accuracy.").strip())
            for k, n, a, t, note in rows]


def _service_args(tcp: str, udp: str) -> list[str]:
    if tcp and udp:
        return ["-sS", "-sU", "-p", f"T:{tcp},U:{udp}", "-sV"]
    if udp:
        return ["-sU", "-p", f"U:{udp}", "-sV"]
    return ["-sS", "-p", tcp, "-sV"]


def _services() -> list[ScanProfile]:
    out = []
    for key, name, tcp, udp, scripts in SERVICES:
        ports = ", ".join(x for x in [f"TCP {tcp}" if tcp else "", f"UDP {udp}" if udp else ""] if x)
        base = _service_args(tcp, udp)
        tier = 3 if udp else 1
        out.append(_mk(f"SVC-{key.upper()}-DETECT", f"{name}: detect services", f"Finds {name} on its usual ports ({ports}) and identifies the product/version. No scripts.",
                       "services", [base], risk="Low", tier=tier,
                       notes="Only the listed ports are scanned; services on other ports are not found." + (" Includes UDP; needs root." if udp else "")))
        if scripts:
            names = ", ".join(scripts)
            out.append(_mk(f"SVC-{key.upper()}-ENUM", f"{name}: enumerate (safe scripts)",
                           f"Detects {name} ({ports}) and runs safe NSE scripts: {names}.",
                           "services", [base + ["--script", ",".join(scripts)]], risk="Low" if "ssl-heartbleed" not in scripts else "Moderate",
                           tier=tier, scripts=scripts,
                           notes="Scripts are checked against your installed Nmap; unavailable ones are reported in the plan, never dropped silently."))
    return out


def _vuln() -> list[ScanProfile]:
    V = "vuln"
    expr = nse.guarded("vuln and safe")
    note = ("Runs only scripts that Nmap labels both 'vuln' and 'safe'; intrusive/dos/exploit/brute/fuzzer/external/broadcast are excluded. "
            "A script that reports nothing does NOT prove the issue is absent, and a reported issue needs manual verification.")
    out = [
        _mk("VULN-SAFE-TOP100", "Safe vulnerability checks: top 100 TCP ports", "Version detection plus safe vulnerability scripts on the top 100 TCP ports.",
            V, [("-sS", "--top-ports", "100", "-sV", "--script", expr)], risk="Moderate", tier=2, notes=note),
        _mk("VULN-SAFE-TOP1000", "Safe vulnerability checks: top 1000 TCP ports", "Version detection plus safe vulnerability scripts on the top 1000 TCP ports.",
            V, [("-sS", "--top-ports", "1000", "-sV", "--script", expr)], risk="Moderate", tier=3, notes=note),
        _mk("VULN-SAFE-ALL", "Safe vulnerability checks: all TCP ports", "Version detection plus safe vulnerability scripts on all TCP ports.",
            V, [("-sS", "-p-", "-sV", "--script", expr)], risk="Elevated", tier=4, notes=note),
        _mk("VULN-SAFE-UDP100", "Safe vulnerability checks: UDP top 100", "Version detection plus safe vulnerability scripts on the top 100 UDP ports.",
            V, [("-sU", "--top-ports", "100", "-sV", "--script", expr)], risk="Moderate", tier=3, notes=note + " UDP scans are slow and need root."),
        _mk("VULN-SAFE-WEB", "Safe vulnerability checks: web ports", "Safe vulnerability scripts on common web ports.",
            V, [("-sS", "-p", "80,443,8000,8080,8443", "-sV", "--script", expr)], risk="Moderate", tier=1, notes=note),
        _mk("VULN-TLS", "TLS weakness checks", "Heartbleed, CCS injection, weak DH parameters and SSLv2 checks on TLS ports.",
            V, [("-sS", "-p", nse.TLS, "-sV", "--script", "ssl-heartbleed,ssl-ccs-injection,ssl-dh-params,sslv2")], risk="Moderate", tier=1,
            scripts=("ssl-heartbleed", "ssl-ccs-injection", "ssl-dh-params", "sslv2"), notes=note),
        _mk("VULN-SMB-MS17-010", "SMB MS17-010 check", "Detects the MS17-010 SMB vulnerability (detection only, no exploit).",
            V, [("-sS", "-p", "139,445", "--script", "smb-vuln-ms17-010")], risk="Moderate", tier=1,
            scripts=("smb-vuln-ms17-010",), notes=note),
        _mk("VULN-EXTERNAL-VULNERS", "Version-based CVE lookup (external service, opt-in)",
            "Looks up detected software versions in the external vulners.com database with the 'vulners' script.",
            V, [("-sS", "--top-ports", "1000", "-sV", "--script", "vulners")], risk="Moderate", tier=3, scripts=("vulners",),
            allow={"external"},
            opt_in="This sends the software names and versions detected on your targets to a third-party service (vulners.com). "
                   "Do not use it where that disclosure is not permitted.",
            notes="Off by default. Results are version-based guesses, not confirmed vulnerabilities.",
            warnings=("Sends detected software versions to an external service.",)),
    ]
    return out


def _bundles() -> list[ScanProfile]:
    B = "bundles"
    return [
        _mk("BUNDLE-STANDARD", "Standard: top 1000 TCP, versions, default scripts, OS", "A balanced first look at a host.",
            B, [("-sS", "--top-ports", "1000", "-sV", "-sC", "-O")], risk="Moderate", tier=3, notes="Runs default (non-intrusive) scripts."),
        _mk("BUNDLE-THOROUGH-TCP", "Thorough TCP: all ports, versions, default scripts, OS", "Full TCP coverage with detection and default scripts.",
            B, [("-sS", "-p-", "-sV", "-sC", "-O")], risk="Elevated", tier=4, notes="Can take a long time per host."),
        _mk("BUNDLE-AGGRESSIVE", "Aggressive (-A): top 1000 TCP", "Nmap's -A: version, OS, default scripts and traceroute.",
            B, [("-sS", "--top-ports", "1000", "-A")], risk="Moderate", tier=3, notes="-A = -sV -O -sC --traceroute. Noisy but not intrusive."),
        _mk("BUNDLE-FULL-AUDIT-LITE", "Full audit (lite): all TCP with versions and OS + UDP top 100 with versions",
            "Two stages covering all TCP ports and the most common UDP ports.",
            B, [("-sS", "-p-", "-sV", "-O"), ("-sU", "--top-ports", "100", "-sV")], risk="Elevated", tier=4,
            notes="Two Nmap processes. Not a substitute for a manual penetration test."),
    ]


def _customs() -> list[ScanProfile]:
    C = "custom"
    return [
        _mk("CUSTOM-PORTS", "Custom port-range scan", "You choose TCP or UDP, the technique, the ports and optional add-ons.",
            C, [("-sS",)], risk="Moderate", tier=2, custom="ports", notes="Ports are validated; arguments are built by the tool."),
        _mk("CUSTOM-ARGS", "Custom Nmap arguments", "You type extra Nmap options, validated against an allow-list.",
            C, [("-sT",)], risk="Moderate", tier=2, custom="args",
            notes="Not allowed: output files, targets, timing, scripts, spoofing/evasion, min-rate. Scripts go through the NSE menu."),
    ]


@lru_cache(maxsize=1)
def _build() -> tuple[ScanProfile, ...]:
    required = _required()
    seen = {_key(p.stages) for p in required}
    out: list[ScanProfile] = list(required)
    for group in (_discovery(), _tcp_udp_grids(), _combined(), _firewall(), _osinfo(), _services(),
                  _vuln(), _bundles(), _customs()):
        for p in group:
            k = _key(p.stages)
            if p.custom == "" and k in seen:
                continue            # identical arguments already offered (e.g. a required profile)
            seen.add(k)
            out.append(p)
    order = {c: i for i, (c, _) in enumerate(CATEGORIES)}
    out.sort(key=lambda p: order[p.category])      # stable: keeps generation order inside a category
    final = []
    for i, p in enumerate(out, 1):
        final.append(ScanProfile(**{**p.__dict__, "number": i}))
    ids = [p.id for p in final]
    assert len(ids) == len(set(ids)), "duplicate profile IDs"
    return tuple(final)


def catalog() -> list[ScanProfile]:
    return list(_build())


def categories() -> list[tuple[str, str, int]]:
    """(key, name, count) for every category, in menu order."""
    cat = _build()
    return [(k, n, sum(1 for p in cat if p.category == k)) for k, n in CATEGORIES]


def by_number(num: int) -> ScanProfile | None:
    cat = _build()
    return cat[num - 1] if 1 <= num <= len(cat) else None


def by_id(pid: str) -> ScanProfile | None:
    for p in _build():
        if p.id == pid:
            return p
    return None


def in_category(key: str) -> list[ScanProfile]:
    return [p for p in _build() if p.category == key]


def search(text: str) -> list[ScanProfile]:
    t = text.lower().strip()
    return [p for p in _build() if t in p.id.lower() or t in p.name.lower() or t in p.description.lower()]


# ------------------------------------------------------------------ custom
def make_custom_ports(proto: str, technique: str, ports: str, addons: list[str]) -> ScanProfile:
    """Build a custom port-range profile. Raises ArgError on invalid input."""
    if not valid_port_spec(ports):
        raise ArgError(f"'{ports}' is not a valid port specification (examples: 80, 1-1023, 22,80,443)")
    if proto == "udp":
        base = "-sU"
    else:
        if technique not in ("-sS", "-sT", "-sA", "-sW", "-sN", "-sF", "-sX"):
            raise ArgError("unknown scan technique")
        base = technique
    allowed = {"-sV", "-sC", "-O"}
    if any(a not in allowed for a in addons):
        raise ArgError("unknown add-on")
    args = (base, "-p", ports, *addons)
    return _mk(f"CUSTOM-{proto.upper()}-{base[1:]}-{ports[:30].replace(',', '_').replace(':', '')}",
               f"Custom {proto.upper()} {base} ports {ports}", f"Custom scan: {base} on ports {ports}"
               + (f" with {' '.join(addons)}" if addons else "") + ".", "custom", [args],
               risk="Moderate" if addons else "Low", tier=2, notes="Custom profile created in this session.", custom="ports")


def make_custom_args(text: str) -> ScanProfile:
    args = validate_custom_args(text)
    import hashlib
    digest = hashlib.sha1(" ".join(args).encode()).hexdigest()[:8]
    return _mk(f"CUSTOM-ARGS-{digest}", "Custom Nmap arguments", "Custom: " + " ".join(args),
               "custom", [tuple(args)], risk="Moderate", tier=2, notes="Custom profile created in this session.", custom="args")


# --------------------------------------------------------------- rendering
def render(p: ScanProfile, width: int = 100) -> str:
    """Multi-line text describing a profile, including the exact Nmap arguments."""
    import textwrap
    lines = [f"[{p.number}] {p.name}", f"  ID:       {p.id}", f"  Category: {dict(CATEGORIES)[p.category]}"]
    for i, st in enumerate(p.stages, 1):
        label = f"  Nmap {'stage ' + str(i) if len(p.stages) > 1 else 'args'}: "
        lines.append(label.ljust(14) + " ".join(st))
    lines.append(f"  Risk: {p.risk}   Duration: {p.duration}   Root needed: {'yes' if p.needs_root else 'no'}")
    for label, text in (("About", p.description), ("Notes", p.notes)):
        if text:
            lines += textwrap.wrap(f"{label}: {text}", width=width, initial_indent="  ", subsequent_indent="    ")
    for w in p.warnings:
        lines += textwrap.wrap(f"WARNING: {w}", width=width, initial_indent="  ", subsequent_indent="    ")
    if p.opt_in:
        lines += textwrap.wrap(f"OPT-IN: {p.opt_in}", width=width, initial_indent="  ", subsequent_indent="    ")
    return "\n".join(lines)


def export_markdown(path: Path) -> None:
    out = ["# nmapflow scan-profile catalog", "",
           "Generated by `python3 nmapflow.py --export-catalog`. Arguments shown are the profile-specific Nmap options; "
           "the tool adds `-T<n>`, output options (`-oX`, `-oN`), `--stats-every`, `-v`, `--reason` and target arguments itself.", "",
           f"Total profiles: {len(_build())}", ""]
    for key, name, count in categories():
        out += [f"## {name} ({count})", "", "| # | ID | Name | Nmap arguments | Risk | Duration | Root | Notes |", "|---|---|---|---|---|---|---|---|"]
        for p in in_category(key):
            args = " &rarr; ".join("`" + " ".join(s).replace("|", "\\|") + "`" for s in p.stages)
            notes = (p.notes + (" **WARNING:** " + " ".join(p.warnings) if p.warnings else "")).replace("|", "\\|")
            out.append(f"| {p.number} | `{p.id}` | {p.name} | {args} | {p.risk} | {p.duration} | {'yes' if p.needs_root else 'no'} | {notes} |")
        out.append("")
    path.write_text("\n".join(out), encoding="utf-8")

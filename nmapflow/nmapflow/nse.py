"""NSE catalog: categories, individual scripts and bundles; safety guard and availability checks.

Scripts are chosen from a fixed allow-list. Users cannot type script names, paths or
script arguments. Every category is passed to Nmap wrapped in an exclusion expression so
intrusive, DoS, exploit, brute-force, fuzzer, external and broadcast scripts never run.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

BANNED_CATEGORIES = ("intrusive", "dos", "exploit", "brute", "fuzzer", "external", "broadcast")
GUARD = "not (" + " or ".join(BANNED_CATEGORIES) + ")"

WEB = "80,443,8080,8443"
TLS = "443,465,636,993,995,8443"


def guarded(expression: str) -> str:
    """Wrap a category expression so banned categories are always excluded.
    Passed to Nmap as ONE argument (no shell), e.g. '(safe) and not (intrusive or ...)'."""
    return f"({expression}) and {GUARD}"


@dataclass(frozen=True)
class NseEntry:
    num: int
    id: str
    name: str
    kind: str                     # category | script | bundle
    purpose: str
    risk: str
    intrusive: str                # 'No' or an explanation
    expression: str = ""          # categories only
    scripts: tuple[str, ...] = ()  # script name, or the members of a bundle
    tcp_ports: str = ""
    udp_ports: str = ""
    opt_in: bool = False
    opt_in_text: str = ""


# name, purpose, risk, tcp, udp
_SCRIPT_ROWS = [
    ("http-title", "Page title of web servers", "Low", WEB, ""),
    ("http-headers", "HTTP response headers", "Low", WEB, ""),
    ("http-methods", "HTTP methods the server advertises", "Low", WEB, ""),
    ("http-server-header", "Server banner header", "Low", WEB, ""),
    ("http-robots.txt", "Reads robots.txt entries", "Low", WEB, ""),
    ("http-security-headers", "Checks OWASP security headers (HSTS, CSP, X-Frame-Options, ...)", "Low", "80,443", ""),
    ("ssl-cert", "Certificate subject, issuer and expiry", "Low", TLS, ""),
    ("ssl-date", "Server clock as reported over TLS", "Low", TLS, ""),
    ("sslv2", "Detects obsolete SSLv2 support", "Low", TLS, ""),
    ("ssl-heartbleed", "Heartbleed check", "Moderate", TLS, ""),
    ("ssl-ccs-injection", "CCS injection check", "Moderate", TLS, ""),
    ("ssl-dh-params", "Weak Diffie-Hellman parameters", "Low", TLS, ""),
    ("ssl-enum-ciphers", "Accepted TLS versions and ciphers with strength grades", "Low to Moderate", TLS, ""),
    ("ssh-hostkey", "Host key fingerprints", "Low", "22", ""),
    ("ssh2-enum-algos", "Key exchange, cipher and MAC algorithms offered", "Low", "22", ""),
    ("sshv1", "Flags legacy SSH protocol 1", "Low", "22", ""),
    ("smb-protocols", "SMB dialects supported", "Low", "139,445", ""),
    ("smb-security-mode", "Authentication and signing mode", "Low", "139,445", ""),
    ("smb2-security-mode", "SMB2/3 signing requirement", "Low", "445", ""),
    ("smb-os-discovery", "OS, host and domain names via SMB", "Low", "139,445", ""),
    ("smb-vuln-ms17-010", "MS17-010 check (detection only, no exploit)", "Moderate", "445", ""),
    ("dns-recursion", "Whether the server allows open recursion", "Low", "53", "53"),
    ("dns-nsid", "DNS server identity (NSID)", "Low", "53", "53"),
    ("ftp-anon", "Tests anonymous FTP login (one attempt, no guessing)", "Low", "21", ""),
    ("ftp-syst", "FTP SYST information", "Low", "21", ""),
    ("smtp-commands", "SMTP commands the server supports", "Low", "25,465,587", ""),
    ("snmp-info", "SNMP engine information (standard 'public' community only)", "Low", "", "161"),
    ("snmp-sysdescr", "System description over SNMP", "Low", "", "161"),
    ("mysql-info", "Version and capabilities from the handshake", "Low", "3306", ""),
    ("ms-sql-info", "SQL Server instance information", "Low", "1433", "1434"),
    ("ms-sql-ntlm-info", "Windows host and domain names via NTLM", "Low", "1433", ""),
    ("mongodb-info", "Server and build information", "Low", "27017", ""),
    ("redis-info", "Server information when no authentication is required", "Low", "6379", ""),
    ("oracle-tns-version", "TNS listener version", "Low", "1521", ""),
    ("rdp-ntlm-info", "Windows host and domain names via RDP", "Low", "3389", ""),
    ("rdp-enum-encryption", "RDP security layers and encryption levels", "Low", "3389", ""),
    ("ldap-rootdse", "LDAP server capabilities and naming contexts", "Low", "389,636", ""),
    ("ntp-info", "NTP server variables", "Low", "", "123"),
    ("vnc-info", "VNC protocol version and authentication types", "Low", "5900-5905", ""),
    ("telnet-encryption", "Whether Telnet offers encryption", "Low", "23", ""),
    ("nfs-showmount", "Lists exported NFS shares", "Low", "111,2049", ""),
]

_OPT_IN_SCRIPT = {
    "ssl-enum-ciphers": ("Nmap labels this script 'intrusive': it opens many TLS handshakes to list "
                         "every accepted cipher. It is not destructive, but it is noisy and may be "
                         "logged or rate-limited by the target."),
}

_BUNDLES = [
    ("http", "HTTP bundle", ["http-title", "http-headers", "http-methods", "http-server-header",
                             "http-robots.txt", "http-security-headers"]),
    ("tls", "TLS bundle", ["ssl-cert", "ssl-date", "sslv2", "ssl-heartbleed", "ssl-ccs-injection", "ssl-dh-params"]),
    ("ssh", "SSH bundle", ["ssh-hostkey", "ssh2-enum-algos", "sshv1"]),
    ("smb", "SMB bundle", ["smb-protocols", "smb-security-mode", "smb2-security-mode",
                           "smb-os-discovery", "smb-vuln-ms17-010"]),
    ("dns", "DNS bundle", ["dns-recursion", "dns-nsid"]),
    ("ftp", "FTP bundle", ["ftp-anon", "ftp-syst"]),
    ("snmp", "SNMP bundle", ["snmp-info", "snmp-sysdescr"]),
    ("db", "Database bundle", ["mysql-info", "ms-sql-info", "ms-sql-ntlm-info", "mongodb-info",
                               "redis-info", "oracle-tns-version"]),
    ("rdp", "RDP bundle", ["rdp-ntlm-info", "rdp-enum-encryption"]),
]


def _build_catalog() -> list[NseEntry]:
    entries: list[NseEntry] = []
    cats = [
        ("default", "default", "default", "Nmap's standard information-gathering set (same as -sC)", "Low", "No"),
        ("safe", "safe", guarded("safe"), "Scripts designed not to affect targets", "Low", "No"),
        ("discovery", "discovery", guarded("discovery"), "DNS, directory, service and network information",
         "Low to Moderate", "Intrusive members removed by the guard"),
        ("version", "version", "version", "Extends -sV; runs only with version detection", "Low", "No"),
        ("vuln", "vuln (safe only)", guarded("vuln and safe"), "Non-disruptive known-vulnerability checks",
         "Moderate", "Intrusive members removed by the guard"),
    ]
    n = 1
    for cid, name, expr, purpose, risk, intr in cats:
        entries.append(NseEntry(n, f"cat-{cid}", name, "category", purpose, risk, intr, expression=expr))
        n += 1
    for name, purpose, risk, tcp, udp in _SCRIPT_ROWS:
        opt = name in _OPT_IN_SCRIPT
        entries.append(NseEntry(
            n, name, name, "script", purpose, risk,
            "Labelled intrusive by Nmap; opt-in with confirmation" if opt else "No",
            scripts=(name,), tcp_ports=tcp, udp_ports=udp, opt_in=opt,
            opt_in_text=_OPT_IN_SCRIPT.get(name, "")))
        n += 1
    by_name = {e.id: e for e in entries}
    for bid, bname, members in _BUNDLES:
        tcp = merge_ports([by_name[m].tcp_ports for m in members])
        udp = merge_ports([by_name[m].udp_ports for m in members])
        entries.append(NseEntry(n, f"bundle-{bid}", bname, "bundle",
                                f"{len(members)} scripts: " + ", ".join(members), "Low to Moderate", "No",
                                scripts=tuple(members), tcp_ports=tcp, udp_ports=udp))
        n += 1
    return entries


def merge_ports(specs: list[str]) -> str:
    """Union of simple port lists like '80,443' or '5900-5905', as a compact string."""
    nums: set[int] = set()
    for spec in specs:
        for item in filter(None, (s.strip() for s in spec.split(","))):
            if "-" in item:
                lo, hi = item.split("-", 1)
                nums.update(range(int(lo), int(hi) + 1))
            else:
                nums.add(int(item))
    out: list[str] = []
    ordered = sorted(nums)
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        out.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(out)


_CATALOG = _build_catalog()


def catalog() -> list[NseEntry]:
    return list(_CATALOG)


def by_number(num: int) -> NseEntry | None:
    return _CATALOG[num - 1] if 1 <= num <= len(_CATALOG) else None


def by_id(entry_id: str) -> NseEntry | None:
    for e in _CATALOG:
        if e.id == entry_id:
            return e
    return None


# --------------------------------------------------------------- availability
_ENTRY_RE = re.compile(r'Entry\s*\{\s*filename\s*=\s*"([^"]+)"\s*,\s*categories\s*=\s*\{([^}]*)\}', re.S)
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def find_script_db(nmap_bin: str | None = None) -> Path | None:
    cands: list[Path] = []
    env = os.environ.get("NMAPDIR")
    if env:
        cands.append(Path(env) / "scripts" / "script.db")
    if nmap_bin:
        try:
            root = Path(shutil.which(nmap_bin) or nmap_bin).resolve().parent.parent
            cands.append(root / "share" / "nmap" / "scripts" / "script.db")
        except OSError:
            pass
    cands += [Path("/usr/share/nmap/scripts/script.db"), Path("/usr/local/share/nmap/scripts/script.db"),
              Path("/opt/homebrew/share/nmap/scripts/script.db")]
    for c in cands:
        if c.is_file():
            return c
    return None


def parse_script_db(path: Path) -> dict[str, set[str]]:
    """Map script name -> its categories, read from the installed Nmap's script.db."""
    text = path.read_text(encoding="utf-8", errors="replace")
    db: dict[str, set[str]] = {}
    for fname, cats in _ENTRY_RE.findall(text):
        name = fname[:-4] if fname.endswith(".nse") else fname
        db[name] = set(re.findall(r'"([^"]+)"', cats))
    return db


@dataclass
class Availability:
    """Result of comparing the catalog with the installed Nmap's script database."""
    db: dict[str, set[str]] | None
    db_path: str = ""
    messages: list[str] = field(default_factory=list)

    def check_script(self, name: str, allow: frozenset = frozenset()) -> tuple[bool, str]:
        if not _NAME_RE.match(name):
            return False, "invalid script name"
        if self.db is None:
            return False, "Nmap's script.db was not found, so scripts cannot be verified"
        cats = self.db.get(name)
        if cats is None:
            return False, "not installed in this Nmap version"
        bad = (cats & set(BANNED_CATEGORIES)) - set(allow)
        if bad:
            return False, "this Nmap version labels it: " + ", ".join(sorted(bad))
        return True, ""

    def check(self, entry: NseEntry) -> tuple[bool, str]:
        if entry.kind == "category":
            return True, ""
        allow = frozenset({"intrusive"}) if entry.opt_in else frozenset()
        usable, missing = [], []
        for s in entry.scripts:
            ok, why = self.check_script(s, allow)
            (usable if ok else missing).append((s, why))
        if not usable:
            return False, missing[0][1] if len(entry.scripts) == 1 else "none of its scripts are usable (" + missing[0][1] + ")"
        if missing:
            return True, "partly available; unavailable: " + ", ".join(f"{s} ({w})" for s, w in missing)
        return True, ""

    def usable_scripts(self, names: list[str], allow: frozenset = frozenset()) -> tuple[list[str], list[str]]:
        """Split names into (usable, problems). Problems are human-readable strings."""
        ok_list, problems = [], []
        for n in names:
            ok, why = self.check_script(n, allow)
            if ok:
                ok_list.append(n)
            else:
                problems.append(f"{n}: {why}")
        return ok_list, problems


def load_availability(nmap_bin: str | None) -> Availability:
    path = find_script_db(nmap_bin)
    if path is None:
        return Availability(None, "", ["script.db not found; NSE scripts cannot be verified or used."])
    try:
        return Availability(parse_script_db(path), str(path))
    except OSError as exc:
        return Availability(None, str(path), [f"cannot read {path}: {exc}"])


# ------------------------------------------------------------------ selection
@dataclass
class NseSelection:
    entries: list[NseEntry] = field(default_factory=list)
    confirmed_opt_in: list[str] = field(default_factory=list)   # entry ids confirmed by the user

    def is_empty(self) -> bool:
        return not self.entries


@dataclass
class NseGroup:
    """One NSE task specification produced from a selection."""
    id: str
    label: str
    args: list[str]
    entry_ids: list[str]
    notes: str = ""
    confirm_note: str = ""
    warnings: list[str] = field(default_factory=list)


def expand_selection(sel: NseSelection, avail: Availability, category_udp_top_ports: int = 0
                     ) -> tuple[list[NseGroup], list[str]]:
    """Turn a selection into task specs. Returns (groups, warnings). Nothing is dropped
    silently: unavailable scripts are reported in the warnings."""
    groups: list[NseGroup] = []
    warnings: list[str] = []
    script_ids: dict[str, list[str]] = {}      # script -> entry ids that requested it
    for e in sel.entries:
        if e.kind == "category":
            args = ["-sT", "--top-ports", "1000", "-sV", "--script", e.expression]
            groups.append(NseGroup(f"nse-{e.id}", f"NSE category: {e.name} (TCP top 1000)", args, [e.id],
                                   notes="Category scripts run against the top 1000 TCP ports with -sV."))
            if category_udp_top_ports > 0:
                uargs = ["-sU", "--top-ports", str(category_udp_top_ports), "-sV", "--script", e.expression]
                groups.append(NseGroup(f"nse-{e.id}-udp", f"NSE category: {e.name} (UDP top {category_udp_top_ports})",
                                       uargs, [e.id], notes="UDP scan: slow, needs root."))
        else:
            for s in e.scripts:
                script_ids.setdefault(s, []).append(e.id)
    if script_ids:
        confirm_notes = []
        allow_all = set()
        for s, ids in script_ids.items():
            entry = by_id(s)
            if entry is not None and entry.opt_in:
                allow_all.add("intrusive")
                if s in sel.confirmed_opt_in or any(i in sel.confirmed_opt_in for i in ids):
                    confirm_notes.append(f"{s}: user confirmed opt-in")
                else:
                    warnings.append(f"{s} requires explicit confirmation and was not confirmed; it was not scheduled.")
                    script_ids = {k: v for k, v in script_ids.items() if k != s}
        usable_tcp: list[str] = []
        usable_udp: list[str] = []
        tcp_ports: list[str] = []
        udp_ports: list[str] = []
        for s in script_ids:
            entry = by_id(s)
            allow = frozenset({"intrusive"}) if entry and entry.opt_in else frozenset()
            ok, why = avail.check_script(s, allow)
            if not ok:
                warnings.append(f"script {s} was not scheduled: {why}")
                continue
            if entry.tcp_ports:
                usable_tcp.append(s)
                tcp_ports.append(entry.tcp_ports)
            if entry.udp_ports:
                usable_udp.append(s)
                udp_ports.append(entry.udp_ports)
        if usable_tcp:
            ports = merge_ports(tcp_ports)
            groups.append(NseGroup(
                "nse-scripts-tcp", f"NSE scripts (TCP): {', '.join(usable_tcp)}",
                ["-sT", "-p", ports, "-sV", "--script", ",".join(usable_tcp)], list(usable_tcp),
                notes=f"Ports taken from each script's usual ports: {ports}.",
                confirm_note="; ".join(confirm_notes)))
        if usable_udp:
            ports = merge_ports(udp_ports)
            groups.append(NseGroup(
                "nse-scripts-udp", f"NSE scripts (UDP): {', '.join(usable_udp)}",
                ["-sU", "-p", ports, "-sV", "--script", ",".join(usable_udp)], list(usable_udp),
                notes=f"UDP ports: {ports}. UDP scanning needs root."))
    return groups, warnings

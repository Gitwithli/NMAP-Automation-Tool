"""Target parsing, validation, de-duplication, exclusions and scope information."""

from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .models import Target

MAX_RANGE_ADDRESSES = 65536
MAX_FILE_BYTES = 1_000_000
MAX_TARGET_ENTRIES = 65536

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*\.?$")
_OCTET_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
_FULL_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")


class TargetError(ValueError):
    """A target string was rejected; the message explains why."""


@dataclass
class Unit:
    """One schedulable piece of scope: an IP, a CIDR block or a hostname."""
    token: str
    kind: str
    addresses: int
    lock_keys: list[str]


def _is_numeric_dotted(text: str) -> bool:
    return all(part.isdigit() for part in text.rstrip(".").split("."))


def parse_token(token: str, source: str = "typed") -> list[Target]:
    """Turn one user token into Target objects (ranges expand into several IPs)."""
    raw = token.strip()
    if not raw:
        raise TargetError("empty target")
    if raw.startswith("-"):
        raise TargetError(f"'{raw}' starts with '-' and could be mistaken for an Nmap option")
    if len(raw) > 253:
        raise TargetError("target is too long")
    if any(ch in raw for ch in " \t\r\n;|&$`\"'\\<>(){}*?!"):
        raise TargetError(f"'{raw}' contains characters that are not valid in a target")

    # single IP
    try:
        ip = ipaddress.ip_address(raw)
        return [Target(raw, "ip", str(ip), "ipv6" if ip.version == 6 else "ipv4", source)]
    except ValueError:
        pass

    # CIDR
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise TargetError(f"'{raw}' is not a valid CIDR range ({exc})") from exc
        if net.version == 4 and net.prefixlen < 8:
            raise TargetError(f"'{raw}' is larger than a /8; split it into smaller ranges")
        if net.version == 6 and net.prefixlen < 112:
            raise TargetError(f"'{raw}' is too large to scan; IPv6 ranges must be /112 or smaller")
        return [Target(raw, "cidr", str(net), "ipv6" if net.version == 6 else "ipv4", source)]

    # 192.168.10.2-20
    m = _OCTET_RANGE_RE.match(raw)
    if m:
        prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        if lo > hi or hi > 255:
            raise TargetError(f"'{raw}' is not a valid last-octet range")
        try:
            return [Target(raw, "ip", str(ipaddress.IPv4Address(f"{prefix}{n}")), "ipv4", source)
                    for n in range(lo, hi + 1)]
        except ValueError as exc:
            raise TargetError(f"'{raw}' is not a valid range ({exc})") from exc

    # 10.0.0.5-10.0.0.40
    m = _FULL_RANGE_RE.match(raw)
    if m:
        try:
            a, b = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
        except ValueError as exc:
            raise TargetError(f"'{raw}' is not a valid range ({exc})") from exc
        if a > b:
            raise TargetError(f"'{raw}': range start is after range end")
        if int(b) - int(a) + 1 > MAX_RANGE_ADDRESSES:
            raise TargetError(f"'{raw}' spans more than {MAX_RANGE_ADDRESSES} addresses")
        return [Target(raw, "ip", str(ipaddress.IPv4Address(n)), "ipv4", source)
                for n in range(int(a), int(b) + 1)]

    # hostname
    if _is_numeric_dotted(raw) or ":" in raw:
        raise TargetError(f"'{raw}' is not a valid IP address or hostname")
    if not _HOST_RE.match(raw):
        raise TargetError(f"'{raw}' is not a valid hostname")
    return [Target(raw, "hostname", raw.lower().rstrip("."), "ipv4", source)]


def load_target_file(path: str) -> tuple[list[str], list[str]]:
    """Read tokens from a text file ('#' starts a comment). Returns (tokens, problems)."""
    p = Path(path).expanduser()
    problems: list[str] = []
    try:
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            return [], [f"{p}: file is larger than {MAX_FILE_BYTES // 1000} KB"]
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"cannot read {p}: {exc.strerror or exc}"]
    tokens: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0]
        for tok in re.split(r"[,\s]+", line.strip()):
            if tok:
                tokens.append(tok)
    if not tokens:
        problems.append(f"{p}: no targets found")
    return tokens, problems


def resolve_hostnames(names: list[str], timeout: float = 6.0) -> dict[str, list[str]]:
    """Resolve hostnames (best effort). Unresolvable names map to an empty list."""
    def one(name: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError):
            return []
        seen: list[str] = []
        for info in infos:
            addr = info[4][0].split("%", 1)[0]
            if addr not in seen:
                seen.append(addr)
        return seen

    result: dict[str, list[str]] = {n: [] for n in names}
    if not names:
        return result
    pool = ThreadPoolExecutor(max_workers=min(8, len(names)))
    futures = {n: pool.submit(one, n) for n in names}
    for n, fut in futures.items():
        try:
            result[n] = fut.result(timeout=timeout)
        except Exception:
            result[n] = []
    pool.shutdown(wait=False, cancel_futures=True)
    return result


@dataclass
class TargetSet:
    """Everything the user asked to scan, with validation results."""
    originals: list[str] = field(default_factory=list)     # as typed, preserved
    targets: list[Target] = field(default_factory=list)    # validated, de-duplicated
    exclusions: list[Target] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)        # rejected input (never scanned)

    # ----------------------------------------------------------- building
    def add(self, tokens: list[str], source: str = "typed") -> None:
        for tok in tokens:
            self.originals.append(tok)
            try:
                new = parse_token(tok, source)
            except TargetError as exc:
                self.errors.append(str(exc))
                continue
            known = {(t.kind, t.normalized) for t in self.targets}
            before = len(self.targets)
            for t in new:
                if (t.kind, t.normalized) in known:
                    self._warn(f"duplicate target ignored: {t.normalized}")
                    continue
                known.add((t.kind, t.normalized))
                self.targets.append(t)
            if len(self.targets) > MAX_TARGET_ENTRIES:
                del self.targets[before:]
                self.errors.append(f"'{tok}' would exceed the limit of {MAX_TARGET_ENTRIES} target entries and was not added")

    def _warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def add_exclusions(self, tokens: list[str]) -> None:
        for tok in tokens:
            try:
                self.exclusions.extend(parse_token(tok, "typed"))
            except TargetError as exc:
                self.errors.append(f"exclusion: {exc}")

    def resolve(self, prefer_ipv6: bool = False) -> None:
        """Resolve hostnames, assign each a family, and remember unresolved ones."""
        names = [t.normalized for t in self.targets + self.exclusions if t.kind == "hostname"]
        table = resolve_hostnames(sorted(set(names)))
        for t in self.targets + self.exclusions:
            if t.kind != "hostname":
                continue
            t.resolved = table.get(t.normalized, [])
            if not t.resolved:
                self._warn(f"hostname '{t.normalized}' did not resolve (it will still be passed to Nmap and reported)")
                continue
            has4 = any(":" not in a for a in t.resolved)
            has6 = any(":" in a for a in t.resolved)
            t.family = "ipv6" if (has6 and (prefer_ipv6 or not has4)) else "ipv4"

    # ------------------------------------------------------------ queries
    def _exclusion_networks(self) -> list[ipaddress._BaseNetwork]:
        nets: list[ipaddress._BaseNetwork] = []
        for e in self.exclusions:
            if e.kind == "cidr":
                nets.append(ipaddress.ip_network(e.normalized))
            elif e.kind == "ip":
                nets.append(ipaddress.ip_network(e.normalized))
            else:
                for a in e.resolved:
                    nets.append(ipaddress.ip_network(a))
        return nets

    def exclusion_tokens(self, family: str) -> list[str]:
        out = [e.normalized for e in self.exclusions if e.family == family or e.kind == "hostname"]
        return list(dict.fromkeys(out))

    def _covered(self, net: ipaddress._BaseNetwork, others: list[ipaddress._BaseNetwork]) -> bool:
        return any(o.version == net.version and net.subnet_of(o) for o in others)

    def units(self, family: str) -> list[Unit]:
        """Schedulable units for one address family, with redundant entries pruned."""
        cidrs = [ipaddress.ip_network(t.normalized) for t in self.targets
                 if t.kind == "cidr" and t.family == family]
        ex_nets = self._exclusion_networks()
        units: list[Unit] = []
        for t in self.targets:
            if t.family != family:
                continue
            if t.kind == "ip":
                ip_net = ipaddress.ip_network(t.normalized)
                if any(ip_net.subnet_of(c) for c in cidrs):
                    continue     # already covered by a CIDR target
                if self._covered(ip_net, ex_nets):
                    self._warn(f"{t.normalized} is excluded and will not be scanned")
                    continue
                units.append(Unit(t.normalized, "ip", 1, [str(ip_net)]))
            elif t.kind == "cidr":
                net = ipaddress.ip_network(t.normalized)
                units.append(Unit(str(net), "cidr", net.num_addresses, [str(net)]))
            else:
                keys = [f"host:{t.normalized}"] + [str(ipaddress.ip_network(a)) for a in t.resolved]
                units.append(Unit(t.normalized, "hostname", 1, keys))
        # drop a CIDR that is wholly inside another CIDR
        pruned: list[Unit] = []
        for u in units:
            if u.kind == "cidr":
                n = ipaddress.ip_network(u.token)
                if any(o is not u and o.kind == "cidr" and n != ipaddress.ip_network(o.token)
                       and n.subnet_of(ipaddress.ip_network(o.token)) for o in units):
                    continue
            pruned.append(u)
        return pruned

    def families(self) -> list[str]:
        fams = []
        for t in self.targets:
            if t.family not in fams:
                fams.append(t.family)
        return fams

    def total_addresses(self) -> int:
        total = 0
        for fam in self.families():
            total += sum(u.addresses for u in self.units(fam))
        return total

    def public_targets(self) -> list[str]:
        out = []
        for t in self.targets:
            addrs: list[str]
            if t.kind == "hostname":
                addrs = t.resolved
            else:
                addrs = [t.normalized.split("/")[0]]
            for a in addrs:
                try:
                    if ipaddress.ip_address(a).is_global:
                        out.append(t.normalized)
                        break
                except ValueError:
                    continue
        return out

    def large_ranges(self) -> list[str]:
        out = []
        for t in self.targets:
            if t.kind == "cidr":
                n = ipaddress.ip_network(t.normalized)
                if n.num_addresses >= 65536:
                    out.append(t.normalized)
        return out

    def extra_confirmation_reasons(self) -> list[str]:
        reasons = []
        pub = self.public_targets()
        if pub:
            shown = ", ".join(pub[:5]) + (" ..." if len(pub) > 5 else "")
            reasons.append(f"{len(pub)} target(s) are public Internet addresses ({shown}). "
                           "Only scan public systems you are explicitly authorized to test.")
        big = self.large_ranges()
        if big:
            reasons.append(f"Large range(s): {', '.join(big)} (65,536 addresses or more). "
                           "Scans may take very long and generate heavy traffic.")
        return reasons

    def digest_tokens(self) -> list[str]:
        """Stable list used to prove that what was confirmed is what gets scanned."""
        toks = sorted(f"{t.kind}:{t.normalized}" for t in self.targets)
        toks += sorted(f"exclude:{e.kind}:{e.normalized}" for e in self.exclusions)
        return toks

    def is_empty(self) -> bool:
        return not self.targets

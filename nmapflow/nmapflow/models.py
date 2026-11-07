"""Data model: dataclasses shared by every module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

# Task statuses. Every requested scan always ends in exactly one of the last six.
PENDING, RUNNING = "pending", "running"
COMPLETED, FAILED, TIMED_OUT, CANCELLED, SKIPPED = (
    "completed", "failed", "timed_out", "cancelled", "skipped")
FINAL_STATUSES = (COMPLETED, FAILED, TIMED_OUT, CANCELLED, SKIPPED)


# ---------------------------------------------------------------- targets
@dataclass
class Target:
    raw: str                      # exactly what the user typed
    kind: str                     # ip | cidr | hostname
    normalized: str               # what is handed to Nmap
    family: str = "ipv4"          # ipv4 | ipv6
    source: str = "typed"         # typed | file | subnet
    resolved: list[str] = field(default_factory=list)  # hostnames only

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------- profiles
@dataclass(frozen=True)
class ScanProfile:
    id: str
    name: str
    description: str
    category: str
    stages: tuple[tuple[str, ...], ...]       # one Nmap argument tuple per process
    risk: str                                 # Low | Moderate | Elevated
    duration: str                             # label, see profiles.DURATIONS
    needs_root: bool
    notes: str = ""
    warnings: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()             # explicit NSE names embedded in args
    allow_labels: frozenset = frozenset()     # banned labels explicitly allowed (opt-in)
    opt_in: str = ""                          # non-empty: needs typed confirmation, text shown
    custom: str = ""                          # '' | ports | args
    number: int = 0                           # menu number, assigned by the catalog


# ----------------------------------------------------------------- tasks
@dataclass
class ScanTask:
    task_id: int
    kind: str                                 # profile | nse
    profile_id: str
    label: str
    args: list[str]
    targets: list[str]
    exclude: list[str] = field(default_factory=list)
    stage: int = 1
    stages: int = 1
    chunk: int = 1
    chunks: int = 1
    family: str = "ipv4"
    timing: int = 3
    extra_flags: list[str] = field(default_factory=list)
    nse_ids: list[str] = field(default_factory=list)
    lock_keys: list[str] = field(default_factory=list)
    needs_root: bool = False
    root_reasons: list[str] = field(default_factory=list)
    risk: str = "Low"
    duration: str = ""
    warnings: list[str] = field(default_factory=list)
    confirm_note: str = ""
    status: str = PENDING
    skip_reason: str = ""
    error: str = ""
    command: list[str] = field(default_factory=list)
    task_dir: str = ""
    started: str | None = None
    finished: str | None = None
    duration_s: float | None = None
    exit_code: int | None = None
    xml_sha256: str = ""
    xml_complete: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanTask":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})


# --------------------------------------------------------- parsed results
@dataclass
class ScriptResult:
    id: str
    output: str


@dataclass
class PortResult:
    number: int
    protocol: str
    state: str
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    method: str = ""
    cpes: list[str] = field(default_factory=list)
    scripts: list[ScriptResult] = field(default_factory=list)


@dataclass
class OsMatch:
    name: str
    accuracy: str = ""
    classes: list[str] = field(default_factory=list)   # "type / vendor / family gen"
    cpes: list[str] = field(default_factory=list)


@dataclass
class TraceHop:
    ttl: str
    address: str
    rtt: str = ""
    host: str = ""


@dataclass
class HostResult:
    address: str
    addrtype: str = "ipv4"
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    state: str = "unknown"
    reason: str = ""
    ports: list[PortResult] = field(default_factory=list)
    extraports: list[str] = field(default_factory=list)   # e.g. "992 closed (resets)"
    os_matches: list[OsMatch] = field(default_factory=list)
    host_scripts: list[ScriptResult] = field(default_factory=list)
    trace: list[TraceHop] = field(default_factory=list)
    distance: str = ""
    uptime_s: str = ""


@dataclass
class ParsedScan:
    path: str = ""
    nmap_args: str = ""
    nmap_version: str = ""
    start: str = ""            # epoch seconds as text
    start_str: str = ""
    end_str: str = ""
    elapsed: float | None = None
    summary: str = ""
    exit_status: str = ""
    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0
    scaninfo: list[str] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    complete: bool = False     # runstats/finished present in the XML
    repaired: bool = False     # XML was truncated; parsed from a repaired in-memory copy
    errors: list[str] = field(default_factory=list)

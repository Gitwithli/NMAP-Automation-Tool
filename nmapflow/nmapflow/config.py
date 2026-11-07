"""Settings: load, validate, save. Stored as JSON next to the launcher."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .utils import atomic_write_json

MAX_CONCURRENCY = 8
PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_DIR / "config.json"


@dataclass
class Config:
    timing: int = 3                       # Nmap -T template, 1..5
    concurrency: int = 1                  # parallel Nmap processes (different hosts only)
    output_dir: str = "reports"           # relative paths are relative to the project folder
    timeout_minutes: int = 240            # per-scan wall-clock limit, 0 = none
    default_profiles: list[str] = field(default_factory=list)   # profile IDs
    default_nse: list[str] = field(default_factory=list)        # NSE entry IDs
    host_discovery: bool = True           # False adds -Pn
    resolve_dns: bool = False             # False adds -n
    hosts_per_task: int = 0               # 0 = automatic (see planner)
    prefer_ipv6: bool = False
    nse_category_udp_top_ports: int = 0   # 0 = category tasks scan TCP only
    nmap_path: str = ""                   # empty = search PATH

    def output_path(self) -> Path:
        p = Path(self.output_dir).expanduser()
        return p if p.is_absolute() else PROJECT_DIR / p


def _coerce(name: str, value: Any, default: Any) -> tuple[Any, str | None]:
    """Return (valid_value, error_message_or_None) for one setting."""
    try:
        if name == "timing":
            v = int(value)
            if not 1 <= v <= 5:
                raise ValueError("timing must be 1-5")
        elif name == "concurrency":
            v = int(value)
            if not 1 <= v <= MAX_CONCURRENCY:
                raise ValueError(f"concurrency must be 1-{MAX_CONCURRENCY}")
        elif name == "timeout_minutes":
            v = int(value)
            if not 0 <= v <= 10080:
                raise ValueError("timeout_minutes must be 0-10080")
        elif name == "hosts_per_task":
            v = int(value)
            if not 0 <= v <= 4096:
                raise ValueError("hosts_per_task must be 0-4096")
        elif name == "nse_category_udp_top_ports":
            v = int(value)
            if not 0 <= v <= 1000:
                raise ValueError("nse_category_udp_top_ports must be 0-1000")
        elif name in ("host_discovery", "resolve_dns", "prefer_ipv6"):
            if not isinstance(value, bool):
                raise ValueError("must be true or false")
            v = value
        elif name in ("output_dir", "nmap_path"):
            if not isinstance(value, str):
                raise ValueError("must be text")
            v = value.strip()
            if name == "output_dir" and not v:
                raise ValueError("must not be empty")
        elif name in ("default_profiles", "default_nse"):
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError("must be a list of IDs")
            v = value
        else:
            return default, f"unknown setting '{name}' ignored"
        return v, None
    except (TypeError, ValueError) as exc:
        return default, f"{name}: {exc}; using default {default!r}"


def validate(data: dict[str, Any]) -> tuple[Config, list[str]]:
    """Build a Config from a dict, replacing invalid entries with defaults."""
    base = Config()
    problems: list[str] = []
    known = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key not in known:
            problems.append(f"unknown setting '{key}' ignored")
            continue
        v, err = _coerce(key, value, getattr(base, key))
        if err:
            problems.append(err)
        setattr(base, key, v)
    return base, problems


def load(path: Path | None = None) -> tuple[Config, list[str]]:
    """Load settings; a missing file gives defaults, a broken file gives defaults + a message."""
    path = path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return Config(), []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("top level must be a JSON object")
    except (OSError, ValueError) as exc:
        return Config(), [f"could not read {path}: {exc}; using defaults"]
    return validate(data)


def save(cfg: Config, path: Path | None = None) -> Path:
    path = path or DEFAULT_CONFIG_PATH
    atomic_write_json(path, asdict(cfg))
    return path

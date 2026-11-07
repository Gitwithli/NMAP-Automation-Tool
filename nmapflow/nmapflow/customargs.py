"""Validation of user-supplied Nmap arguments and port specifications.

User text is split with shlex (no shell is involved anywhere) and then checked against an
ALLOW-LIST. Anything not on the list is rejected with a reason. Targets, output files,
timing and NSE scripts are controlled by the tool itself and cannot be set here.
"""

from __future__ import annotations

import re
import shlex

MAX_RATE_CAP = 1000

# flag -> hazard text, used to give a helpful message instead of a generic one
_DENIED = {
    "-oX": "output files are managed by the tool", "-oN": "output files are managed by the tool",
    "-oG": "output files are managed by the tool", "-oA": "output files are managed by the tool",
    "-oS": "output files are managed by the tool", "--append-output": "output files are managed by the tool",
    "-iL": "targets are chosen in the target menu", "-iR": "random target scanning is not allowed",
    "--excludefile": "exclusions are chosen in the target menu", "--exclude": "exclusions are chosen in the target menu",
    "--script": "select scripts in the NSE menu", "--script-args": "script arguments are not supported",
    "--script-args-file": "script arguments are not supported",
    "--datadir": "changing Nmap's data directory is not allowed", "--resume": "resume is not supported",
    "--interactive": "interactive mode is not allowed", "--stylesheet": "output is managed by the tool",
    "-D": "decoy/spoofing options are not supported", "-S": "source spoofing is not supported",
    "--spoof-mac": "spoofing is not supported", "-f": "packet fragmentation/evasion is not supported",
    "--mtu": "packet fragmentation/evasion is not supported", "--badsum": "crafted bad checksums are not supported",
    "-sI": "idle scan is not supported", "-b": "FTP bounce scan is not supported",
    "--min-rate": "forcing a minimum packet rate can overwhelm targets", "--min-parallelism": "not supported",
    "--send-eth": "not supported", "--send-ip": "not supported", "--proxies": "not supported",
    "--data": "custom payloads are not supported", "--data-string": "custom payloads are not supported",
    "--data-length": "custom payloads are not supported", "--ip-options": "not supported",
    "--ttl": "not supported", "-e": "interface selection is not supported", "--privileged": "not supported",
    "--unprivileged": "not supported", "-6": "IPv6 is selected automatically from the targets",
    "-oM": "output files are managed by the tool",
}

_NO_VALUE = {
    "-sS", "-sT", "-sA", "-sW", "-sN", "-sF", "-sX", "-sU", "-sV", "-sC", "-sn", "-sL", "-O", "-A",
    "-F", "-r", "-Pn", "-PE", "-PP", "-PM", "-PR", "--open", "--reason", "--traceroute",
    "--osscan-guess", "--osscan-limit", "--version-light", "--version-all", "-p-",
    "--allports", "--defeat-rst-ratelimit",
}
_VALUE_FLAGS = {
    "-p": "ports", "--top-ports": "int:1:65535", "--version-intensity": "int:0:9",
    "--max-retries": "int:0:10", "--host-timeout": "duration", "--scan-delay": "duration",
    "--max-rate": f"int:1:{MAX_RATE_CAP}",
}
_ATTACHED_PING = ("-PS", "-PA", "-PU")   # -PS22,80,443 etc. (value glued to the flag)

_PORT_ITEM = r"(?:[TUS]:)?(?:\d{1,5}(?:-\d{1,5})?|-)"
_PORT_RE = re.compile(rf"^{_PORT_ITEM}(?:,(?:[TUS]:)?\d{{1,5}}(?:-\d{{1,5}})?)*$")
_DURATION_RE = re.compile(r"^\d{1,6}(?:ms|s|m|h)?$")


class ArgError(ValueError):
    """Raised with a user-facing explanation when arguments are rejected."""


def valid_port_spec(spec: str) -> bool:
    """True for specs such as 80, 1-1023, 22,80,443, T:80,U:53, or '-' (all ports)."""
    if not spec or len(spec) > 400 or not _PORT_RE.match(spec):
        return False
    for item in spec.split(","):
        item = item.split(":", 1)[-1]
        if item == "-":
            continue
        parts = item.split("-")
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return False
        if any(n < 0 or n > 65535 for n in nums):
            return False
        if len(nums) == 2 and nums[0] > nums[1]:
            return False
    return True


def _check_value(flag: str, rule: str, value: str) -> None:
    if rule == "ports":
        if not valid_port_spec(value):
            raise ArgError(f"{flag}: '{value}' is not a valid port specification")
    elif rule.startswith("int:"):
        _, lo, hi = rule.split(":")
        if not value.isdigit() or not int(lo) <= int(value) <= int(hi):
            raise ArgError(f"{flag}: value must be a whole number from {lo} to {hi}")
    elif rule == "duration":
        if not _DURATION_RE.match(value):
            raise ArgError(f"{flag}: '{value}' is not a valid time (examples: 30s, 10m, 2h)")


def validate_custom_args(text: str) -> list[str]:
    """Return a safe argument list or raise ArgError. The list never contains targets."""
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ArgError(f"could not read the arguments: {exc}") from exc
    if not tokens:
        raise ArgError("no arguments entered")
    if len(tokens) > 40:
        raise ArgError("too many arguments (limit 40)")
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        flag, eq, attached = tok.partition("=") if tok.startswith("--") else (tok, "", "")
        if tok.startswith("-T") and len(tok) == 3 and tok[2].isdigit():
            raise ArgError("timing (-T) is chosen in the timing menu")
        if tok in _NO_VALUE:
            out.append(tok)
        elif flag in _VALUE_FLAGS:
            rule = _VALUE_FLAGS[flag]
            if eq:
                value = attached
            else:
                i += 1
                if i >= len(tokens):
                    raise ArgError(f"{flag} needs a value")
                value = tokens[i]
            _check_value(flag, rule, value)
            out.extend([flag, value])
        elif tok.startswith("-p") and len(tok) > 2 and not tok.startswith("--"):
            value = tok[2:]
            _check_value("-p", "ports", value)
            out.extend(["-p", value])
        elif tok.startswith(_ATTACHED_PING) and len(tok) > 3:
            if not valid_port_spec(tok[3:]) or tok[3:] == "-":
                raise ArgError(f"{tok[:3]}: invalid port list '{tok[3:]}'")
            out.append(tok)
        elif tok in _DENIED or flag in _DENIED:
            hazard = _DENIED.get(tok) or _DENIED.get(flag)
            raise ArgError(f"'{tok}' is not allowed: {hazard}")
        elif not tok.startswith("-"):
            raise ArgError(f"'{tok}' looks like a target; targets are chosen in the target menu")
        else:
            raise ArgError(f"'{tok}' is not on the list of allowed options")
        i += 1
    return out

"""Detect local network interfaces and IPv4 subnets. Detection never scans anything."""

from __future__ import annotations

import ipaddress
import json
import shutil
import socket
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class LocalSubnet:
    interface: str
    address: str
    network: str        # CIDR of the subnet
    note: str = ""


def _from_ip_json(text: str) -> list[LocalSubnet]:
    out: list[LocalSubnet] = []
    for iface in json.loads(text):
        name = iface.get("ifname", "?")
        flags = iface.get("flags", [])
        if name == "lo" or "LOOPBACK" in flags:
            continue
        if iface.get("operstate") == "DOWN" or ("UP" not in flags and "LOWER_UP" not in flags):
            continue
        for info in iface.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            addr, plen = info.get("local"), info.get("prefixlen")
            if addr is None or plen is None:
                continue
            try:
                net = ipaddress.ip_network(f"{addr}/{plen}", strict=False)
            except ValueError:
                continue
            note = "link-local" if net.is_link_local else ""
            out.append(LocalSubnet(name, addr, str(net), note))
    return out


def detect_subnets() -> tuple[list[LocalSubnet], str]:
    """Return (subnets, message). The message explains an empty or approximate result."""
    ip_bin = shutil.which("ip")
    if ip_bin:
        try:
            proc = subprocess.run([ip_bin, "-j", "-4", "addr", "show"], capture_output=True,
                                  text=True, timeout=10, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                subnets = _from_ip_json(proc.stdout)
                return subnets, ("" if subnets else "No active IPv4 interfaces were found.")
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            msg = f"'ip' failed ({exc}); trying a fallback."
        else:
            msg = "'ip -j' gave no usable output; trying a fallback."
    else:
        msg = "The 'ip' command was not found (install iproute2); trying a fallback."

    # Fallback: ask the OS which local address would be used for outbound traffic.
    # A UDP connect() sends no packets.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            addr = s.getsockname()[0]
        net = ipaddress.ip_network(f"{addr}/24", strict=False)
        return [LocalSubnet("(unknown)", addr, str(net),
                            "guessed as /24; verify before scanning")], msg
    except OSError:
        return [], msg + " No local address could be determined; enter a CIDR manually."

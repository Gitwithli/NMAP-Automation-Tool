"""Privilege analysis: which Nmap options need raw sockets (root)?"""

from __future__ import annotations

import os
from typing import Sequence

# Option -> reason. These need raw-socket access on Linux.
_ROOT_EXACT = {
    "-sS": "SYN scan (-sS) sends raw packets",
    "-sA": "ACK scan (-sA) sends raw packets",
    "-sW": "window scan (-sW) sends raw packets",
    "-sN": "Null scan (-sN) sends raw packets",
    "-sF": "FIN scan (-sF) sends raw packets",
    "-sX": "Xmas scan (-sX) sends raw packets",
    "-sU": "UDP scan (-sU) needs raw access to read ICMP replies",
    "-O": "OS detection (-O) sends crafted raw packets",
    "-A": "-A includes OS detection (-O) and traceroute",
    "--traceroute": "traceroute (--traceroute) sends raw packets",
    "-PE": "ICMP echo ping (-PE) needs raw sockets",
    "-PP": "ICMP timestamp ping (-PP) needs raw sockets",
    "-PM": "ICMP netmask ping (-PM) needs raw sockets",
    "-PR": "ARP ping (-PR) needs raw sockets",
}
_ROOT_PREFIX = {
    "-PA": "TCP ACK ping (-PA) needs raw sockets",
    "-PU": "UDP ping (-PU) needs raw sockets",
}


def is_privileged() -> bool | None:
    """True when running as root, False when not, None when it cannot be determined
    (non-POSIX platforms)."""
    if os.name == "posix" and hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return None


def root_reasons(args: Sequence[str]) -> list[str]:
    """Human-readable reasons why these Nmap arguments need root (empty list = none)."""
    reasons: list[str] = []
    for a in args:
        r = _ROOT_EXACT.get(a)
        if r is None:
            for pre, text in _ROOT_PREFIX.items():
                if a.startswith(pre):
                    r = text
                    break
        if r and r not in reasons:
            reasons.append(r)
    return reasons


def explain() -> str:
    return ("SYN, ACK, UDP, Null/FIN/Xmas scans, OS detection (-O), traceroute and ARP/ICMP "
            "host discovery need raw sockets. On Linux run the tool with 'sudo python3 nmapflow.py'. "
            "TCP connect scans (-sT), version detection over connect scans and NSE scripts "
            "work without root.")

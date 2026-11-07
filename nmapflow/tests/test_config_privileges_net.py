import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nmapflow import config as C
from nmapflow import netdetect, privileges


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_defaults_match_documentation(self):
        c = C.Config()
        self.assertEqual((c.timing, c.concurrency, c.output_dir, c.timeout_minutes), (3, 1, "reports", 240))
        self.assertEqual((c.host_discovery, c.resolve_dns, c.hosts_per_task, c.prefer_ipv6), (True, False, 0, False))
        self.assertEqual((c.default_profiles, c.default_nse, c.nse_category_udp_top_ports, c.nmap_path), ([], [], 0, ""))

    def test_missing_file_gives_defaults(self):
        cfg, problems = C.load(self.d / "nope.json")
        self.assertEqual(cfg, C.Config())
        self.assertEqual(problems, [])

    def test_roundtrip(self):
        p = self.d / "c.json"
        cfg = C.Config(timing=4, concurrency=3, timeout_minutes=0, host_discovery=False, resolve_dns=True,
                       default_profiles=["REQ-02-TCP-ALL-SYN"], default_nse=["cat-safe"])
        C.save(cfg, p)
        loaded, problems = C.load(p)
        self.assertEqual(problems, [])
        self.assertEqual(loaded, cfg)

    def test_invalid_values_fall_back_with_message(self):
        bad = {"timing": 9, "concurrency": 99, "timeout_minutes": -1, "hosts_per_task": "x", "host_discovery": "yes",
               "output_dir": "", "default_profiles": "REQ", "nse_category_udp_top_ports": 5000, "mystery": 1}
        cfg, problems = C.validate(bad)
        self.assertEqual(cfg, C.Config())
        self.assertEqual(len(problems), len(bad))

    def test_boundaries(self):
        cfg, problems = C.validate({"timing": 1, "concurrency": C.MAX_CONCURRENCY, "timeout_minutes": 10080})
        self.assertEqual(problems, [])
        self.assertEqual((cfg.timing, cfg.concurrency), (1, 8))
        _, problems = C.validate({"concurrency": 9})
        self.assertTrue(problems)

    def test_corrupt_json(self):
        p = self.d / "c.json"
        p.write_text("{not json")
        cfg, problems = C.load(p)
        self.assertEqual(cfg, C.Config())
        self.assertIn("could not read", problems[0])

    def test_non_object_json(self):
        p = self.d / "c.json"
        p.write_text("[1,2]")
        _, problems = C.load(p)
        self.assertTrue(problems)

    def test_output_path_relative_and_absolute(self):
        self.assertTrue(C.Config(output_dir="reports").output_path().is_absolute())
        self.assertEqual(C.Config(output_dir=str(self.d)).output_path(), self.d)

    def test_save_is_private(self):
        p = self.d / "c.json"
        C.save(C.Config(), p)
        if os.name == "posix":
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)


class PrivilegeTests(unittest.TestCase):
    def test_root_flags(self):
        for flag in ["-sS", "-sA", "-sW", "-sN", "-sF", "-sX", "-sU", "-O", "-A", "--traceroute", "-PE", "-PP", "-PM", "-PR", "-PA80", "-PU53"]:
            with self.subTest(flag=flag):
                self.assertTrue(privileges.root_reasons([flag]))

    def test_no_root_needed(self):
        for args in (["-sT"], ["-sT", "-sV"], ["-sT", "-sC", "--script", "http-title"], ["-sL"], ["-sn"], ["-Pn"], ["-sn", "-PS22,80,443"], ["-p", "80"]):
            with self.subTest(args=args):
                self.assertEqual(privileges.root_reasons(args), [])

    def test_reasons_are_unique_and_readable(self):
        r = privileges.root_reasons(["-sS", "-sS", "-O"])
        self.assertEqual(len(r), 2)
        self.assertTrue(all(isinstance(x, str) and x for x in r))

    def test_is_privileged_uses_euid(self):
        with mock.patch("os.geteuid", return_value=0):
            self.assertTrue(privileges.is_privileged())
        with mock.patch("os.geteuid", return_value=1000):
            self.assertFalse(privileges.is_privileged())

    def test_unknown_platform(self):
        with mock.patch.object(privileges.os, "name", "nt"):
            self.assertIsNone(privileges.is_privileged())

    def test_explain_mentions_sudo(self):
        self.assertIn("sudo", privileges.explain())


IP_JSON = json.dumps([
    {"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "192.168.10.23", "prefixlen": 24},
                   {"family": "inet", "local": "10.9.8.7", "prefixlen": 16}]},
    {"ifname": "wlan0", "flags": ["BROADCAST", "MULTICAST"], "operstate": "DOWN",
     "addr_info": [{"family": "inet", "local": "172.16.0.5", "prefixlen": 24}]},
    {"ifname": "tun0", "flags": ["POINTOPOINT", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
     "addr_info": [{"family": "inet", "local": "169.254.3.4", "prefixlen": 16}, {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]},
    {"ifname": "br0", "flags": ["UP"], "operstate": "UP", "addr_info": []},
])


class NetDetectTests(unittest.TestCase):
    def run_with(self, stdout, rc=0, which="/usr/sbin/ip"):
        proc = subprocess.CompletedProcess([], rc, stdout, "")
        with mock.patch.object(netdetect.shutil, "which", return_value=which), \
                mock.patch.object(netdetect.subprocess, "run", return_value=proc) as run:
            return netdetect.detect_subnets(), run

    def test_parses_ip_json_and_skips_loopback_and_down(self):
        (subnets, msg), run = self.run_with(IP_JSON)
        nets = {(s.interface, s.network) for s in subnets}
        self.assertEqual(nets, {("eth0", "192.168.10.0/24"), ("eth0", "10.9.0.0/16"), ("tun0", "169.254.0.0/16")})
        self.assertEqual(msg, "")
        self.assertTrue(any(s.note == "link-local" for s in subnets))
        args = run.call_args[0][0]
        self.assertIsInstance(args, list)
        self.assertNotIn("shell", run.call_args[1])

    def test_no_interfaces_message(self):
        (subnets, msg), _ = self.run_with("[]")
        self.assertEqual(subnets, [])
        self.assertIn("No active", msg)

    def test_fallback_when_ip_missing(self):
        class FakeSock:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def connect(s, addr): pass
            def getsockname(s): return ("192.168.50.7", 40000)
        with mock.patch.object(netdetect.shutil, "which", return_value=None), \
                mock.patch.object(netdetect.socket, "socket", return_value=FakeSock()):
            subnets, msg = netdetect.detect_subnets()
        self.assertIn("iproute2", msg)
        self.assertEqual([s.network for s in subnets], ["192.168.50.0/24"])
        self.assertIn("guessed", subnets[0].note)

    def test_total_failure_is_explained(self):
        with mock.patch.object(netdetect.shutil, "which", return_value=None), \
                mock.patch.object(netdetect.socket, "socket", side_effect=OSError("no net")):
            subnets, msg = netdetect.detect_subnets()
        self.assertEqual(subnets, [])
        self.assertIn("manually", msg)

    def test_ip_command_failure_uses_fallback(self):
        with mock.patch.object(netdetect.shutil, "which", return_value="/bin/ip"), \
                mock.patch.object(netdetect.subprocess, "run", side_effect=OSError("boom")), \
                mock.patch.object(netdetect.socket, "socket", side_effect=OSError("no net")):
            subnets, msg = netdetect.detect_subnets()
        self.assertEqual(subnets, [])
        self.assertIn("failed", msg)


if __name__ == "__main__":
    unittest.main()

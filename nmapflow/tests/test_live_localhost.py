"""OPTIONAL live tests against THIS machine's loopback only.

Skipped unless NMAPFLOW_LIVE_TESTS=1 and a real nmap is installed:

    NMAPFLOW_LIVE_TESTS=1 python3 -m unittest tests.test_live_localhost -v

Every scan target in this file is 127.0.0.1 (checked by an assertion before each run).
"""

import http.server
import os
import shutil
import socket
import subprocess
import threading
import unittest

from nmapflow import nse as nse_mod
from nmapflow import profiles as P
from nmapflow.config import Config
from nmapflow.parser import parse_file
from nmapflow.privileges import root_reasons

from .helpers import LabTestCase, is_root

LIVE = os.environ.get("NMAPFLOW_LIVE_TESTS") == "1" and shutil.which("nmap")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@unittest.skipUnless(LIVE, "set NMAPFLOW_LIVE_TESTS=1 and install nmap to run the live localhost tests")
class LiveLocalhost(LabTestCase):
    def setUp(self):
        super().setUp()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def live(self):
        lab = self.lab()
        lab.nmap = shutil.which("nmap")
        lab.avail = nse_mod.load_availability(lab.nmap)
        return lab

    def loopback_only(self, plan):
        for t in plan.tasks:
            self.assertEqual(t.targets, ["127.0.0.1"], "live tests may only scan 127.0.0.1")

    def test_every_profile_is_accepted_by_the_real_nmap_option_parser(self):
        bad = []
        for p in P.catalog():
            if p.custom:
                continue
            for stage in p.stages:
                r = subprocess.run([shutil.which("nmap"), *stage, "-T3", "-n"], capture_output=True, text=True, timeout=60)
                text = r.stdout + r.stderr
                ok = "No targets were specified" in text or (not is_root() and root_reasons(stage) and "requires root" in text)
                if not ok:
                    bad.append((p.id, text.strip()[:120]))
        self.assertEqual(bad, [])

    def test_connect_scan_finds_the_local_web_server(self):
        lab = self.live()
        ts = lab.targets("127.0.0.1")
        profile = P.make_custom_ports("tcp", "-sT", str(self.port), ["-sV"])
        plan = lab.plan(ts, [profile])
        self.loopback_only(plan)
        session, ex = lab.run(plan, ts, Config(timeout_minutes=2))
        t = plan.tasks[0]
        self.assertEqual((t.status, t.error), ("completed", ""))
        parsed = parse_file(session.dir / t.task_dir / "scan.xml")
        self.assertTrue(parsed.complete)
        (host,) = parsed.hosts
        (port,) = host.ports
        self.assertEqual((port.number, port.state, port.service), (self.port, "open", "http"))

    def test_closed_port_is_reported_closed(self):
        lab = self.live()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        ts = lab.targets("127.0.0.1")
        plan = lab.plan(ts, [P.make_custom_ports("tcp", "-sT", str(closed), [])])
        session, _ = lab.run(plan, ts)
        parsed = parse_file(session.dir / plan.tasks[0].task_dir / "scan.xml")
        self.assertEqual([p.state for p in parsed.hosts[0].ports], ["closed"])

    def test_nse_task_runs_on_its_own(self):
        try:
            web = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), QuietHandler)
        except OSError:
            self.skipTest("port 8080 is busy")
        threading.Thread(target=web.serve_forever, daemon=True).start()
        self.addCleanup(web.server_close)
        self.addCleanup(web.shutdown)
        lab = self.live()
        ts = lab.targets("127.0.0.1")
        plan = lab.plan(ts, [], self.sel("http-title", "http-headers"))
        self.loopback_only(plan)
        session, _ = lab.run(plan, ts)
        t = plan.tasks[0]
        self.assertEqual(t.status, "completed", t.error)
        parsed = parse_file(session.dir / t.task_dir / "scan.xml")
        scripts = {s.id for h in parsed.hosts for p in h.ports for s in p.scripts}
        self.assertIn("http-title", scripts)

    def test_real_timeout_keeps_partial_output(self):
        lab = self.live()
        ts = lab.targets("127.0.0.1")
        plan = lab.plan(ts, [P.make_custom_args("-sT -p 1-200")], timing=1)       # T1 waits between probes: very slow
        self.loopback_only(plan)
        session, _ = lab.run(plan, ts, Config(timeout_minutes=0.1))
        t = plan.tasks[0]
        self.assertEqual(t.status, "timed_out")
        self.assertTrue((session.dir / t.task_dir / "scan.xml").exists())
        self.assertFalse(t.xml_complete)

    @unittest.skipUnless(is_root(), "SYN scan needs root")
    def test_syn_scan_with_os_detection_as_root(self):
        lab = self.live()
        ts = lab.targets("127.0.0.1")
        plan = lab.plan(ts, [P.make_custom_ports("tcp", "-sS", f"{self.port}", ["-sV"])])
        session, _ = lab.run(plan, ts)
        self.assertEqual(plan.tasks[0].status, "completed")


if __name__ == "__main__":
    unittest.main()

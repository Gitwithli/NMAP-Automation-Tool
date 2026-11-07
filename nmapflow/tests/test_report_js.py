"""Optional: drives the generated HTML report in jsdom (sorting, filtering, expand/collapse, print).

Needs Node.js plus the jsdom package. Skipped otherwise.
    mkdir -p /tmp/jsd && (cd /tmp/jsd && npm install jsdom)
    NMAPFLOW_JSDOM=/tmp/jsd/node_modules python3 -m unittest tests.test_report_js -v
"""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from nmapflow.report_html import write_report

from .helpers import LabTestCase

NODE = shutil.which("node")
JSDOM = os.environ.get("NMAPFLOW_JSDOM", "")
SCRIPT = Path(__file__).parent / "js" / "report_behaviour.js"


@unittest.skipUnless(NODE and JSDOM and (Path(JSDOM) / "jsdom").is_dir(), "set NMAPFLOW_JSDOM=<path to node_modules containing jsdom>")
class ReportJavaScript(LabTestCase):
    def test_behaviour_in_jsdom(self):
        lab = self.lab("vuln")
        ts = lab.targets("10.0.0.5", "10.0.0.6", "10.0.0.7")
        plan = lab.plan(ts, [self.profile("REQ-02-TCP-ALL-SYN"), self.profile("REQ-07-TCP-TOP1000-SYN-SV-OS")], self.sel("http-title"), concurrency=3)
        session, _ = lab.run(plan, ts)
        report = write_report(session)
        proc = subprocess.run([NODE, str(SCRIPT), str(report)], capture_output=True, text=True, timeout=120,
                              env={**os.environ, "NODE_PATH": JSDOM})
        self.assertTrue(proc.stdout.strip(), proc.stderr[:500])
        result = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(result["failed"], [], result)
        self.assertGreaterEqual(result["total"], 20)

    def test_script_has_valid_syntax(self):
        from nmapflow.report_html import JS
        p = self.tmp / "r.js"
        p.write_text(JS)
        proc = subprocess.run([NODE, "--check", str(p)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()

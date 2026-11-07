import re
import unittest
from html.parser import HTMLParser

from nmapflow import aggregate
from nmapflow import report_html as H
from nmapflow.aggregate import classify
from nmapflow.config import Config
from nmapflow.models import CANCELLED, COMPLETED, FAILED, SKIPPED, TIMED_OUT
from nmapflow.report_html import render, write_report
from nmapflow.session import Session

from .helpers import LabTestCase, make_fake_nmap

SYN, CONNECT, ACK = "REQ-02-TCP-ALL-SYN", "REQ-09-TCP-ALL-CONNECT", "REQ-01-TCP-ALL-ACK"


class Balanced(HTMLParser):
    VOID = {"meta", "br", "input", "link", "img", "hr"}

    def __init__(self):
        super().__init__()
        self.stack, self.errors, self.scripts = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append((tag, self.stack[-3:]))
        else:
            self.stack.pop()


def check_html(testcase, html):
    p = Balanced()
    p.feed(html)
    testcase.assertEqual(p.errors, [])
    testcase.assertEqual(p.stack, [])
    return p


class ClassifyFindings(unittest.TestCase):
    def test_only_explicit_states_count(self):
        self.assertEqual(classify("x", "State: VULNERABLE\n IDs: CVE:CVE-2014-0160"), ("Reported vulnerable", ["CVE-2014-0160"]))
        self.assertEqual(classify("x", "State: LIKELY VULNERABLE")[0], "Likely vulnerable")
        self.assertIsNone(classify("x", "NOT VULNERABLE: patched"))
        self.assertIsNone(classify("ssl-cert", "Subject: CVE-2020-1234 mentioned in a banner"))
        self.assertIsNone(classify("http-title", "Welcome"))
        self.assertIsNone(classify("x", "vulnerable"))                       # lower case is not Nmap's state wording

    def test_mixed_output_keeps_the_vulnerable_state(self):
        self.assertEqual(classify("x", "NOT VULNERABLE: a\nVULNERABLE: b")[0], "Reported vulnerable")

    def test_vulners_candidates_are_labelled_as_unverified(self):
        label, cves = classify("vulners", "cpe:/a:x:1\n CVE-2021-1111 7.5\n CVE-2020-2222 5.0")
        self.assertIn("unverified", label)
        self.assertEqual(cves, ["CVE-2020-2222", "CVE-2021-1111"])
        self.assertIsNone(classify("vulners", "no results"))


class MixedOutcomeReport(LabTestCase):
    """One session containing every kind of result, built from real (fake-nmap) processes."""

    def setUp(self):
        super().setUp()
        from unittest import mock
        from nmapflow import runner as R
        lab = self.lab("vuln")
        self.lab_ = lab
        ts = lab.targets("10.0.0.5")
        sel = self.sel("http-title", "ssl-heartbleed")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT), self.profile(ACK), self.profile("REQ-01-TCP-ALL-ACK") if False else self.profile("REQ-06-TCP-TOP1000-SYN-SV")], sel)
        self.plan = plan
        # 1 completes, 2 is removed at plan review, 3 fails, 4 times out, 5 (NSE, vuln mode) completes
        plan.tasks[1].status, plan.tasks[1].skip_reason = SKIPPED, "removed by user at plan review"
        fail_nmap, _ = make_fake_nmap(lab.root / "bin_fail", "fail")
        slow_nmap, _ = make_fake_nmap(lab.root / "bin_slow", "ok", delay=30)
        real = R.build_command
        mapping = {3: fail_nmap, 4: slow_nmap}

        def pick(nmap_bin, task, x, n):
            return real(mapping.get(task.task_id, lab.nmap), task, x, n)

        s, ex = lab.executor(plan, ts, Config(timeout_minutes=0.04))
        with mock.patch.object(R, "build_command", side_effect=pick):
            ex.run()
        self.session = s
        self.html = write_report(s).read_text()

    def test_statuses_cover_every_requested_scan(self):
        self.assertEqual([t.status for t in self.plan.tasks], [COMPLETED, SKIPPED, FAILED, TIMED_OUT, COMPLETED])

    def test_html_is_well_formed_and_self_contained(self):
        p = check_html(self, self.html)
        self.assertEqual(p.scripts, 1)
        self.assertEqual(re.findall(r'(?:src|href)="https?://', self.html), [])
        self.assertNotIn("<link", self.html)
        self.assertNotIn("@import", self.html)
        self.assertNotIn("url(http", self.html)
        self.assertIn("Content-Security-Policy", self.html)
        import html as _h
        self.assertIn("default-src 'none'", _h.unescape(self.html))

    def test_every_scan_is_listed_with_its_status(self):
        for t in self.plan.tasks:
            self.assertIn(t.label, self.html)
        self.assertIn("s-skipped", self.html)
        self.assertIn("s-failed", self.html)
        self.assertIn("s-timed_out", self.html)
        self.assertIn("s-completed", self.html)
        self.assertIn("removed by user at plan review", self.html)

    def test_incomplete_report_is_announced(self):
        self.assertIn("This report is incomplete", self.html)
        self.assertIn("3 of 5 requested scans did not", self.html)
        self.assertNotIn("All requested scans completed", self.html)

    def test_failed_and_timed_out_details(self):
        self.assertIn("Failed to resolve", self.html)
        self.assertIn("minute limit", self.html)
        self.assertIn("Errors and incomplete scans", self.html)

    def test_partial_results_from_the_timed_out_scan_are_included(self):
        agg = aggregate.build(self.session)
        self.assertIn(4, agg.parsed)
        self.assertTrue(agg.parsed[4].repaired)
        self.assertFalse(agg.parsed[4].complete)
        self.assertTrue(any(o.task_id == 4 for o in agg.port_rows))
        self.assertIn("scan was probably interrupted", self.html)

    def test_findings_use_the_scripts_own_words(self):
        self.assertIn("Reported vulnerable", self.html)
        self.assertIn("CVE-2014-0160", self.html)
        self.assertIn("ssl-heartbleed", self.html)
        agg = aggregate.build(self.session)
        self.assertEqual(len(agg.findings), 1)                      # NOT VULNERABLE did not become a finding
        self.assertEqual(agg.findings[0].script, "ssl-heartbleed")
        self.assertEqual(agg.findings[0].task_id, 5)

    def test_no_invented_scores_or_security_claims(self):
        self.assertNotRegex(self.html, r"CVSS[: ]+\d")
        text = self.html.lower()
        self.assertIn("they do not show that any system is secure", text)       # the disclaimer is there
        text = text.replace("they do not show that any system is secure", "")
        for phrase in ("is secure", "are secure", "is safe", "no risk", "fully patched", "no vulnerabilities found", "all clear"):
            self.assertNotIn(phrase, text)

    def test_required_sections_and_toc(self):
        for sid in ("summary", "scope", "runs", "discovery", "ports", "versions", "os", "scripts", "findings", "hosts", "errors", "notes"):
            self.assertIn(f"id='{sid}'", self.html)
            self.assertIn(f"href='#{sid}'", self.html)
        for text in ("Executive summary", "Scope and authorization", "Scans executed", "Host discovery", "Open ports and services",
                     "Version detection", "OS detection", "NSE script results", "Vulnerability-related findings",
                     "Recommendations and limitations"):
            self.assertIn(text, self.html)

    def test_interactive_features_present(self):
        for needle in ("id='q'", "sortable", "filterable", "<details", "Expand all", "beforeprint", "@media print",
                       "prefers-color-scheme:dark", "@media (max-width:900px)", "viewport"):
            self.assertIn(needle if needle != "viewport" else "name='viewport'", self.html)

    def test_scope_and_authorization_are_recorded(self):
        self.assertIn("AUTHORIZED", self.html)
        self.assertIn("10.0.0.5", self.html)
        self.assertIn("Authorization", self.html)
        self.assertIn("Plan confirmed", self.html)

    def test_service_version_and_os_tables_have_data(self):
        self.assertIn("OpenSSH", self.html)
        self.assertIn("9.2p1", self.html)
        self.assertIn("nginx", self.html)
        self.assertIn("cpe:/a:openbsd:openssh:9.2p1", self.html)

    def test_report_is_rebuilt_identically_from_the_saved_session(self):
        reloaded = Session.load(self.session.dir)
        again = write_report(reloaded).read_text()
        strip = lambda h: re.sub(r"generated [^·]*·", "", h)
        self.assertEqual(strip(again), strip(self.html))


class OtherReportCases(LabTestCase):
    def test_hostile_scan_content_is_escaped(self):
        lab = self.lab("hostile")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [], self.sel("http-title"))
        s, _ = lab.run(plan, ts)
        html = write_report(s).read_text()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertEqual(html.count("<script"), 1)                   # only the report's own script
        check_html(self, html)

    def test_hostile_labels_errors_and_targets_are_escaped(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, _ = lab.run(plan, ts)
        t = plan.tasks[0]
        t.label = "<img src=x onerror=alert(1)>"
        t.error = "</td><script>alert(2)</script>"
        t.status = FAILED
        s.data["operator"] = "<b>root</b>"
        s.data["scope"]["originals"] = ["<svg onload=alert(3)>"]
        html = render(s, aggregate.build(s))
        for raw in ("<img src=x", "<script>alert(2)", "<svg onload", "<b>root</b>"):
            self.assertNotIn(raw, html)
        check_html(self, html)

    def test_control_characters_are_removed(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, _ = lab.run(plan, ts)
        plan.tasks[0].error = "bell\x07 nul\x00 esc\x1b[31m"
        plan.tasks[0].status = FAILED
        html = render(s, aggregate.build(s))
        for ch in ("\x07", "\x00", "\x1b"):
            self.assertNotIn(ch, html)

    def test_all_good_session_says_so(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, _ = lab.run(plan, ts)
        html = write_report(s).read_text()
        self.assertIn("All requested scans completed", html)
        self.assertNotIn("This report is incomplete", html)
        self.assertIn("No script in these scans reported a vulnerable state", html)
        self.assertIn("22/tcp", html)

    def test_cancelled_session_is_flagged(self):
        lab = self.lab("ok", delay=30)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        s, ex = lab.executor(plan, ts)
        import threading
        threading.Timer(0.8, ex.cancel_all.set).start()
        ex.run()
        html = write_report(s).read_text()
        self.assertIn("stopped by the user", html)
        self.assertIn("This report is incomplete", html)
        self.assertEqual({t.status for t in plan.tasks}, {CANCELLED})
        self.assertIn("cancelled by user before it started", html)
        self.assertEqual(len(lab.intervals()), 1)                    # the second scan never started

    def test_session_with_no_results_still_renders(self):
        lab = self.lab("noxml")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, _ = lab.run(plan, ts)
        html = write_report(s).read_text()
        check_html(self, html)
        self.assertIn("No ports were reported", html)
        self.assertIn("no XML", html)

    def test_session_where_every_task_was_skipped(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        plan.tasks[0].status, plan.tasks[0].skip_reason = SKIPPED, "needs root privileges; tool was not run as root"
        s, _ = lab.run(plan, ts)
        html = write_report(s).read_text()
        self.assertIn("needs root privileges", html)
        self.assertIn("1 of 1 requested scans did not", html)

    def test_large_scan_report_stays_reasonable(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.0/24")
        plan = lab.plan(ts, [self.profile(SYN)], concurrency=4)
        s, _ = lab.run(plan, ts, Config(concurrency=4))
        html = write_report(s).read_text()
        self.assertEqual(len(plan.tasks), 4)
        agg = aggregate.build(s)
        self.assertEqual(len(agg.hosts), 4)                          # the fake reports one host per task
        self.assertLess(len(html), 400_000)
        check_html(self, html)

    def test_host_details_expandable_and_per_host(self):
        lab = self.lab("vuln")
        ts = lab.targets("10.0.0.5", "10.0.0.6")
        plan = lab.plan(ts, [self.profile("REQ-07-TCP-TOP1000-SYN-SV-OS"), self.profile("OSINFO-TRACE-PING")], self.sel("http-title"))
        s, _ = lab.run(plan, ts)
        html = write_report(s).read_text()
        self.assertEqual(html.count('<details class="host">'), 2)
        self.assertIn("Linux 5.15", html)
        self.assertIn("Traceroute", html)

    def test_sort_and_filter_helpers_use_safe_dom_calls(self):
        self.assertNotIn("innerHTML", H.JS)
        self.assertNotIn("eval(", H.JS)
        self.assertNotIn("document.write", H.JS)
        self.assertNotIn("http", H.JS)


if __name__ == "__main__":
    unittest.main()

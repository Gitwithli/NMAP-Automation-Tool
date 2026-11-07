import json
import os
import stat
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from nmapflow import aggregate
from nmapflow import session as S
from nmapflow.config import Config
from nmapflow.models import COMPLETED, ScanTask, SKIPPED
from nmapflow.report_xml import write_xml
from nmapflow.session import Session, SessionError, list_sessions
from nmapflow.utils import sha256_file

from .helpers import LabTestCase, is_root

SYN, CONNECT = "REQ-02-TCP-ALL-SYN", "REQ-09-TCP-ALL-CONNECT"


class SessionBasics(LabTestCase):
    def test_folder_layout_and_privacy(self):
        s = Session.create(self.tmp / "reports")
        self.assertTrue(s.dir.is_dir())
        self.assertTrue((s.dir / "tasks").is_dir())
        self.assertRegex(s.id, r"^\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d$")
        if os.name == "posix":
            self.assertEqual(s.dir.stat().st_mode & 0o777, 0o700)
        self.assertTrue((s.dir / ".lock").exists())
        s.release()
        self.assertFalse((s.dir / ".lock").exists())
        s.release()                                                  # releasing twice is harmless

    def test_same_second_sessions_get_unique_folders(self):
        with mock.patch.object(S, "timestamp_dirname", return_value="2026-01-01_00-00-00"):
            a = Session.create(self.tmp / "reports")
            b = Session.create(self.tmp / "reports")
            c = Session.create(self.tmp / "reports")
        self.assertEqual([a.id, b.id, c.id], ["2026-01-01_00-00-00", "2026-01-01_00-00-00-2", "2026-01-01_00-00-00-3"])

    def test_task_dir_names_are_safe(self):
        s = Session.create(self.tmp / "reports")
        t = ScanTask(task_id=7, kind="profile", profile_id="x", label="../../etc/passwd; rm -rf / <script>", args=[], targets=[])
        d = s.task_dir(t)
        self.assertEqual(d.parent, s.dir / "tasks")
        self.assertTrue(d.name.startswith("007_"))
        self.assertNotIn("..", d.name)
        self.assertNotIn("/", d.name)

    def test_save_and_load_roundtrip(self):
        s = Session.create(self.tmp / "reports")
        s.tasks = [ScanTask(task_id=1, kind="profile", profile_id="p", label="L", args=["-sT"], targets=["10.0.0.1"], status=SKIPPED, skip_reason="why")]
        s.set_scope({"originals": ["10.0.0.1"], "targets": [], "exclusions": [], "warnings": []})
        s.save()
        loaded = Session.load(s.dir)
        self.assertEqual(loaded.id, s.id)
        self.assertEqual(loaded.tasks[0].to_dict(), s.tasks[0].to_dict())
        self.assertEqual(loaded.data["scope"]["originals"], ["10.0.0.1"])

    def test_load_rejects_bad_files(self):
        d = self.tmp / "x"
        d.mkdir()
        with self.assertRaises(SessionError):
            Session.load(d)                                          # no session.json
        (d / "session.json").write_text("{broken")
        with self.assertRaises(SessionError):
            Session.load(d)
        (d / "session.json").write_text(json.dumps({"format": "something-else"}))
        with self.assertRaises(SessionError):
            Session.load(d)
        (d / "session.json").write_text("[]")
        with self.assertRaises(SessionError):
            Session.load(d)

    def test_listing_newest_first_and_tolerates_junk(self):
        base = self.tmp / "reports"
        ids = []
        for name in ("2026-01-01_00-00-01", "2026-01-01_00-00-03", "2026-01-01_00-00-02"):
            with mock.patch.object(S, "timestamp_dirname", return_value=name):
                s = Session.create(base)
                s.save()
                ids.append(s.id)
        (base / "stray-folder").mkdir()
        (base / "a-file.txt").write_text("x")
        listing = list_sessions(base)
        names = [p.name for p, _ in listing]
        self.assertEqual(names[:3], ["stray-folder", "2026-01-01_00-00-03", "2026-01-01_00-00-02"][0:1] + ["2026-01-01_00-00-03", "2026-01-01_00-00-02"])
        self.assertIsNone(dict(listing)[base / "stray-folder"])
        self.assertNotIn("a-file.txt", names)
        self.assertEqual(list_sessions(self.tmp / "missing"), [])

    def test_confirmation_requirements(self):
        s = Session.create(self.tmp / "reports")
        with self.assertRaises(SessionError):
            s.require_confirmed("d")
        s.set_authorization("AUTHORIZED", "d")
        with self.assertRaises(SessionError):
            s.require_confirmed("d")
        s.set_plan_confirmation(2)
        s.require_confirmed("d")
        with self.assertRaises(SessionError):
            s.require_confirmed("other")
        self.assertEqual(s.data["authorization"]["typed"], "AUTHORIZED")
        self.assertIn("authorization", s.data["authorization"]["statement"].lower())


class SessionXml(LabTestCase):
    def run_two(self):
        lab = self.lab("vuln")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        plan.tasks[1].status, plan.tasks[1].skip_reason = SKIPPED, "removed by user at plan review"
        session, _ = lab.run(plan, ts)
        return lab, session, plan

    def test_structure_and_references(self):
        lab, session, plan = self.run_two()
        path = write_xml(session)
        root = ET.parse(path).getroot()
        self.assertEqual(root.tag, "nmapflow-session")
        self.assertEqual(root.get("format"), "nmapflow-session-xml")
        self.assertEqual(root.get("id"), session.id)
        self.assertNotEqual(root.tag, "nmaprun")                     # not native Nmap XML
        raw = path.read_text()
        self.assertIn("NOT native Nmap XML", raw)
        auth = root.find("authorization")
        self.assertEqual(auth.get("typed"), "AUTHORIZED")
        self.assertTrue(auth.get("timestamp"))
        self.assertEqual(root.find("scope/original-input").text, "10.0.0.5")
        self.assertEqual(root.find("scope/target").get("kind"), "ip")
        tasks = root.findall("tasks/task")
        self.assertEqual([t.get("status") for t in tasks], [COMPLETED, SKIPPED])
        self.assertEqual(tasks[1].find("skip-reason").text, "removed by user at plan review")
        self.assertIsNone(tasks[1].find("nmap-xml"))                 # nothing ran, nothing to reference

    def test_references_point_at_untouched_files_with_matching_hashes(self):
        lab, session, plan = self.run_two()
        root = ET.parse(write_xml(session)).getroot()
        t = root.find("tasks/task")
        ref = t.find("nmap-xml")
        target = session.dir / ref.get("href")
        self.assertTrue(target.is_file())
        self.assertEqual(ref.get("sha256"), sha256_file(target))
        self.assertEqual(ref.get("complete"), "true")
        for tag in ("nmap-output", "stdout-log", "stderr-log"):
            self.assertTrue((session.dir / t.find(tag).get("href")).is_file())
        self.assertEqual(t.find("command").text, " ".join(plan.tasks[0].command))
        self.assertEqual(t.get("exit_code"), "0")

    def test_writing_reports_never_changes_the_original_nmap_files(self):
        from nmapflow.report_html import write_report
        lab, session, plan = self.run_two()
        d = session.dir / plan.tasks[0].task_dir
        before = {n: (d / n).read_bytes() for n in ("scan.xml", "scan.nmap")}
        mtimes = {n: (d / n).stat().st_mtime_ns for n in before}
        for _ in range(3):
            write_xml(session)
            write_report(session)
        for n, data in before.items():
            self.assertEqual((d / n).read_bytes(), data)
            self.assertEqual((d / n).stat().st_mtime_ns, mtimes[n])

    def test_xml_is_well_formed_even_with_hostile_text(self):
        lab, session, plan = self.run_two()
        plan.tasks[0].error = "bad <tag> & \"quotes\" ]]> \x01-free"
        plan.tasks[0].label = "label <&>"
        ET.fromstring(write_xml(session).read_bytes())               # must parse

    def test_xml_for_a_session_with_no_scope(self):
        s = Session.create(self.tmp / "reports")
        root = ET.fromstring(write_xml(s).read_bytes())
        self.assertEqual(root.findall("tasks/task"), [])


class IntegrityVerification(LabTestCase):
    def finished(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, _ = lab.run(plan, ts)
        return session, plan.tasks[0]

    def test_untouched_files_verify(self):
        session, t = self.finished()
        self.assertEqual(aggregate.verify_integrity(session), {1: "verified"})

    def test_modification_is_detected(self):
        session, t = self.finished()
        f = session.dir / t.task_dir / "scan.xml"
        f.chmod(0o600)
        f.write_text(f.read_text().replace("open", "clsd", 1))
        self.assertEqual(aggregate.verify_integrity(session), {1: "MISMATCH"})

    def test_deletion_is_detected(self):
        session, t = self.finished()
        (session.dir / t.task_dir / "scan.xml").unlink()
        self.assertEqual(aggregate.verify_integrity(session), {1: "missing"})

    def test_tasks_without_xml_are_not_applicable(self):
        lab = self.lab("noxml")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, _ = lab.run(plan, ts)
        self.assertEqual(aggregate.verify_integrity(session), {1: "n/a"})

    def test_hash_survives_session_reload(self):
        session, t = self.finished()
        loaded = Session.load(session.dir)
        self.assertEqual(aggregate.verify_integrity(loaded), {1: "verified"})
        self.assertEqual(loaded.tasks[0].xml_sha256, t.xml_sha256)

    def test_report_warns_about_tampering(self):
        from nmapflow.report_html import write_report
        session, t = self.finished()
        f = session.dir / t.task_dir / "scan.xml"
        f.chmod(0o600)
        f.write_text(f.read_text() + "\n<!-- tampered -->")
        html = write_report(session).read_text()
        self.assertIn("Integrity warning", html)
        self.assertIn("MISMATCH", html)

    @unittest.skipIf(is_root(), "root bypasses file permissions")
    def test_read_only_originals_reject_writes_for_normal_users(self):
        session, t = self.finished()
        f = session.dir / t.task_dir / "scan.xml"
        self.assertEqual(stat.S_IMODE(f.stat().st_mode) & 0o222, 0)
        with self.assertRaises(PermissionError):
            f.write_text("x")
        with self.assertRaises(PermissionError):
            f.open("a")


if __name__ == "__main__":
    unittest.main()

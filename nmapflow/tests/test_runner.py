import json
import os
import signal
import stat
import subprocess
import threading
import time
import unittest
from unittest import mock

from nmapflow import runner as R
from nmapflow import profiles as P
from nmapflow.config import Config
from nmapflow.models import CANCELLED, COMPLETED, FAILED, SKIPPED, TIMED_OUT
from nmapflow.parser import parse_file
from nmapflow.session import SessionError
from nmapflow.utils import sha256_file, shell_display

from .helpers import LabTestCase, is_root, make_fake_nmap, max_concurrent, read_log

SYN = "REQ-02-TCP-ALL-SYN"
CONNECT = "REQ-09-TCP-ALL-CONNECT"


class SuccessfulRun(LabTestCase):
    def test_outputs_are_complete_and_preserved(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, ex = lab.run(plan, ts)
        (t,) = plan.tasks
        self.assertEqual((t.status, t.exit_code, t.error), (COMPLETED, 0, ""))
        d = session.dir / t.task_dir
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["command.txt", "meta.json", "scan.nmap", "scan.xml", "stderr.log", "stdout.log"])
        self.assertEqual(t.xml_sha256, sha256_file(d / "scan.xml"))
        self.assertTrue(t.xml_complete)
        self.assertEqual((d / "command.txt").read_text().strip(), shell_display(t.command))
        meta = json.loads((d / "meta.json").read_text())
        self.assertEqual(meta["status"], COMPLETED)
        self.assertEqual(meta["xml_sha256"], t.xml_sha256)
        self.assertEqual(session.data["interrupted"], False)
        self.assertIsNotNone(session.data["finished"])
        saved = json.loads((session.dir / "session.json").read_text())
        self.assertEqual([x["status"] for x in saved["tasks"]], [COMPLETED])

    def test_originals_are_read_only(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, _ = lab.run(plan, ts)
        d = session.dir / plan.tasks[0].task_dir
        for name in ("scan.xml", "scan.nmap"):
            mode = stat.S_IMODE((d / name).stat().st_mode)
            self.assertEqual(mode & 0o222, 0, f"{name} is writable ({oct(mode)})")

    @unittest.skipIf(is_root(), "root bypasses file permissions")
    def test_originals_cannot_be_overwritten_by_a_normal_user(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, _ = lab.run(plan, ts)
        with self.assertRaises(PermissionError):
            open(session.dir / plan.tasks[0].task_dir / "scan.xml", "w")

    def test_session_folder_permissions(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, _ = lab.run(plan, ts)
        if os.name == "posix":
            self.assertEqual(session.dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual((session.dir / "session.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((session.dir / plan.tasks[0].task_dir / "stdout.log").stat().st_mode & 0o777, 0o600)

    def test_multi_stage_profile_makes_two_processes_and_two_xml_files(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [P.by_number(4)])
        session, _ = lab.run(plan, ts)
        self.assertEqual([t.status for t in plan.tasks], [COMPLETED, COMPLETED])
        dirs = {t.task_dir for t in plan.tasks}
        self.assertEqual(len(dirs), 2)
        procs = lab.intervals()
        self.assertEqual(len(procs), 2)
        self.assertIn("-sS", procs[0][2])
        self.assertIn("-sU", procs[1][2])

    def test_progress_and_open_port_counting(self):
        lab = self.lab("progress")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        _, ex = lab.run(plan, ts)
        p = ex.progress[1]
        self.assertEqual(p.pct, 45.2)
        self.assertEqual(p.remaining, "0:00:21")
        self.assertEqual(p.open_ports, 2)
        self.assertIn("SYN Stealth Scan", p.phase)

    def test_stdout_and_stderr_are_logged(self):
        lab = self.lab("progress")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, _ = lab.run(plan, ts)
        log = (session.dir / plan.tasks[0].task_dir / "stdout.log").read_text()
        self.assertIn("Discovered open port 22/tcp", log)

    def test_exact_command_is_what_the_process_received(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5", "10.0.0.6")
        plan = lab.plan(ts, [self.profile(SYN)])
        lab.run(plan, ts)
        (proc,) = lab.intervals()
        self.assertEqual(proc[2], plan.tasks[0].command[1:])


class SafeSubprocessUse(LabTestCase):
    def test_popen_gets_a_list_and_no_shell(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        real = subprocess.Popen
        captured = {}

        def spy(*a, **kw):
            captured["args"], captured["kw"] = a, kw
            return real(*a, **kw)

        with mock.patch.object(R.subprocess, "Popen", side_effect=spy):
            lab.run(plan, ts)
        self.assertIsInstance(captured["args"][0], list)
        self.assertTrue(all(isinstance(x, str) for x in captured["args"][0]))
        self.assertFalse(captured["kw"].get("shell", False))
        self.assertEqual(captured["kw"]["stdin"], subprocess.DEVNULL)
        if os.name == "posix":
            self.assertTrue(captured["kw"].get("start_new_session"))

    def test_hostile_target_text_cannot_reach_popen(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5; touch /tmp/pwned", "$(touch /tmp/pwned)", "-oX", "10.0.0.6")
        self.assertEqual([t.normalized for t in ts.targets], ["10.0.0.6"])
        plan = lab.plan(ts, [self.profile(SYN)])
        lab.run(plan, ts)
        self.assertFalse(os.path.exists("/tmp/pwned"))
        self.assertEqual(plan.tasks[0].targets, ["10.0.0.6"])


class ConfirmationGate(LabTestCase):
    def prepare(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        return lab, ts, plan

    def test_refuses_without_authorization(self):
        lab, ts, plan = self.prepare()
        s, ex = lab.executor(plan, ts, confirm=False)
        with self.assertRaises(SessionError) as cm:
            ex.run()
        self.assertIn("authorized", str(cm.exception))
        self.assertEqual(lab.intervals(), [])
        self.assertEqual(plan.tasks[0].status, "pending")

    def test_refuses_without_plan_confirmation(self):
        lab, ts, plan = self.prepare()
        s, ex = lab.executor(plan, ts, confirm=False)
        s.set_authorization("AUTHORIZED", plan.targets_digest)
        with self.assertRaises(SessionError) as cm:
            ex.run()
        self.assertIn("confirmed", str(cm.exception))
        self.assertEqual(read_log(lab.log), [])

    def test_refuses_when_targets_changed_after_authorization(self):
        lab, ts, plan = self.prepare()
        s, ex = lab.executor(plan, ts)
        plan.targets_digest = "0" * 64              # plan no longer matches the authorized scope
        with self.assertRaises(SessionError) as cm:
            ex.run()
        self.assertIn("differ", str(cm.exception))
        self.assertEqual(read_log(lab.log), [])

    def test_wrong_typed_text_is_not_authorization(self):
        lab, ts, plan = self.prepare()
        s, ex = lab.executor(plan, ts, confirm=False)
        s.set_authorization("authorized", plan.targets_digest)
        s.set_plan_confirmation(1)
        with self.assertRaises(SessionError):
            ex.run()


class SkippedTasks(LabTestCase):
    def test_skipped_tasks_are_never_run_but_stay_in_the_session(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        plan.tasks[0].status, plan.tasks[0].skip_reason = SKIPPED, "removed by user at plan review"
        session, _ = lab.run(plan, ts)
        self.assertEqual([t.status for t in plan.tasks], [SKIPPED, COMPLETED])
        self.assertEqual(len(lab.intervals()), 1)
        saved = json.loads((session.dir / "session.json").read_text())
        self.assertEqual([t["status"] for t in saved["tasks"]], [SKIPPED, COMPLETED])
        self.assertEqual(saved["tasks"][0]["skip_reason"], "removed by user at plan review")
        self.assertFalse(plan.tasks[0].task_dir)


class FailureModes(LabTestCase):
    def one(self, mode, **cfg):
        lab = self.lab(mode)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        session, ex = lab.run(plan, ts, Config(**cfg) if cfg else None)
        return lab, session, plan.tasks[0]

    def test_nonzero_exit(self):
        _, session, t = self.one("fail")
        self.assertEqual((t.status, t.exit_code), (FAILED, 1))
        self.assertIn("Failed to resolve", t.error)
        self.assertNotIn("QUITTING", t.error)
        self.assertTrue((session.dir / t.task_dir / "stderr.log").read_text().strip())

    def test_exit_zero_but_no_xml(self):
        _, _, t = self.one("noxml")
        self.assertEqual(t.status, FAILED)
        self.assertIn("no XML", t.error)

    def test_malformed_xml_is_a_failure_not_a_crash(self):
        _, session, t = self.one("badxml")
        self.assertEqual(t.status, FAILED)
        self.assertIn("incomplete", t.error)
        self.assertFalse(t.xml_complete)
        self.assertTrue((session.dir / t.task_dir / "scan.xml").exists())           # evidence kept

    def test_truncated_xml_with_exit_zero_is_a_failure(self):
        _, session, t = self.one("truncated")
        self.assertEqual(t.status, FAILED)
        parsed = parse_file(session.dir / t.task_dir / "scan.xml")
        self.assertTrue(parsed.repaired)
        self.assertEqual(len(parsed.hosts), 1)                                      # partial results still readable

    def test_nonzero_exit_with_good_xml_is_a_failure_but_results_are_kept(self):
        _, session, t = self.one("nonzero_xml")
        self.assertEqual((t.status, t.exit_code), (FAILED, 3))
        self.assertTrue(parse_file(session.dir / t.task_dir / "scan.xml").complete)

    def test_failed_task_does_not_stop_the_others(self):
        lab = self.lab("fail")
        ok_nmap, _ = make_fake_nmap(lab.root / "bin2", "ok")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        # first task fails (fail-mode binary), second must still run: swap binaries per task
        s, ex = lab.executor(plan, ts)
        calls = []
        real = R.build_command

        def alternating(nmap_bin, task, x, n):
            calls.append(task.task_id)
            return real(lab.nmap if task.task_id == 1 else ok_nmap, task, x, n)

        with mock.patch.object(R, "build_command", side_effect=alternating):
            ex.run()
        self.assertEqual([t.status for t in plan.tasks], [FAILED, COMPLETED])

    def test_missing_nmap_binary(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        lab.run(plan, ts, nmap="/nonexistent/path/nmap")
        t = plan.tasks[0]
        self.assertEqual(t.status, FAILED)
        self.assertIn("could not start Nmap", t.error)
        self.assertIn("No such file", t.error)

    def test_nmap_not_executable_is_a_permission_failure(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        path = lab.root / "bin" / "not_exec"
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o644)
        if is_root():
            self.skipTest("root can execute anything that has an x bit; covered by the mocked test below")
        lab.run(plan, ts, nmap=str(path))
        self.assertEqual(plan.tasks[0].status, FAILED)
        self.assertIn("Permission denied", plan.tasks[0].error)

    def test_permission_error_from_popen(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        with mock.patch.object(R.subprocess, "Popen", side_effect=PermissionError(13, "Permission denied")):
            lab.run(plan, ts)
        self.assertEqual(plan.tasks[0].status, FAILED)
        self.assertIn("Permission denied", plan.tasks[0].error)
        self.assertEqual(plan.tasks[0].started is not None, True)

    def test_unexpected_internal_error_is_contained(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        real = R.parse_file
        calls = {"n": 0}

        def boom(path):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("parser exploded")
            return real(path)

        with mock.patch.object(R, "parse_file", side_effect=boom):
            lab.run(plan, ts)
        self.assertEqual(plan.tasks[0].status, FAILED)
        self.assertIn("internal error", plan.tasks[0].error)
        self.assertEqual(plan.tasks[1].status, COMPLETED)

    def test_existing_output_files_are_never_overwritten(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, ex = lab.executor(plan, ts)
        d = s.task_dir(plan.tasks[0])
        (d / "scan.xml").write_text("PRECIOUS ORIGINAL")
        ex.run()
        t = plan.tasks[0]
        self.assertEqual(t.status, FAILED)
        self.assertIn("never overwritten", t.error)
        self.assertEqual((d / "scan.xml").read_text(), "PRECIOUS ORIGINAL")
        self.assertEqual(lab.intervals(), [])                      # nmap was never started

    def test_existing_normal_output_also_protected(self):
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, ex = lab.executor(plan, ts)
        d = s.task_dir(plan.tasks[0])
        (d / "scan.nmap").write_text("KEEP")
        ex.run()
        self.assertEqual(plan.tasks[0].status, FAILED)
        self.assertEqual((d / "scan.nmap").read_text(), "KEEP")


class Timeouts(LabTestCase):
    def test_timeout_keeps_partial_results(self):
        lab = self.lab("ok", delay=30)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        t0 = time.time()
        session, _ = lab.run(plan, ts, Config(timeout_minutes=0.03))
        self.assertLess(time.time() - t0, 15)
        t = plan.tasks[0]
        self.assertEqual(t.status, TIMED_OUT)
        self.assertIn("minute limit", t.error)
        self.assertFalse(t.xml_complete)
        parsed = parse_file(session.dir / t.task_dir / "scan.xml")
        self.assertTrue(parsed.repaired)
        self.assertEqual(len(parsed.hosts), 1)
        self.assertEqual(len(t.xml_sha256), 64)

    def test_zero_means_no_timeout(self):
        lab = self.lab("ok", delay=1.0)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        lab.run(plan, ts, Config(timeout_minutes=0))
        self.assertEqual(plan.tasks[0].status, COMPLETED)

    def test_hung_process_is_killed(self):
        lab = self.lab("hang")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        with mock.patch.object(R, "_GRACE_INT", 0.4), mock.patch.object(R, "_GRACE_TERM", 0.4):
            t0 = time.time()
            lab.run(plan, ts, Config(timeout_minutes=0.02))
        self.assertLess(time.time() - t0, 12)
        self.assertEqual(plan.tasks[0].status, TIMED_OUT)
        pid = read_log(lab.log)[0]["pid"]
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0) if not _zombie(pid) else (_ for _ in ()).throw(ProcessLookupError())


def _zombie(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split(")")[-1].split()[0] == "Z"
    except OSError:
        return False


class Cancellation(LabTestCase):
    def test_cancel_all_event(self):
        lab = self.lab("ok", delay=30)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        s, ex = lab.executor(plan, ts)
        threading.Timer(0.8, ex.cancel_all.set).start()
        t0 = time.time()
        ex.run()
        self.assertLess(time.time() - t0, 12)
        self.assertEqual(plan.tasks[0].status, CANCELLED)
        self.assertIn("partial output kept", plan.tasks[0].error)
        self.assertEqual(plan.tasks[1].status, CANCELLED)          # never started, still recorded
        self.assertEqual(len(lab.intervals()), 1)

    def interrupt_soon(self, delay=0.8):
        timer = threading.Timer(delay, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.start()
        self.addCleanup(timer.cancel)

    def test_ctrl_c_stop_keeps_partial_results_and_marks_everything(self):
        lab = self.lab("ok", delay=30)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT), self.profile("REQ-01-TCP-ALL-ACK")])
        asked = []
        s, ex = lab.executor(plan, ts, ask_cancel=lambda running: asked.append([t.task_id for t in running]) or "stop")
        self.interrupt_soon()
        ex.run()
        self.assertEqual(asked, [[1]])
        self.assertEqual([t.status for t in plan.tasks], [CANCELLED] * 3)
        self.assertIn("before it started", plan.tasks[1].error)
        self.assertTrue(s.data["interrupted"])
        partial = parse_file(s.dir / plan.tasks[0].task_dir / "scan.xml")
        self.assertTrue(partial.repaired)
        self.assertEqual(len(partial.hosts), 1)
        saved = json.loads((s.dir / "session.json").read_text())
        self.assertTrue(saved["interrupted"])

    def test_ctrl_c_skip_cancels_only_the_running_scan(self):
        lab = self.lab("ok", delay=2.0)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        s, ex = lab.executor(plan, ts, ask_cancel=lambda running: "skip")
        self.interrupt_soon(0.8)
        ex.run()
        self.assertEqual(plan.tasks[0].status, CANCELLED)
        self.assertIn("skipped by user", plan.tasks[0].error)
        self.assertEqual(plan.tasks[1].status, COMPLETED)
        self.assertFalse(s.data["interrupted"])

    def test_ctrl_c_continue_changes_nothing(self):
        lab = self.lab("ok", delay=2.0)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, ex = lab.executor(plan, ts, ask_cancel=lambda running: "continue")
        self.interrupt_soon(0.8)
        ex.run()
        self.assertEqual(plan.tasks[0].status, COMPLETED)

    def test_ctrl_c_without_a_callback_stops(self):
        lab = self.lab("ok", delay=30)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, ex = lab.executor(plan, ts)
        self.interrupt_soon()
        ex.run()
        self.assertEqual(plan.tasks[0].status, CANCELLED)

    def test_second_ctrl_c_in_prompt_means_stop(self):
        lab = self.lab("ok", delay=30)
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])

        def prompt(running):
            raise KeyboardInterrupt

        s, ex = lab.executor(plan, ts, ask_cancel=prompt)
        self.interrupt_soon()
        ex.run()
        self.assertEqual(plan.tasks[0].status, CANCELLED)

    def test_crashing_prompt_callback_stops_safely(self):
        for cb in (lambda running: (_ for _ in ()).throw(RuntimeError("terminal gone")), lambda running: "banana"):
            with self.subTest(cb=cb):
                lab = self.lab("ok", delay=30)
                ts = lab.targets("10.0.0.5")
                plan = lab.plan(ts, [self.profile(SYN)])
                s, ex = lab.executor(plan, ts, ask_cancel=cb)
                self.interrupt_soon()
                ex.run()
                self.assertEqual(plan.tasks[0].status, CANCELLED)

    def test_cancel_escalates_to_kill_for_stubborn_process(self):
        lab = self.lab("hang")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, ex = lab.executor(plan, ts)
        threading.Timer(0.8, ex.cancel_all.set).start()
        with mock.patch.object(R, "_GRACE_INT", 0.4), mock.patch.object(R, "_GRACE_TERM", 0.4):
            t0 = time.time()
            ex.run()
        self.assertLess(time.time() - t0, 10)
        self.assertEqual(plan.tasks[0].status, CANCELLED)

    def test_force_flag_shortens_the_grace_period(self):
        lab = self.lab("hang")
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile(SYN)])
        s, ex = lab.executor(plan, ts)
        ex.force.set()
        threading.Timer(0.8, ex.cancel_all.set).start()
        t0 = time.time()
        ex.run()                                                   # default grace is 8s + 4s; force makes it ~1s
        self.assertLess(time.time() - t0, 6)
        self.assertEqual(plan.tasks[0].status, CANCELLED)


class ConcurrencyAndLocking(LabTestCase):
    def test_sequential_by_default(self):
        lab = self.lab("ok", delay=0.3)
        ts = lab.targets("10.0.0.1", "10.0.0.2", "10.0.0.3")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT)])
        lab.run(plan, ts, Config(concurrency=1))
        self.assertEqual(max_concurrent(lab.intervals()), 1)
        self.assertEqual(len(plan.tasks), 2)

    def test_different_hosts_run_in_parallel_up_to_the_limit(self):
        lab = self.lab("ok", delay=1.0)
        ts = lab.targets("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")
        plan = lab.plan(ts, [self.profile(SYN)], concurrency=4)
        self.assertEqual(len(plan.tasks), 4)
        t0 = time.time()
        lab.run(plan, ts, Config(concurrency=4))
        self.assertEqual(max_concurrent(lab.intervals()), 4)
        self.assertLess(time.time() - t0, 3.5)                     # would be >= 4s if sequential

    def test_limit_is_never_exceeded(self):
        lab = self.lab("ok", delay=0.5)
        ts = lab.targets(*[f"10.0.0.{i}" for i in range(1, 9)])
        plan = lab.plan(ts, [self.profile(SYN)], concurrency=8)
        self.assertEqual(len(plan.tasks), 8)
        lab.run(plan, ts, Config(concurrency=2))                   # plan made for 8, executor limited to 2
        self.assertEqual(max_concurrent(lab.intervals()), 2)
        self.assertEqual({t.status for t in plan.tasks}, {COMPLETED})

    def test_limit_is_clamped_to_the_maximum(self):
        lab = self.lab("ok", delay=0.05)
        ts = lab.targets("10.0.0.1")
        plan = lab.plan(ts, [self.profile(SYN)])
        lab.run(plan, ts, Config(concurrency=1000))                # absurd value must not spawn 1000 workers
        self.assertLessEqual(max_concurrent(lab.intervals()), 8)

    def test_two_scans_of_the_same_host_never_overlap(self):
        lab = self.lab("ok", delay=0.5)
        ts = lab.targets("10.0.0.1", "10.0.0.2")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT), self.profile("REQ-01-TCP-ALL-ACK")], concurrency=2)
        self.assertEqual(len(plan.tasks), 6)
        lab.run(plan, ts, Config(concurrency=4))
        iv = lab.intervals()
        for i, a in enumerate(iv):
            for b in iv[i + 1:]:
                ta = [x for x in a[2] if x.startswith("10.0.0.")]
                tb = [x for x in b[2] if x.startswith("10.0.0.")]
                if set(ta) & set(tb):
                    self.assertFalse(a[0] < b[1] and b[0] < a[1], f"overlapping scans of {set(ta) & set(tb)}")
        self.assertEqual(max_concurrent(iv), 2)                    # the two hosts did run side by side

    def test_overlapping_cidr_and_host_are_serialized(self):
        lab = self.lab("ok", delay=0.5)
        ts = lab.targets("10.0.0.0/24")
        a = lab.plan(ts, [self.profile(SYN)])
        ts2 = lab.targets("10.0.0.9")
        b = lab.plan(ts2, [self.profile(CONNECT)])
        # merge two plans (as if two selections touched overlapping scope)
        b.tasks[0].task_id = 2
        a.tasks.append(b.tasks[0])
        a.targets_digest = a.targets_digest
        lab.run(a, ts)
        iv = lab.intervals()
        self.assertEqual(max_concurrent(iv), 1)

    def test_pending_work_is_not_lost_when_everything_conflicts(self):
        lab = self.lab("ok", delay=0.2)
        ts = lab.targets("10.0.0.1")
        plan = lab.plan(ts, [self.profile(SYN), self.profile(CONNECT), self.profile("REQ-01-TCP-ALL-ACK")])
        lab.run(plan, ts, Config(concurrency=3))
        self.assertEqual([t.status for t in plan.tasks], [COMPLETED] * 3)
        self.assertEqual(max_concurrent(lab.intervals()), 1)


if __name__ == "__main__":
    unittest.main()

import json
import logging
import os
import re
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from nmapflow import models, utils
from nmapflow import profiles as P


class TextHelpers(unittest.TestCase):
    def test_slugify(self):
        self.assertEqual(utils.slugify("All TCP ports - SYN scan"), "All-TCP-ports-SYN-scan")
        self.assertEqual(utils.slugify("../../etc/passwd"), "etc-passwd")
        self.assertEqual(utils.slugify("<script>alert(1)</script>"), "script-alert-1-script")
        self.assertEqual(utils.slugify("a --- b"), "a-b")
        self.assertEqual(utils.slugify(""), "item")
        self.assertEqual(utils.slugify("///"), "item")
        self.assertEqual(len(utils.slugify("x" * 200, 30)), 30)
        self.assertNotRegex(utils.slugify("a/b\\c:d*e?f\"g<h>i|j k\x00l"), r"[/\\:*?\"<>| \x00]")

    def test_human_duration(self):
        cases = {None: "-", 0: "0s", 59.4: "59s", 61: "1m 01s", 3600: "1h 00m 00s", 3725: "1h 02m 05s", 0.4: "0s"}
        for value, expected in cases.items():
            self.assertEqual(utils.human_duration(value), expected)

    def test_strip_control(self):
        self.assertEqual(utils.strip_control("a\x00b\x07c\x1bd\x7fe"), "abcd\x7fe")      # DEL is legal in XML 1.0
        self.assertEqual(utils.strip_control("tab\tnl\ncr\r"), "tab\tnl\ncr\r")
        self.assertEqual(utils.strip_control("caf\u00e9 \u4e2d\u6587 \U0001F600"), "caf\u00e9 \u4e2d\u6587 \U0001F600")
        self.assertEqual(utils.strip_control("lone \ud800 surrogate"), "lone  surrogate")
        self.assertEqual(utils.strip_control("\ufffe\uffff"), "")

    def test_shell_display_quotes_dangerous_text_but_is_display_only(self):
        s = utils.shell_display(["nmap", "-sT", "--script", "(safe) and not (dos)", "a b", "$(id)"])
        self.assertIn("'(safe) and not (dos)'", s)
        self.assertIn("'$(id)'", s)
        self.assertIn("'a b'", s)
        self.assertTrue(s.startswith("nmap -sT"))

    def test_timestamp_names(self):
        self.assertRegex(utils.timestamp_dirname(), r"^\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d$")
        self.assertRegex(utils.now_iso(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d$")


class FileHelpers(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_atomic_write_creates_private_file(self):
        p = self.d / "sub" / "f.txt"
        utils.atomic_write_text(p, "héllo\n")
        self.assertEqual(p.read_text(encoding="utf-8"), "héllo\n")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual([x.name for x in p.parent.iterdir()], ["f.txt"])             # no temp files left

    def test_atomic_write_replaces_whole_file(self):
        p = self.d / "f.txt"
        utils.atomic_write_text(p, "old " * 1000)
        utils.atomic_write_text(p, "new")
        self.assertEqual(p.read_text(), "new")

    def test_failed_write_leaves_original_and_no_temp_file(self):
        p = self.d / "f.txt"
        utils.atomic_write_text(p, "original")
        with mock.patch.object(utils.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                utils.atomic_write_text(p, "replacement")
        self.assertEqual(p.read_text(), "original")
        self.assertEqual([x.name for x in self.d.iterdir()], ["f.txt"])

    def test_atomic_json(self):
        p = self.d / "x.json"
        utils.atomic_write_json(p, {"a": [1, 2], "path": Path("/x"), "ü": "ß"})
        data = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(data, {"a": [1, 2], "path": "/x", "ü": "ß"})

    def test_sha256(self):
        p = self.d / "f.bin"
        p.write_bytes(b"abc" * 1_000_000)
        import hashlib
        self.assertEqual(utils.sha256_file(p), hashlib.sha256(b"abc" * 1_000_000).hexdigest())
        with self.assertRaises(OSError):
            utils.sha256_file(self.d / "missing")

    def test_private_dir(self):
        p = utils.make_private_dir(self.d / "a" / "b")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)
        utils.make_private_dir(p)                                                      # idempotent

    def test_fix_ownership_is_a_safe_noop_without_sudo(self):
        p = self.d / "f"
        p.write_text("x")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_UID", None)
            utils.fix_ownership(p)
            utils.fix_ownership_tree(self.d)
        with mock.patch.dict(os.environ, {"SUDO_UID": "abc", "SUDO_GID": "def"}):
            utils.fix_ownership(p)                                                     # garbage values ignored

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root")
    def test_fix_ownership_hands_files_back_to_the_sudo_user(self):
        p = self.d / "f"
        p.write_text("x")
        with mock.patch.dict(os.environ, {"SUDO_UID": "12345", "SUDO_GID": "12346"}):
            utils.fix_ownership(p)
        self.assertEqual((p.stat().st_uid, p.stat().st_gid), (12345, 12346))


class LoggingAndColour(unittest.TestCase):
    def test_logger_writes_to_file_only(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        log = utils.setup_logger(d / "s.log")
        log.info("hello %s", "world")
        for h in log.handlers:
            h.flush()
        self.assertIn("hello world", (d / "s.log").read_text())
        self.assertFalse(log.propagate)
        utils.setup_logger(None)                                                       # replaces handlers, closes the file

    def test_colour_respects_no_color_and_tty(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(utils.colour_enabled())
            self.assertEqual(utils.style("x", "red"), "x")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            with mock.patch.object(utils.sys.stdout, "isatty", return_value=True, create=True):
                self.assertTrue(utils.colour_enabled() or os.name == "nt")
                if os.name != "nt":
                    self.assertEqual(utils.style("x", "red", "bold"), "\033[31;1mx\033[0m")
            with mock.patch.object(utils.sys.stdout, "isatty", return_value=False, create=True):
                self.assertEqual(utils.style("x", "red"), "x")
        self.assertEqual(utils.style("x"), "x")


class ModelTests(unittest.TestCase):
    def test_scantask_roundtrip_and_unknown_keys(self):
        t = models.ScanTask(task_id=3, kind="nse", profile_id="p", label="L", args=["-sT"], targets=["10.0.0.1"],
                            warnings=["w"], status=models.SKIPPED, skip_reason="r", exit_code=None, duration_s=1.5)
        d = t.to_dict()
        d["future_field"] = "ignored"
        back = models.ScanTask.from_dict(d)
        self.assertEqual(back, t)
        d2 = json.loads(json.dumps(t.to_dict()))
        self.assertEqual(models.ScanTask.from_dict(d2), t)

    def test_task_defaults_do_not_share_lists(self):
        a = models.ScanTask(task_id=1, kind="profile", profile_id="p", label="L", args=[], targets=[])
        b = models.ScanTask(task_id=2, kind="profile", profile_id="p", label="L", args=[], targets=[])
        a.warnings.append("x")
        a.extra_flags.append("-n")
        self.assertEqual((b.warnings, b.extra_flags), ([], []))

    def test_profiles_are_immutable(self):
        p = P.by_number(1)
        with self.assertRaises(FrozenInstanceError):
            p.name = "changed"
        self.assertIsInstance(p.stages, tuple)

    def test_final_statuses(self):
        self.assertEqual(set(models.FINAL_STATUSES), {"completed", "failed", "timed_out", "cancelled", "skipped"})
        self.assertNotIn(models.PENDING, models.FINAL_STATUSES)

    def test_target_to_dict(self):
        t = models.Target("10.0.0.1", "ip", "10.0.0.1")
        self.assertEqual(t.to_dict()["family"], "ipv4")


if __name__ == "__main__":
    unittest.main()

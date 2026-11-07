import contextlib
import io
import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

from nmapflow import cli
from nmapflow import config as config_mod
from nmapflow import nse as nse_mod
from nmapflow import profiles as P
from nmapflow import targets as T
from nmapflow.cli import App, BackToMenu, ExitApp, parse_numbers
from nmapflow.config import Config
from nmapflow.netdetect import LocalSubnet
from nmapflow.nse import Availability

from .helpers import LabTestCase, read_log

CTRL_C = object()


class Feeder:
    """Replacement for input(): replays scripted answers; EOF when they run out."""

    def __init__(self, lines):
        self.lines, self.prompts = list(lines), []

    def __call__(self, prompt=""):
        self.prompts.append(prompt)
        if not self.lines:
            raise EOFError
        v = self.lines.pop(0)
        if v is CTRL_C:
            raise KeyboardInterrupt
        return v


class CliTestCase(LabTestCase):
    def app(self, lab=None, privileged=True, mode="ok", delay=0.0, **cfg):
        lab = lab or self.lab(mode, delay)
        cfg.setdefault("output_dir", str(lab.reports))
        a = App(Config(**cfg), lab.nmap, "7.94", lab.avail, lab.root / "config.json")
        a.privileged = privileged
        self.last_lab = lab
        return a, lab

    def drive(self, lines, privileged=True, mode="ok", delay=0.0, app_lab=None, **cfg):
        a, lab = app_lab or self.app(privileged=privileged, mode=mode, delay=delay, **cfg)
        feeder, out = Feeder(lines), io.StringIO()
        resolver = mock.patch.object(T, "resolve_hostnames", side_effect=lambda names, **k: {n: [] for n in names})
        with mock.patch("builtins.input", feeder), contextlib.redirect_stdout(out), resolver:
            rc = a.run()
        return lab, a, out.getvalue(), feeder, rc

    def call(self, app, fn, lines):
        feeder, out = Feeder(lines), io.StringIO()
        with mock.patch("builtins.input", feeder), contextlib.redirect_stdout(out):
            result = fn()
        return result, out.getvalue(), feeder

    @staticmethod
    def sessions(lab):
        return sorted(p for p in lab.reports.glob("20*") if p.is_dir()) if lab.reports.exists() else []

    def session_json(self, lab):
        (d,) = self.sessions(lab)
        return json.loads((d / "session.json").read_text()), d


SINGLE_OK = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"]


class MainMenu(CliTestCase):
    def test_exit_choices(self):
        for answer in ("5", "q", "exit", "quit"):
            with self.subTest(answer=answer):
                lab, a, out, f, rc = self.drive([answer])
                self.assertEqual(rc, 0)

    def test_menu_shows_the_five_required_entries(self):
        lab, a, out, f, rc = self.drive(["5"])
        for text in ("1) Single host", "2) Multiple hosts", "3) Whole local network", "4) View previous scan sessions", "5) Exit"):
            self.assertIn(text, out)
        self.assertIn("authorized to assess", out)

    def test_invalid_choice_and_eof(self):
        lab, a, out, f, rc = self.drive(["9", "abc", ""])                # then EOF
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("Please enter 1-5"), 3)

    def test_ctrl_c_returns_to_the_menu(self):
        lab, a, out, f, rc = self.drive(["1", CTRL_C, "5"])
        self.assertIn("Cancelled; back at the main menu", out)
        self.assertEqual(read_log(lab.log), [])

    def test_non_root_notice(self):
        lab, a, out, f, rc = self.drive(["5"], privileged=False)
        self.assertIn("Not running as root", out)


class SingleHostFlow(CliTestCase):
    def test_complete_session(self):
        lab, a, out, f, rc = self.drive(SINGLE_OK)
        data, d = self.session_json(lab)
        self.assertEqual([t["status"] for t in data["tasks"]], ["completed"])
        self.assertEqual(data["authorization"]["typed"], "AUTHORIZED")
        self.assertEqual(data["scope"]["originals"], ["10.0.0.5"])
        self.assertTrue((d / "report.html").exists())
        self.assertTrue((d / "session.xml").exists())
        self.assertTrue((d / "session.log").exists())
        self.assertIn("SESSION FINISHED", out)
        self.assertIn("does not prove", out)
        self.assertIn("HTML report:", out)
        self.assertFalse((d / ".lock").exists())

    def test_exact_command_is_shown_before_running(self):
        lab, a, out, f, rc = self.drive(SINGLE_OK)
        self.assertIn("SCAN PLAN - REVIEW", out)
        self.assertIn("command: nmap -sT -p- -T3 -n", out)
        self.assertIn("Type RUN to start", " ".join(f.prompts))

    def test_single_host_input_validation(self):
        lines = ["1", "10.0.0.1 10.0.0.2", "10.0.0.0/24", "192.168.1.1-5", "bad;host", "-iL", "999.1.1.1", ""]
        lab, a, out, f, rc = self.drive(lines + ["5"])
        self.assertIn("exactly one target", out)
        self.assertEqual(out.count("That is a range"), 2)
        self.assertEqual(out.count("Rejected:"), 3)
        self.assertEqual(self.sessions(lab), [])
        self.assertEqual(read_log(lab.log), [])


class NothingRunsWithoutConfirmation(CliTestCase):
    """Every way of backing out must leave the fake nmap untouched."""

    def assertNeverScanned(self, lab):
        self.assertEqual(read_log(lab.log), [])
        self.assertEqual(self.sessions(lab), [])

    def test_wrong_authorization_text(self):
        for typed in ("", "authorized", "yes", "AUTHORISED", "AUTHORIZE", "y", "AUTHORIZED!"):
            with self.subTest(typed=typed):
                lab, a, out, f, rc = self.drive(["1", "10.0.0.5", "", typed, "5"])
                self.assertIn("Not confirmed", out)
                self.assertNeverScanned(lab)

    def test_declining_at_the_plan_review(self):
        for answer in ("b", "q", "cancel", "run", "Run", "RUN!", "yes", ""):
            with self.subTest(answer=answer):
                steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "n", "3", "", answer, "5"]
                lab, a, out, f, rc = self.drive(steps)
                self.assertNeverScanned(lab)

    def test_lowercase_run_does_not_start(self):
        lab, a, out, f, rc = self.drive(["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "n", "3", "", "run", "b", "5"])
        self.assertIn("Type RUN (capital letters)", out)
        self.assertNeverScanned(lab)

    def test_ctrl_c_during_selection(self):
        for step in range(3, 9):
            with self.subTest(step=step):
                steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "n", "3", ""]
                lab, a, out, f, rc = self.drive(steps[:step] + [CTRL_C, "5"])
                self.assertNeverScanned(lab)

    def test_public_address_needs_its_own_yes(self):
        lab, a, out, f, rc = self.drive(["1", "8.8.8.8", "", "no", "5"])
        self.assertIn("public Internet addresses", out)
        self.assertIn("scan cancelled", out)
        self.assertNeverScanned(lab)
        lab, a, out, f, rc = self.drive(["1", "8.8.8.8", "", "yes", "5"])          # lower case is not enough
        self.assertNeverScanned(lab)

    def test_public_address_with_both_confirmations_is_planned_but_only_the_fake_runs(self):
        lab, a, out, f, rc = self.drive(["1", "8.8.8.8", "", "YES", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"])
        self.assertEqual(len(read_log(lab.log)), 2)                       # one start + one end line from the fake
        data, _ = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["targets"], ["8.8.8.8"])

    def test_large_range_needs_confirmation(self):
        lab, a, out, f, rc = self.drive(["2", "10.0.0.0/16", "", "NO", "5"])
        self.assertIn("65,536", out)
        self.assertNeverScanned(lab)

    def test_nothing_selected(self):
        lab, a, out, f, rc = self.drive(["1", "10.0.0.5", "", "AUTHORIZED", "done", "n", "5"])
        self.assertIn("Nothing selected", out)
        self.assertNeverScanned(lab)

    def test_there_is_no_headless_scan_option(self):
        parser = cli.build_arg_parser()
        for argv in (["--scan", "10.0.0.5"], ["--target", "10.0.0.5"], ["--yes"], ["--authorized"], ["--run"], ["-t", "10.0.0.5"]):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                    parser.parse_args(argv)
                self.assertEqual(cm.exception.code, 2)
        options = {o for a in parser._actions for o in a.option_strings}
        self.assertEqual(options, {"-h", "--help", "--version", "--list-profiles", "--show-profile", "--list-nse",
                                   "--export-catalog", "--config", "--reports-dir"})


class MultipleHosts(CliTestCase):
    def test_rejected_entries_are_reported_and_not_scanned(self):
        lab, a, out, f, rc = self.drive(["2", "10.0.0.1 bad;host 10.0.0.2 -oX", "n", ""] + ["5"])
        self.assertIn("Rejected input (these will NOT be scanned)", out)
        self.assertEqual(out.count("  - "), 2)
        self.assertEqual(self.sessions(lab), [])

    def test_continue_with_valid_entries_only(self):
        steps = ["2", "10.0.0.1 bad;host 10.0.0.2", "y", "", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, _ = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["targets"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(data["scope"]["originals"], ["10.0.0.1", "bad;host", "10.0.0.2"])

    def test_file_import_with_comments(self):
        lab = self.lab()
        tf = lab.root / "hosts.txt"
        tf.parent.mkdir(parents=True, exist_ok=True)
        tf.write_text("# lab hosts\n10.0.0.1\n10.0.0.2  # second\n\n10.0.0.3\n")
        steps = ["2", f"@{tf}", "", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"]
        a, _ = self.app(lab=lab)
        _, a, out, f, rc = self.drive(steps, app_lab=(a, lab))
        data, _ = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["targets"], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_missing_file_is_reported(self):
        lab, a, out, f, rc = self.drive(["2", "@/nonexistent/hosts.txt", "", "5"])
        self.assertIn("cannot read", out)
        self.assertEqual(self.sessions(lab), [])

    def test_exclusions_reach_the_command(self):
        steps = ["2", "10.0.0.0/29", "10.0.0.3, 10.0.0.4", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, _ = self.session_json(lab)
        t = data["tasks"][0]
        self.assertEqual(t["exclude"], ["10.0.0.3", "10.0.0.4"])
        self.assertIn("10.0.0.3,10.0.0.4", t["command"])
        self.assertEqual([x["normalized"] for x in data["scope"]["exclusions"]], ["10.0.0.3", "10.0.0.4"])

    def test_duplicates_warning_is_visible(self):
        lab, a, out, f, rc = self.drive(["2", "10.0.0.1 10.0.0.1", "", "n", ""] if False else ["2", "10.0.0.1 10.0.0.1", "", "no", "5"])
        self.assertIn("duplicate target ignored", out)


class NetworkMode(CliTestCase):
    SUBNETS = [LocalSubnet("eth0", "192.168.10.23", "192.168.10.0/24"), LocalSubnet("tun0", "10.8.0.2", "10.8.0.0/24", "note")]

    def drive_net(self, steps):
        a, lab = self.app()
        with mock.patch.object(cli, "detect_subnets", return_value=(self.SUBNETS, "")):
            return self.drive(steps, app_lab=(a, lab))

    def test_subnets_are_listed_but_never_scanned_automatically(self):
        lab, a, out, f, rc = self.drive_net(["3", "", "5"])
        self.assertIn("192.168.10.0/24", out)
        self.assertIn("10.8.0.0/24", out)
        self.assertIn("nothing has been scanned", out)
        self.assertEqual(read_log(lab.log), [])

    def test_pick_a_detected_subnet(self):
        lab, a, out, f, rc = self.drive_net(["3", "2", "10.8.0.1", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"])
        data, _ = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["targets"], ["10.8.0.0/24"])
        self.assertIn("10.8.0.0/24", out)

    def test_selection_validation_and_manual_cidr(self):
        steps = ["3", "9", "0", "x", "m", "10.0.0.5", "m", "192.168.5.0/30", "", "AUTHORIZED", "9", "done", "n", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive_net(steps)
        self.assertIn("choose one of the listed numbers", out)
        self.assertIn("Rejected: not a CIDR range", out)
        data, _ = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["targets"], ["192.168.5.0/30"])

    def test_scope_screen_names_the_range_before_any_scan(self):
        lab, a, out, f, rc = self.drive_net(["3", "1", "", "no-such-confirmation", "5"])
        self.assertIn("SCOPE CONFIRMATION", out)
        self.assertIn("about 256 address(es)", out)
        self.assertEqual(read_log(lab.log), [])

    def test_empty_detection_message(self):
        a, lab = self.app()
        with mock.patch.object(cli, "detect_subnets", return_value=([], "No active IPv4 interfaces were found.")):
            lab, a, out, f, rc = self.drive(["3", "", "5"], app_lab=(a, lab))
        self.assertIn("No active IPv4 interfaces", out)


class ProfileSelection(CliTestCase):
    def pick(self, lines, **cfg):
        a, _ = self.app(**cfg)
        result, out, feeder = self.call(a, a.select_profiles, lines)
        return result, out, feeder

    def test_number_lists_and_ranges(self):
        (profiles, opt), out, f = self.pick(["4, 7,8", "done"])
        self.assertEqual([p.number for p in profiles], [4, 7, 8])
        (profiles, _), _, _ = self.pick(["4-6", "2", "done"])
        self.assertEqual([p.number for p in profiles], [4, 5, 6, 2])

    def test_duplicates_in_selection_are_collapsed(self):
        (profiles, _), _, _ = self.pick(["4", "4,4", "4-5", "done"])
        self.assertEqual([p.number for p in profiles], [4, 5])

    def test_whole_category(self):
        (profiles, _), _, _ = self.pick(["c2", "done"])
        self.assertEqual(len(profiles), 10)
        self.assertEqual({p.category for p in profiles}, {"discovery"})
        (profiles, _), _, _ = self.pick(["c1", "done"])
        self.assertEqual([p.number for p in profiles], list(range(1, 11)))

    def test_custom_category_cannot_be_selected_blindly(self):
        (profiles, _), out, _ = self.pick(["c11", "done"])
        self.assertEqual(profiles, [])
        self.assertIn("need details", out)

    def test_listing_search_and_show(self):
        _, out, _ = self.pick(["l1", "list 3", "list all", "/ssh", "show 5", "/zzzzzz", "done"])
        self.assertIn("All TCP ports - ACK scan", out)
        self.assertIn("SSH: detect services", out)
        self.assertIn("-sA --top-ports 1000 -sV", out)
        self.assertIn("Nmap args:", out)
        self.assertIn("No match.", out)

    def test_remove_clear_none(self):
        (profiles, _), _, _ = self.pick(["1-4", "remove 2,3", "done"])
        self.assertEqual([p.number for p in profiles], [1, 4])
        (profiles, _), _, _ = self.pick(["1-4", "clear", "done"])
        self.assertEqual(profiles, [])
        (profiles, _), _, _ = self.pick(["1-4", "none"])
        self.assertEqual(profiles, [])

    def test_bad_input_is_explained_and_does_not_end_selection(self):
        (profiles, _), out, _ = self.pick(["abc", "0", "999", "5-3", "list 99", "c99", "show 999", "2", "done"])
        self.assertEqual([p.number for p in profiles], [2])
        for text in ("is not a number", "is not in the list", "backwards range", "category must be 1-"):
            self.assertIn(text, out)

    def test_quit_returns_none(self):
        result, _, _ = self.pick(["2", "quit"])
        self.assertIsNone(result)

    def test_warnings_are_shown_when_adding(self):
        _, out, _ = self.pick(["5", "done"])
        self.assertIn("never 'open'", out)

    def test_custom_port_profile(self):
        (profiles, _), out, _ = self.pick(["custom", "1", "tcp", "2", "8080,8443", "-sV", "done"])
        self.assertEqual(profiles[0].stages, (("-sT", "-p", "8080,8443", "-sV"),))

    def test_custom_port_profile_rejects_bad_input(self):
        (profiles, _), out, _ = self.pick(["custom", "1", "tcp", "1", "99999", "", "custom", "1", "tcp", "1", "80", "-oX", "done"])
        self.assertEqual(profiles, [])
        self.assertEqual(out.count("Rejected:"), 2)

    def test_custom_arguments(self):
        (profiles, _), out, _ = self.pick(["custom", "2", "-sT -p 22 -sV", "done"])
        self.assertEqual(profiles[0].stages, (("-sT", "-p", "22", "-sV"),))

    def test_custom_arguments_are_validated(self):
        for bad in ("-sS --script vuln", "-oX /tmp/x", "10.0.0.1", "-D RND:3", "$(id)"):
            with self.subTest(bad=bad):
                (profiles, _), out, _ = self.pick(["custom", "2", bad, "done"])
                self.assertEqual(profiles, [])
                self.assertIn("Rejected:", out)

    def test_custom_profiles_reachable_by_their_catalog_number(self):
        n = P.by_id("CUSTOM-ARGS").number
        (profiles, _), out, _ = self.pick([str(n), "-sT -p 21", "done"])
        self.assertEqual(profiles[0].stages, (("-sT", "-p", "21"),))

    def test_opt_in_profile_requires_typed_yes(self):
        n = P.by_id("VULN-EXTERNAL-VULNERS").number
        (profiles, opt), out, _ = self.pick([str(n), "yes", str(n), "NO", "done"])
        self.assertEqual((profiles, opt), ([], []))
        self.assertIn("OPT-IN REQUIRED", out)
        self.assertIn("vulners.com", out)
        (profiles, opt), _, _ = self.pick([str(n), "YES", "done"])
        self.assertEqual([p.id for p in profiles], ["VULN-EXTERNAL-VULNERS"])
        self.assertEqual(opt, ["VULN-EXTERNAL-VULNERS"])

    def test_defaults_can_be_accepted_or_declined(self):
        (profiles, _), out, _ = self.pick([""], default_profiles=["REQ-02-TCP-ALL-SYN"])
        self.assertEqual([p.id for p in profiles], ["REQ-02-TCP-ALL-SYN"])
        (profiles, _), out, _ = self.pick(["n", "9", "done"], default_profiles=["REQ-02-TCP-ALL-SYN"])
        self.assertEqual([p.number for p in profiles], [9])

    def test_prompt_shows_how_many_are_selected(self):
        _, _, f = self.pick(["1-3", "done"])
        self.assertTrue(any("[3 selected]" in p for p in f.prompts))


class NseSelection(CliTestCase):
    def pick(self, lines, avail=None, **cfg):
        a, lab = self.app(**cfg)
        if avail is not None:
            a.avail = avail
        return self.call(a, a.select_nse, lines)

    def test_declining_gives_empty_selection(self):
        sel, out, _ = self.pick(["n"])
        self.assertTrue(sel.is_empty())

    def test_select_scripts_and_bundles(self):
        sel, out, _ = self.pick(["y", "6,7,47", "done"])
        self.assertEqual([e.id for e in sel.entries], ["http-title", "http-headers", "bundle-http"])
        self.assertEqual(sel.confirmed_opt_in, [])

    def test_range_syntax(self):
        sel, _, _ = self.pick(["y", "19-21", "done"])
        self.assertEqual([e.id for e in sel.entries], ["ssh-hostkey", "ssh2-enum-algos", "sshv1"])

    def test_opt_in_script_needs_typed_yes(self):
        sel, out, _ = self.pick(["y", "18", "yes", "done"])
        self.assertEqual(sel.entries, [])
        self.assertIn("OPT-IN REQUIRED", out)
        self.assertIn("intrusive", out)
        sel, _, _ = self.pick(["y", "18", "YES", "done"])
        self.assertEqual([e.id for e in sel.entries], ["ssl-enum-ciphers"])
        self.assertEqual(sel.confirmed_opt_in, ["ssl-enum-ciphers"])

    def test_unavailable_entries_are_refused_with_a_reason(self):
        sel, out, _ = self.pick(["y", "6,7", "done"], avail=Availability({"http-title": {"safe"}}))
        self.assertEqual([e.id for e in sel.entries], ["http-title"])
        self.assertIn("http-headers: not available", out)

    def test_missing_script_database(self):
        sel, out, _ = self.pick([], avail=Availability(None, "", ["script.db not found"]))
        self.assertTrue(sel.is_empty())
        self.assertIn("unavailable", out)

    def test_list_and_show(self):
        sel, out, _ = self.pick(["y", "list", "show 5", "show 18", "done"])
        self.assertIn("Categories", out)
        self.assertIn("Individual scripts", out)
        self.assertIn("Bundles", out)
        self.assertIn("[opt-in: intrusive-labelled]", out)
        self.assertIn("Nmap expression:", out)
        self.assertIn("Intrusive/disruptive:", out)

    def test_bad_numbers(self):
        sel, out, _ = self.pick(["y", "0", "56", "x", "6", "done"])
        self.assertEqual([e.id for e in sel.entries], ["http-title"])

    def test_none_and_quit(self):
        sel, _, _ = self.pick(["y", "6", "none"])
        self.assertTrue(sel.is_empty())
        sel, _, _ = self.pick(["y", "6", "quit"])
        self.assertIsNone(sel)

    def test_defaults(self):
        sel, _, _ = self.pick([""], default_nse=["cat-safe", "http-title"])
        self.assertEqual([e.id for e in sel.entries], ["cat-safe", "http-title"])

    def test_nse_only_session_runs_without_any_profile(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "done", "y", "6,7", "done", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, d = self.session_json(lab)
        self.assertEqual([t["kind"] for t in data["tasks"]], ["nse"])
        self.assertEqual(data["tasks"][0]["status"], "completed")
        self.assertEqual(data["nse_selection"], ["http-title", "http-headers"])
        self.assertEqual(data["profiles"], [])

    def test_profiles_and_nse_run_as_separate_tasks(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "y", "6", "done", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, _ = self.session_json(lab)
        self.assertEqual([t["kind"] for t in data["tasks"]], ["profile", "nse"])
        self.assertNotIn("--script", data["tasks"][0]["args"])


class TimingAndOptions(CliTestCase):
    def test_timing_choices(self):
        a, _ = self.app()
        for answer, expected in (("", 3), ("4", 4), ("t2", 2), ("T1", 1)):
            with self.subTest(answer=answer):
                v, out, _ = self.call(a, a.select_timing, [answer])
                self.assertEqual(v, expected)

    def test_timing_retries_on_bad_input(self):
        a, _ = self.app()
        v, out, f = self.call(a, a.select_timing, ["0", "9", "abc", "6", "2"])
        self.assertEqual(v, 2)
        self.assertEqual(out.count("Enter 1-5."), 4)

    def test_t5_needs_confirmation(self):
        a, _ = self.app()
        v, out, _ = self.call(a, a.select_timing, ["5", "n", "5", "y"])
        self.assertEqual(v, 5)
        self.assertIn("fragile", out)
        v, _, _ = self.call(a, a.select_timing, ["5", "n", "3"])
        self.assertEqual(v, 3)

    def test_timing_is_explained(self):
        a, _ = self.app()
        _, out, _ = self.call(a, a.select_timing, [""])
        self.assertIn("speed and reliability", out)
        for t in ("T1", "T2", "T3", "T4", "T5"):
            self.assertIn(t, out)

    def test_run_options_override_for_one_run(self):
        a, _ = self.app()
        cfg, out, f = self.call(a, a.run_options, ["y", "2", "no", "yes", "10", "4", "n", "n"])
        self.assertEqual((cfg.concurrency, cfg.host_discovery, cfg.resolve_dns, cfg.timeout_minutes, cfg.hosts_per_task), (2, False, True, 10, 4))
        self.assertEqual(a.cfg.concurrency, 1)                       # defaults untouched

    def test_run_options_reject_bad_values(self):
        a, _ = self.app()
        cfg, out, _ = self.call(a, a.run_options, ["y", "99", "", "", "-5", "", "n", "n"])
        self.assertEqual(cfg.concurrency, 1)
        self.assertEqual(cfg.timeout_minutes, 240)
        self.assertIn("concurrency must be", out)

    def test_run_options_can_be_saved_as_defaults(self):
        a, lab = self.app()
        cfg, out, _ = self.call(a, a.run_options, ["y", "3", "", "", "", "", "y", "n"])
        saved = json.loads((lab.root / "config.json").read_text())
        self.assertEqual(saved["concurrency"], 3)

    def test_concurrency_flows_into_the_plan_and_runs_in_parallel(self):
        a, lab = self.app(delay=1.0)
        steps = ["2", "10.0.0.1 10.0.0.2 10.0.0.3", "", "AUTHORIZED", "9", "done", "n", "3", "y", "3", "", "", "", "", "n", "n", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps, app_lab=(a, lab))
        data, _ = self.session_json(lab)
        self.assertEqual(len(data["tasks"]), 3)
        self.assertEqual({t["status"] for t in data["tasks"]}, {"completed"})
        from .helpers import max_concurrent
        self.assertEqual(max_concurrent(lab.intervals()), 3)


class PlanReviewBehaviour(CliTestCase):
    def test_removed_tasks_stay_in_the_session_as_skipped(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9,10", "done", "n", "3", "", "r 1", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, d = self.session_json(lab)
        self.assertEqual([t["status"] for t in data["tasks"]], ["skipped", "completed"])
        self.assertEqual(data["tasks"][0]["skip_reason"], "removed by user at plan review")
        self.assertEqual(len(lab.intervals()), 1)
        html = (d / "report.html").read_text()
        self.assertIn("removed by user at plan review", html)
        self.assertIn("1 of 2 requested scans did not", html)
        import xml.etree.ElementTree as ET
        root = ET.parse(d / "session.xml").getroot()
        self.assertEqual([t.get("status") for t in root.findall("tasks/task")], ["skipped", "completed"])

    def test_removing_everything_leaves_nothing_to_run(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "n", "3", "", "r 1", "5"]
        lab, a, out, f, rc = self.drive(steps)
        self.assertIn("Nothing left to run", out)
        self.assertEqual(self.sessions(lab), [])
        self.assertEqual(read_log(lab.log), [])

    def test_bad_removal_input(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "done", "n", "3", "", "r 7", "r x", "b", "5"]
        lab, a, out, f, rc = self.drive(steps)
        self.assertIn("is not in the list", out)
        self.assertIn("is not a number", out)

    def test_duplicates_prompt_keep_first(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "custom", "2", "-sT -p-", "done", "n", "3", "", "k", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, _ = self.session_json(lab)
        self.assertEqual([t["status"] for t in data["tasks"]], ["completed", "skipped"])
        self.assertEqual(data["tasks"][1]["skip_reason"], "duplicate of task 1")
        self.assertEqual(len(lab.intervals()), 1)

    def test_duplicates_prompt_run_all(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "custom", "2", "-sT -p-", "done", "n", "3", "", "a", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps)
        data, _ = self.session_json(lab)
        self.assertEqual([t["status"] for t in data["tasks"]], ["completed", "completed"])

    def test_duplicates_prompt_quit(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "9", "custom", "2", "-sT -p-", "done", "n", "3", "", "q", "5"]
        lab, a, out, f, rc = self.drive(steps)
        self.assertEqual(read_log(lab.log), [])


class RootHandling(CliTestCase):
    def test_root_tasks_can_be_skipped_when_not_root(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "2,9", "done", "n", "3", "", "s", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps, privileged=False)
        data, _ = self.session_json(lab)
        self.assertEqual([t["status"] for t in data["tasks"]], ["skipped", "completed"])
        self.assertIn("needs root", data["tasks"][0]["skip_reason"])
        self.assertIn("sudo python3 nmapflow.py", out)
        self.assertEqual(len(lab.intervals()), 1)

    def test_all_root_tasks_skipped_means_nothing_runs(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "2", "done", "n", "3", "", "s", "5"]
        lab, a, out, f, rc = self.drive(steps, privileged=False)
        self.assertIn("Every selected scan needs root", out)
        self.assertEqual(read_log(lab.log), [])
        self.assertEqual(self.sessions(lab), [])

    def test_default_answer_quits(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "2", "done", "n", "3", "", "", "5"]
        lab, a, out, f, rc = self.drive(steps, privileged=False)
        self.assertEqual(read_log(lab.log), [])

    def test_run_anyway_records_whatever_nmap_does(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "2", "done", "n", "3", "", "r", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps, privileged=False)
        data, _ = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["status"], "completed")           # the fake does not care about root
        self.assertTrue(data["tasks"][0]["needs_root"])

    def test_root_user_sees_no_prompt(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "2", "done", "n", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps, privileged=True)
        self.assertNotIn("need root, and you are not running as root", out)

    def test_unknown_privilege_is_a_notice_not_a_block(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "2", "done", "n", "3", "", "RUN", "5"]
        lab, a, out, f, rc = self.drive(steps, privileged=None)
        self.assertIn("cannot be determined", out)
        self.assertEqual(len(lab.intervals()), 1)


class FailureHandling(CliTestCase):
    def test_session_folder_cannot_be_created(self):
        a, lab = self.app()
        with mock.patch.object(cli.Session, "create", side_effect=PermissionError(13, "Permission denied")):
            lab, a, out, f, rc = self.drive(SINGLE_OK, app_lab=(a, lab))
        self.assertIn("Cannot create the session folder", out)
        self.assertIn("Permission denied", out)
        self.assertEqual(read_log(lab.log), [])
        self.assertEqual(rc, 0)

    def test_output_directory_not_creatable(self):
        a, lab = self.app(output_dir="/proc/nonexistent/nmapflow-reports")
        lab, a, out, f, rc = self.drive(SINGLE_OK, app_lab=(a, lab))
        self.assertIn("Cannot create the session folder", out)
        self.assertEqual(read_log(lab.log), [])

    def test_low_disk_space(self):
        a, lab = self.app()
        usage = shutil._ntuple_diskusage(100 * 2**20, 99 * 2**20, 1 * 2**20)
        with mock.patch.object(cli.shutil, "disk_usage", return_value=usage):
            lab, a, out, f, rc = self.drive(SINGLE_OK, app_lab=(a, lab))
        self.assertIn("Only 1 MB free", out)
        self.assertEqual(read_log(lab.log), [])

    def test_report_failure_does_not_lose_the_raw_results(self):
        a, lab = self.app()
        with mock.patch.object(cli, "write_report", side_effect=RuntimeError("template bug")):
            lab, a, out, f, rc = self.drive(SINGLE_OK, app_lab=(a, lab))
        self.assertIn("Could not build the reports", out)
        data, d = self.session_json(lab)
        self.assertEqual(data["tasks"][0]["status"], "completed")
        self.assertTrue((d / data["tasks"][0]["task_dir"] / "scan.xml").exists())

    def test_failed_scan_is_summarised_not_hidden(self):
        lab, a, out, f, rc = self.drive(SINGLE_OK, mode="fail")
        self.assertIn("FAILED", out)
        self.assertIn("did not complete", out)
        self.assertIn("Failed to resolve", out)
        data, d = self.session_json(lab)
        self.assertIn("Failed to resolve", (d / "report.html").read_text())

    def test_no_host_responded_hint(self):
        a, lab = self.app(mode="ok")
        # an fake that reports an empty result: reuse the 'ok' fake but parse an empty-host document by patching parse_file
        from nmapflow import runner as R
        from nmapflow.models import ParsedScan
        empty = ParsedScan(complete=True, hosts_up=0, hosts_total=1)
        with mock.patch.object(R, "parse_file", return_value=empty):
            lab, a, out, f, rc = self.drive(SINGLE_OK, app_lab=(a, lab))
        self.assertIn("No host responded", out)

    def test_ctrl_c_prompt_choices(self):
        a, _ = self.app()
        task = mock.Mock(task_id=1, label="x")
        for answer, expected in (("", "continue"), ("c", "continue"), ("k", "skip"), ("s", "stop"), ("S", "stop"), ("x", None)):
            with self.subTest(answer=answer):
                if expected is None:
                    v, out, _ = self.call(a, lambda: a._ask_cancel([task]), [answer, "s"])
                    self.assertEqual(v, "stop")
                else:
                    v, out, _ = self.call(a, lambda: a._ask_cancel([task]), [answer])
                    self.assertEqual(v, expected)
        v, out, _ = self.call(a, lambda: a._ask_cancel([task]), [])           # closed terminal: stop safely
        self.assertEqual(v, "stop")
        v, out, _ = self.call(a, lambda: a._ask_cancel([task]), [CTRL_C])     # second Ctrl+C: stop safely
        self.assertEqual(v, "stop")


class DefaultsAndSettings(CliTestCase):
    def test_default_profiles_used_in_a_full_run(self):
        steps = ["1", "10.0.0.5", "", "AUTHORIZED", "", "n", "3", "", "RUN", "5"]
        a, lab = self.app(default_profiles=["REQ-09-TCP-ALL-CONNECT"])
        lab, a, out, f, rc = self.drive(steps, app_lab=(a, lab))
        data, _ = self.session_json(lab)
        self.assertEqual(data["profiles"][0]["id"], "REQ-09-TCP-ALL-CONNECT")

    def test_settings_menu_saves(self):
        a, lab = self.app()
        steps = ["c", "y", "2", "", "", "", "", "4", "", "", "REQ-09-TCP-ALL-CONNECT", "none", "", "5"]
        lab, a, out, f, rc = self.drive(steps, app_lab=(a, lab))
        saved = json.loads((lab.root / "config.json").read_text())
        self.assertEqual((saved["concurrency"], saved["timing"]), (2, 4))
        self.assertEqual(saved["default_profiles"], ["REQ-09-TCP-ALL-CONNECT"])
        self.assertIn("Saved settings", out)

    def test_settings_menu_without_editing(self):
        a, lab = self.app()
        lab, a, out, f, rc = self.drive(["c", "n", "5"], app_lab=(a, lab))
        self.assertIn("timeout_minutes", out)
        self.assertFalse((lab.root / "config.json").exists())

    def test_unwritable_config_is_reported(self):
        a, lab = self.app()
        with mock.patch.object(cli.config_mod, "save", side_effect=OSError("read-only file system")):
            lab, a, out, f, rc = self.drive(["c", "y", "2", "", "", "", "", "", "", "", "", "", "", "5"], app_lab=(a, lab))
        self.assertIn("Could not save settings", out)


class PreviousSessions(CliTestCase):
    def test_no_sessions(self):
        lab, a, out, f, rc = self.drive(["4", "5"])
        self.assertIn("No scan sessions found", out)

    def test_list_open_and_rebuild(self):
        a, lab = self.app()
        lab, a, out, f, rc = self.drive(SINGLE_OK[:-1] + ["4", "1", "r", "5"], app_lab=(a, lab))
        self.assertIn("xml:verified", out)
        self.assertIn("Authorized by", out)
        self.assertIn("Rebuilt:", out)
        self.assertIn("1/1 scans completed", out)

    def test_corrupt_session_is_listed_not_fatal(self):
        a, lab = self.app()
        bad = lab.reports / "2020-01-01_00-00-00"
        bad.mkdir(parents=True)
        (bad / "session.json").write_text("{broken")
        lab, a, out, f, rc = self.drive(["4", "1", "", "5"], app_lab=(a, lab))
        self.assertIn("no readable session.json", out)

    def test_tampering_is_visible_when_viewing(self):
        a, lab = self.app()
        lab, a, out, f, rc = self.drive(SINGLE_OK[:-1] + ["5"], app_lab=(a, lab))
        data, d = self.session_json(lab)
        xml = d / data["tasks"][0]["task_dir"] / "scan.xml"
        xml.chmod(0o600)
        xml.write_text(xml.read_text() + "<!-- edited -->")
        lab, a, out, f, rc = self.drive(["4", "1", "", "5"], app_lab=(a, lab))
        self.assertIn("xml:MISMATCH", out)


class EntryPoint(CliTestCase):
    def run_main(self, argv, stdin_lines=()):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("builtins.input", Feeder(stdin_lines)):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_version(self):
        rc, out, _ = self.run_main(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("nmapflow 1.0.0", out)

    def test_list_profiles(self):
        rc, out, _ = self.run_main(["--list-profiles"])
        self.assertEqual(rc, 0)
        rows = [ln for ln in out.splitlines() if ln.strip()[:1].isdigit()]
        self.assertEqual(len(rows), len(P.catalog()))
        self.assertIn("-sA -p-", out)
        self.assertIn("-sS -p-  ->  -sU --top-ports 1000", out)

    def test_show_profile_by_number_and_id(self):
        for key in ("5", "REQ-05-TCP-TOP1000-ACK-SV"):
            rc, out, _ = self.run_main(["--show-profile", key])
            self.assertEqual(rc, 0)
            self.assertIn("-sA --top-ports 1000 -sV", out)
            self.assertIn("Risk:", out)
        rc, out, _ = self.run_main(["--show-profile", "nope"])
        self.assertEqual(rc, 1)
        self.assertIn("No such profile", out)

    def test_list_nse(self):
        rc, out, _ = self.run_main(["--list-nse"])
        self.assertEqual(rc, 0)
        self.assertEqual(len([ln for ln in out.splitlines() if ln.strip()]), 55)

    def test_export_catalog(self):
        target = self.tmp / "catalog.md"
        rc, out, _ = self.run_main(["--export-catalog", str(target)])
        self.assertEqual(rc, 0)
        self.assertIn(f"Total profiles: {len(P.catalog())}", target.read_text())

    def test_missing_nmap_is_explained(self):
        cfgfile = self.tmp / "c.json"
        cfgfile.write_text("{}")
        with mock.patch.object(cli.shutil, "which", return_value=None):
            rc, out, err = self.run_main(["--config", str(cfgfile)])
        self.assertEqual(rc, 2)
        self.assertIn("Nmap was not found", err)
        self.assertIn("sudo apt update && sudo apt install -y nmap", err)

    def test_configured_nmap_path_that_does_not_exist(self):
        cfgfile = self.tmp / "c.json"
        cfgfile.write_text(json.dumps({"nmap_path": "/nonexistent/nmap"}))
        rc, out, err = self.run_main(["--config", str(cfgfile)])
        self.assertEqual(rc, 2)
        self.assertIn("Nmap was not found", err)

    def test_interactive_start_with_fake_nmap(self):
        lab = self.lab()
        cfgfile = self.tmp / "c.json"
        cfgfile.write_text(json.dumps({"nmap_path": lab.nmap, "output_dir": str(lab.reports)}))
        rc, out, err = self.run_main(["--config", str(cfgfile)], ["5"])
        self.assertEqual(rc, 0)
        self.assertIn("Nmap 7.94", out)

    def test_reports_dir_option_and_bad_config_message(self):
        lab = self.lab()
        cfgfile = self.tmp / "c.json"
        cfgfile.write_text(json.dumps({"nmap_path": lab.nmap, "timing": 99}))
        rc, out, err = self.run_main(["--config", str(cfgfile), "--reports-dir", str(lab.reports)], ["5"])
        self.assertIn("Settings: timing", out)
        self.assertEqual(rc, 0)

    def test_ctrl_c_at_startup_is_clean(self):
        lab = self.lab()
        cfgfile = self.tmp / "c.json"
        cfgfile.write_text(json.dumps({"nmap_path": lab.nmap}))
        with mock.patch.object(cli.App, "run", side_effect=KeyboardInterrupt):
            rc, out, err = self.run_main(["--config", str(cfgfile)])
        self.assertEqual(rc, 130)


class ParseNumbers(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_numbers("4, 7,8", 10), [4, 7, 8])
        self.assertEqual(parse_numbers("2-4", 10), [2, 3, 4])
        self.assertEqual(parse_numbers("3 3 3", 10), [3])
        self.assertEqual(parse_numbers("", 10), [])

    def test_invalid(self):
        for text, maxnum in (("0", 5), ("6", 5), ("a", 5), ("3-1", 5), ("1-9", 5), ("-2", 5), ("1.5", 5)):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_numbers(text, maxnum)


if __name__ == "__main__":
    unittest.main()

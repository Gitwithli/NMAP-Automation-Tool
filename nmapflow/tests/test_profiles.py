import re
import tempfile
import unittest
from pathlib import Path

from nmapflow import nse as nse_mod
from nmapflow import profiles as P
from nmapflow.customargs import ArgError, valid_port_spec
from nmapflow.planner import PlanOptions, build_command, build_plan
from nmapflow.privileges import root_reasons
from nmapflow.targets import TargetSet

from .helpers import LabTestCase, fake_availability

EXPECTED_COUNT = 156

# Every Nmap option the catalog is allowed to use, with how many values it takes.
KNOWN_FLAGS = {
    "-sS": 0, "-sT": 0, "-sA": 0, "-sW": 0, "-sN": 0, "-sF": 0, "-sX": 0, "-sU": 0, "-sV": 0, "-sC": 0,
    "-sn": 0, "-sL": 0, "-O": 0, "-A": 0, "-F": 0, "-p-": 0, "-p": 1, "--top-ports": 1,
    "-PE": 0, "-PP": 0, "-PM": 0, "-PR": 0, "--traceroute": 0, "--osscan-guess": 0, "--osscan-limit": 0,
    "--version-light": 0, "--script": 1,
}
FORBIDDEN = {"-oX", "-oN", "-oG", "-oA", "-iL", "-D", "-S", "-f", "--min-rate", "--script-args", "--data", "-T0", "-sI", "-b", "-iR"}
SCRIPT_NAMES = {s for e in nse_mod.catalog() for s in e.scripts} | {"vulners"}


def check_stage(testcase, pid, stage):
    i = 0
    stage = list(stage)
    while i < len(stage):
        a = stage[i]
        if a.startswith(("-PS", "-PA", "-PU")):
            testcase.assertTrue(valid_port_spec(a[3:]), (pid, a))
            i += 1
            continue
        testcase.assertIn(a, KNOWN_FLAGS, f"{pid}: unknown option {a}")
        testcase.assertNotIn(a, FORBIDDEN, pid)
        n = KNOWN_FLAGS[a]
        vals = stage[i + 1:i + 1 + n]
        testcase.assertEqual(len(vals), n, f"{pid}: {a} is missing its value")
        if a == "-p":
            testcase.assertTrue(valid_port_spec(vals[0]), f"{pid}: bad port spec {vals[0]}")
        if a == "--top-ports":
            testcase.assertIn(vals[0], {"10", "20", "100", "1000", "10000"}, pid)
        if a == "--script":
            v = vals[0]
            if v.startswith("("):
                testcase.assertTrue(v.endswith(nse_mod.GUARD), f"{pid}: category expression without guard")
            else:
                for name in v.split(","):
                    testcase.assertIn(name, SCRIPT_NAMES, f"{pid}: script {name} is not in the allow-list")
        i += 1 + n


class CatalogStructure(unittest.TestCase):
    def test_total_count(self):
        self.assertEqual(len(P.catalog()), EXPECTED_COUNT)

    def test_unique_ids_and_sequential_numbers(self):
        cat = P.catalog()
        self.assertEqual(len({p.id for p in cat}), len(cat))
        self.assertEqual([p.number for p in cat], list(range(1, len(cat) + 1)))

    def test_categories_cover_everything(self):
        cats = P.categories()
        self.assertEqual([c[0] for c in cats], [c[0] for c in P.CATEGORIES])
        self.assertEqual(sum(c[2] for c in cats), len(P.catalog()))
        for key, name, count in cats:
            with self.subTest(category=key):
                self.assertGreater(count, 0)
                self.assertEqual(len(P.in_category(key)), count)

    def test_category_order_in_menu(self):
        order = {k: i for i, (k, _) in enumerate(P.CATEGORIES)}
        seq = [order[p.category] for p in P.catalog()]
        self.assertEqual(seq, sorted(seq))

    def test_lookup_helpers(self):
        self.assertEqual(P.by_number(1).id, "REQ-01-TCP-ALL-ACK")
        self.assertIsNone(P.by_number(0))
        self.assertIsNone(P.by_number(EXPECTED_COUNT + 1))
        self.assertIsNone(P.by_id("nope"))
        self.assertEqual(P.by_id("REQ-02-TCP-ALL-SYN").number, 2)
        self.assertTrue(P.search("ssh"))
        self.assertEqual(P.search("zzzzzz"), [])

    def test_every_profile_has_required_fields(self):
        for p in P.catalog():
            with self.subTest(profile=p.id):
                self.assertTrue(p.id and p.name and p.description and p.category)
                self.assertTrue(p.stages and all(s for s in p.stages))
                self.assertIn(p.risk, P.RISKS)
                self.assertIn(p.duration, P.DURATIONS)
                self.assertIsInstance(p.needs_root, bool)
                self.assertTrue(p.notes or p.description)

    def test_needs_root_matches_arguments(self):
        for p in P.catalog():
            with self.subTest(profile=p.id):
                args = [a for s in p.stages for a in s]
                self.assertEqual(p.needs_root, bool(root_reasons(args)))

    def test_no_destructive_or_disruptive_options(self):
        for p in P.catalog():
            with self.subTest(profile=p.id):
                for a in (x for s in p.stages for x in s):
                    self.assertNotIn(a, FORBIDDEN)
                    self.assertFalse(re.match(r"^-T\d$", a), "timing is chosen by the user, not the profile")
                text = " ".join(a for s in p.stages for a in s)
                for banned in ("brute", "dos", "exploit", "fuzzer"):
                    if "--script" in text and not text.count("not ("):
                        self.assertNotIn(banned, text)

    def test_all_arguments_are_valid_nmap_options(self):
        for p in P.catalog():
            with self.subTest(profile=p.id):
                for stage in p.stages:
                    check_stage(self, p.id, stage)

    def test_stage_combinations_are_sensible(self):
        for p in P.catalog():
            with self.subTest(profile=p.id):
                for st in p.stages:
                    if "-O" in st and p.category != "custom":
                        self.assertNotIn("-sU", st, "OS detection is not paired with UDP-only scans")
                        for ack_like in ("-sA", "-sW", "-sN", "-sF", "-sX"):
                            self.assertNotIn(ack_like, st)
                    if "-sA" in st and "-sV" in st:
                        self.assertEqual(p.id, "REQ-05-TCP-TOP1000-ACK-SV")
                        self.assertTrue(p.warnings)

    def test_scripts_field_matches_arguments(self):
        for p in P.catalog():
            if not p.scripts:
                continue
            with self.subTest(profile=p.id):
                joined = ",".join(a for s in p.stages for i, a in enumerate(s) if i and s[i - 1] == "--script")
                for name in p.scripts:
                    self.assertIn(name, joined.split(","))

    def test_opt_in_profiles(self):
        opt = [p for p in P.catalog() if p.opt_in]
        self.assertEqual([p.id for p in opt], ["VULN-EXTERNAL-VULNERS"])
        self.assertIn("external", opt[0].allow_labels)
        self.assertTrue(opt[0].warnings)

    def test_vuln_profiles_use_safe_guard(self):
        for p in P.in_category("vuln"):
            text = " ".join(a for s in p.stages for a in s)
            if "(vuln and safe)" in text:
                self.assertIn(nse_mod.GUARD, text)

    def test_service_profiles_use_only_listed_ports(self):
        for key, name, tcp, udp, scripts in P.SERVICES:
            det = P.by_id(f"SVC-{key.upper()}-DETECT")
            self.assertIsNotNone(det, key)
            stage = det.stages[0]
            pspec = stage[stage.index("-p") + 1]
            if tcp and udp:
                self.assertEqual(pspec, f"T:{tcp},U:{udp}")
            elif udp:
                self.assertEqual(pspec, f"U:{udp}")
            else:
                self.assertEqual(pspec, tcp)
            enum = P.by_id(f"SVC-{key.upper()}-ENUM")
            self.assertEqual(enum is not None, bool(scripts), key)


class RequiredProfiles(unittest.TestCase):
    """The eight required profiles (plus the two literal-flag companions), exactly as agreed."""
    EXPECTED = {
        1: [("-sA", "-p-")],
        2: [("-sS", "-p-")],
        3: [("-sU", "-p-")],
        4: [("-sS", "-p-"), ("-sU", "--top-ports", "1000")],
        5: [("-sA", "--top-ports", "1000", "-sV")],
        6: [("-sS", "--top-ports", "1000", "-sV")],
        7: [("-sS", "--top-ports", "1000", "-sV", "-O")],
        8: [("-sU", "--top-ports", "10000", "-sV")],
        9: [("-sT", "-p-")],
        10: [("-sT", "--top-ports", "1000", "-sV")],
    }

    def test_slots_one_to_ten(self):
        for n, stages in self.EXPECTED.items():
            with self.subTest(slot=n):
                p = P.by_number(n)
                self.assertEqual(p.category, "required")
                self.assertEqual([tuple(s) for s in p.stages], stages)

    def test_profile_four_is_two_processes(self):
        self.assertEqual(len(P.by_number(4).stages), 2)

    def test_warnings_on_the_misleading_ones(self):
        self.assertTrue(P.by_number(5).warnings)
        self.assertTrue(P.by_number(3).warnings)
        self.assertTrue(P.by_number(8).warnings)
        self.assertIn("-sT", P.by_number(1).notes)
        self.assertIn("-sT", P.by_number(5).notes)

    def test_root_requirements(self):
        for n in (1, 2, 3, 4, 5, 6, 7, 8):
            self.assertTrue(P.by_number(n).needs_root, n)
        for n in (9, 10):
            self.assertFalse(P.by_number(n).needs_root, n)

    def test_required_args_are_not_duplicated_elsewhere(self):
        keys = [tuple(tuple(s) for s in p.stages) for p in P.catalog() if not p.custom]
        self.assertEqual(len(keys), len(set(keys)))


class GridContents(unittest.TestCase):
    def test_tcp_grid_is_complete(self):
        for tkey, flag in (("SYN", "-sS"), ("CONNECT", "-sT")):
            for skey, *_ in P.TCP_SCOPES:
                for akey, _, _ in P.ADDONS:
                    with self.subTest(t=tkey, s=skey, a=akey):
                        found = [p for p in P.catalog() if p.stages[0][0] == flag and len(p.stages) == 1 and p.category in ("tcp", "required")
                                 and p.id.startswith(("TCP-", "REQ-"))]
                        self.assertTrue(found)
        ids = {p.id for p in P.in_category("tcp")}
        self.assertIn("TCP-SYN-TOP100", ids)
        self.assertIn("TCP-CONNECT-ALL-SV-OS", ids)
        self.assertIn("TCP-SYN-COMMON-SV-SC", ids)

    def test_udp_grid(self):
        ids = {p.id for p in P.in_category("udp") + P.in_category("required")}
        for key in ("UDP-TOP1000", "UDP-TOP100-SV", "UDP-TOP20", "UDP-COMMON-SV"):
            self.assertIn(key, ids)

    def test_user_requested_topics_exist(self):
        wanted = ["connect", "top 100", "default scripts", "version", "OS detection", "traceroute", "http", "tls", "ssh", "ftp", "dns",
                  "smb", "smtp", "snmp", "mysql", "postgres", "rdp", "ldap", "ntp", "vulnerab", "custom port", "custom nmap"]
        blob = " ".join((p.name + " " + p.description).lower() for p in P.catalog())
        for w in wanted:
            with self.subTest(topic=w):
                self.assertIn(w.lower(), blob)


class CustomProfiles(unittest.TestCase):
    def test_custom_ports(self):
        p = P.make_custom_ports("tcp", "-sS", "22,80,443", ["-sV"])
        self.assertEqual(p.stages, (("-sS", "-p", "22,80,443", "-sV"),))
        self.assertEqual(p.custom, "ports")
        u = P.make_custom_ports("udp", "-sT", "53,161", [])
        self.assertEqual(u.stages[0][0], "-sU")

    def test_custom_ports_validation(self):
        for args in [("tcp", "-sS", "99999", []), ("tcp", "-sS", "80;ls", []), ("tcp", "-sX2", "80", []),
                     ("tcp", "-sT", "80", ["--script"]), ("tcp", "-sT", "80", ["-sV", "-oX"]), ("tcp", "-sI", "80", [])]:
            with self.subTest(args=args):
                with self.assertRaises(ArgError):
                    P.make_custom_ports(*args)

    def test_custom_args(self):
        p = P.make_custom_args("-sT -p 80 -sV")
        self.assertEqual(p.stages, (("-sT", "-p", "80", "-sV"),))
        self.assertEqual(P.make_custom_args("-sT -p 80 -sV").id, p.id)       # deterministic ID
        with self.assertRaises(ArgError):
            P.make_custom_args("-sS --script vuln")


class Rendering(unittest.TestCase):
    def test_render_shows_exact_arguments_for_every_profile(self):
        for p in P.catalog():
            with self.subTest(profile=p.id):
                text = P.render(p)
                for st in p.stages:
                    self.assertIn(" ".join(st), text)
                self.assertIn(p.id, text)
                self.assertIn(p.risk, text)

    def test_export_markdown_lists_everything(self):
        out = Path(tempfile.mkdtemp()) / "p.md"
        P.export_markdown(out)
        text = out.read_text()
        self.assertIn(f"Total profiles: {EXPECTED_COUNT}", text)
        for p in P.catalog():
            self.assertIn(f"`{p.id}`", text)
        rows = [ln for ln in text.splitlines() if re.match(r"^\| \d+ \| `", ln)]
        self.assertEqual(len(rows), EXPECTED_COUNT)


class EveryProfileThroughThePlanner(LabTestCase):
    def test_all_profiles_produce_safe_commands(self):
        ts = TargetSet()
        ts.add(["10.0.0.5"])
        confirmed = [p.id for p in P.catalog() if p.opt_in]
        plan = build_plan(ts, P.catalog(), None, fake_availability(), PlanOptions(), confirmed)
        self.assertEqual(len(plan.tasks), sum(len(p.stages) for p in P.catalog()))
        self.assertEqual(plan.warnings, [])
        for t in plan.tasks:
            with self.subTest(task=t.label):
                cmd = build_command("/usr/bin/nmap", t, "/x/scan.xml", "/x/scan.nmap")
                self.assertIsInstance(cmd, list)
                self.assertTrue(all(isinstance(a, str) and a for a in cmd))
                self.assertEqual(cmd[0], "/usr/bin/nmap")
                self.assertEqual(cmd[-1], "10.0.0.5")
                self.assertEqual(cmd.count("-oX"), 1)
                self.assertEqual(cmd[cmd.index("-oX") + 1], "/x/scan.xml")
                self.assertEqual(cmd[cmd.index("-oN") + 1], "/x/scan.nmap")
                self.assertIn("-T3", cmd)
                self.assertIn("--reason", cmd)
                self.assertEqual(t.needs_root, bool(root_reasons(t.args)))

    def test_all_profiles_run_through_the_fake_nmap(self):
        """All 156 profiles, executed as real (fake-nmap) processes, each leaving an XML + hash."""
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        confirmed = [p.id for p in P.catalog() if p.opt_in]
        plan = lab.plan(ts, P.catalog(), opt_in=confirmed)
        session, ex = lab.run(plan, ts)
        statuses = {t.status for t in plan.tasks}
        self.assertEqual(statuses, {"completed"}, [(t.label, t.status, t.error) for t in plan.tasks if t.status != "completed"])
        for t in plan.tasks:
            d = session.dir / t.task_dir
            self.assertTrue((d / "scan.xml").exists(), t.label)
            self.assertEqual(len(t.xml_sha256), 64)
        # the fake nmap saw exactly the planned commands
        self.assertEqual(len(lab.intervals()), len(plan.tasks))


if __name__ == "__main__":
    unittest.main()

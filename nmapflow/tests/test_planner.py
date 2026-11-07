import ipaddress
import unittest
from unittest import mock

from nmapflow import nse as nse_mod
from nmapflow import planner
from nmapflow import profiles as P
from nmapflow.models import ScanTask
from nmapflow.nse import Availability, NseSelection
from nmapflow.planner import PlanOptions, build_command, build_plan, chunk_units, targets_digest
from nmapflow.runner import tasks_conflict
from nmapflow.targets import TargetSet, Unit

from .helpers import fake_availability


def ts_of(*tokens, exclude=()):
    ts = TargetSet()
    ts.add(list(tokens))
    if exclude:
        ts.add_exclusions(list(exclude))
    return ts


def plan_for(ts, profiles=(), sel=None, opts=None, avail=None, opt_in=()):
    return build_plan(ts, [P.by_id(p) if isinstance(p, str) else p for p in profiles], sel, avail or fake_availability(),
                      opts or PlanOptions(), list(opt_in))


def expand(tokens):
    out = set()
    for tok in tokens:
        try:
            out.update(str(a) for a in ipaddress.ip_network(tok, strict=False))
        except ValueError:
            out.add(tok)
    return out


class Chunking(unittest.TestCase):
    def units(self, *tokens):
        return ts_of(*tokens).units("ipv4")

    def test_concurrency_one_is_a_single_task(self):
        u = self.units("10.0.0.1", "10.0.0.2", "10.0.1.0/24")
        self.assertEqual(len(chunk_units(u, 1, 0)), 1)

    def test_empty(self):
        self.assertEqual(chunk_units([], 4, 0), [])

    def test_automatic_split_covers_everything_exactly_once(self):
        cases = [
            (["10.0.0.0/24"], 4), (["10.0.0.0/24"], 3), (["10.0.0.0/30"], 8), (["10.0.0.1", "10.0.0.2", "10.0.0.3"], 3),
            (["10.0.0.1", "10.0.0.2", "10.0.0.3"], 2), (["10.0.0.0/25", "192.168.0.1", "172.16.0.0/28"], 4), (["10.0.0.5"], 8),
        ]
        for tokens, conc in cases:
            with self.subTest(tokens=tokens, conc=conc):
                units = self.units(*tokens)
                chunks = chunk_units(units, conc, 0)
                self.assertLessEqual(len(chunks), conc)
                got = []
                for c in chunks:
                    got.append(expand([u.token for u in c]))
                union = set().union(*got)
                self.assertEqual(union, expand(tokens))
                self.assertEqual(sum(len(g) for g in got), len(union), "an address was assigned to two tasks")

    def test_balanced(self):
        chunks = chunk_units(self.units("10.0.0.0/24"), 4, 0)
        sizes = [sum(u.addresses for u in c) for c in chunks]
        self.assertEqual(sizes, [64, 64, 64, 64])

    def test_hosts_per_task(self):
        chunks = chunk_units(self.units("10.0.0.0/29", "192.168.1.1"), 1, 3)
        self.assertEqual([len(c) for c in chunks], [3, 3, 3])
        self.assertEqual(sum(len(c) for c in chunks), 9)

    def test_hosts_per_task_expansion_is_bounded(self):
        with self.assertRaises(ValueError):
            chunk_units(self.units("10.0.0.0/12"), 1, 10)

    def test_hostnames_are_never_split(self):
        u = [Unit("a.example", "hostname", 1, ["host:a.example"]), Unit("b.example", "hostname", 1, ["host:b.example"])]
        chunks = chunk_units(u, 4, 0)
        self.assertEqual(sorted(c[0].token for c in chunks), ["a.example", "b.example"])


class PlanConstruction(unittest.TestCase):
    def test_one_task_per_profile_stage(self):
        plan = plan_for(ts_of("10.0.0.5"), ["REQ-04-SYN-ALL-UDP-TOP1000", "REQ-02-TCP-ALL-SYN"])
        self.assertEqual([(t.profile_id, t.stage, t.stages) for t in plan.tasks],
                         [("REQ-04-SYN-ALL-UDP-TOP1000", 1, 2), ("REQ-04-SYN-ALL-UDP-TOP1000", 2, 2), ("REQ-02-TCP-ALL-SYN", 1, 1)])
        self.assertEqual([t.task_id for t in plan.tasks], [1, 2, 3])
        self.assertEqual(plan.tasks[0].args, ["-sS", "-p-"])
        self.assertEqual(plan.tasks[1].args, ["-sU", "--top-ports", "1000"])
        self.assertTrue(all(t.status == "pending" for t in plan.tasks))

    def test_default_flags(self):
        (t,) = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN"]).tasks
        self.assertEqual(t.extra_flags, ["-n"])
        self.assertEqual(t.timing, 3)
        self.assertEqual(t.targets, ["10.0.0.5"])

    def test_options_change_flags(self):
        (t,) = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN"], opts=PlanOptions(timing=4, host_discovery=False, resolve_dns=True)).tasks
        self.assertEqual(t.extra_flags, ["-Pn"])
        self.assertEqual(t.timing, 4)

    def test_discovery_profiles_ignore_skip_discovery_with_a_note(self):
        for pid in ("DISC-PING-DEFAULT", "DISC-LIST"):
            with self.subTest(pid=pid):
                (t,) = plan_for(ts_of("10.0.0.5"), [pid], opts=PlanOptions(host_discovery=False)).tasks
                self.assertNotIn("-Pn", t.extra_flags)
                self.assertTrue(any("-Pn" in w for w in t.warnings))

    def test_list_scan_keeps_dns_resolution(self):
        (t,) = plan_for(ts_of("10.0.0.5"), ["DISC-LIST"]).tasks
        self.assertNotIn("-n", t.extra_flags)

    def test_ipv6_is_separated_and_gets_dash_6(self):
        plan = plan_for(ts_of("10.0.0.5", "::1", "2001:db8::/112"), ["REQ-02-TCP-ALL-SYN"])
        fam = {t.family: t for t in plan.tasks}
        self.assertEqual(set(fam), {"ipv4", "ipv6"})
        self.assertNotIn("-6", fam["ipv4"].extra_flags)
        self.assertIn("-6", fam["ipv6"].extra_flags)
        self.assertEqual(fam["ipv6"].targets, ["::1", "2001:db8::/112"])
        self.assertIn("[ipv4]", fam["ipv4"].label)

    def test_exclusions_are_passed_once_per_family(self):
        plan = plan_for(ts_of("10.0.0.0/24", exclude=("10.0.0.7", "10.0.0.8")), ["REQ-02-TCP-ALL-SYN"])
        (t,) = plan.tasks
        cmd = build_command("nmap", t, "x", "y")
        self.assertEqual(cmd[cmd.index("--exclude") + 1], "10.0.0.7,10.0.0.8")

    def test_concurrency_splits_hosts_into_tasks(self):
        plan = plan_for(ts_of("10.0.0.0/24"), ["REQ-02-TCP-ALL-SYN"], opts=PlanOptions(concurrency=4))
        self.assertEqual(len(plan.tasks), 4)
        self.assertEqual({t.chunks for t in plan.tasks}, {4})
        self.assertEqual(sorted(t.chunk for t in plan.tasks), [1, 2, 3, 4])
        self.assertEqual(expand(sum((t.targets for t in plan.tasks), [])), expand(["10.0.0.0/24"]))
        for t in plan.tasks:
            self.assertIn("hosts", t.label)

    def test_hosts_per_task_option_and_fallback(self):
        plan = plan_for(ts_of("10.0.0.0/30"), ["REQ-02-TCP-ALL-SYN"], opts=PlanOptions(hosts_per_task=2))
        self.assertEqual([len(t.targets) for t in plan.tasks], [2, 2])
        big = plan_for(ts_of("10.0.0.0/12"), ["REQ-02-TCP-ALL-SYN"], opts=PlanOptions(hosts_per_task=5))
        self.assertEqual(len(big.tasks), 1)
        self.assertTrue(any("too many addresses" in w for w in big.warnings))
        self.assertEqual(len([w for w in big.warnings if "too many addresses" in w]), 1)

    def test_lock_keys(self):
        plan = plan_for(ts_of("10.0.0.0/30", "10.9.9.9", "h.example"), ["REQ-02-TCP-ALL-SYN"])
        keys = plan.tasks[0].lock_keys
        self.assertIn("10.0.0.0/30", keys)
        self.assertIn("10.9.9.9/32", keys)
        self.assertIn("host:h.example", keys)

    def test_root_requirements_recorded_per_task(self):
        plan = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN", "REQ-09-TCP-ALL-CONNECT"])
        self.assertTrue(plan.tasks[0].needs_root and plan.tasks[0].root_reasons)
        self.assertFalse(plan.tasks[1].needs_root)

    def test_profile_warnings_are_carried_to_tasks(self):
        (t,) = plan_for(ts_of("10.0.0.5"), ["REQ-05-TCP-TOP1000-ACK-SV"]).tasks
        self.assertTrue(any("never 'open'" in w for w in t.warnings))

    def test_nothing_selected(self):
        plan = plan_for(ts_of("10.0.0.5"), [])
        self.assertEqual(plan.tasks, [])
        self.assertIn("Nothing to schedule.", plan.warnings)

    def test_digest_identifies_scope(self):
        a, b = ts_of("10.0.0.1"), ts_of("10.0.0.1")
        self.assertEqual(plan_for(a, ["REQ-02-TCP-ALL-SYN"]).targets_digest, targets_digest(b))
        self.assertNotEqual(targets_digest(a), targets_digest(ts_of("10.0.0.2")))
        self.assertNotEqual(targets_digest(a), targets_digest(ts_of("10.0.0.1", exclude=("10.0.0.9",))))


class Duplicates(unittest.TestCase):
    def test_identical_tasks_are_flagged_not_removed(self):
        plan = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN", "REQ-02-TCP-ALL-SYN", "REQ-01-TCP-ALL-ACK"])
        self.assertEqual(len(plan.tasks), 3)
        self.assertEqual(plan.duplicates, [(2, 1)])
        self.assertTrue(any("Identical to task 1" in w for w in plan.tasks[1].warnings))
        self.assertEqual([t.status for t in plan.tasks], ["pending"] * 3)

    def test_custom_profile_with_same_args_is_a_duplicate_too(self):
        custom = P.make_custom_args("-sS -p-")
        plan = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN", custom])
        self.assertEqual(plan.duplicates, [(2, 1)])

    def test_different_targets_or_timing_are_not_duplicates(self):
        p1 = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN"])
        p2 = plan_for(ts_of("10.0.0.6"), ["REQ-02-TCP-ALL-SYN"])
        self.assertNotEqual(p1.tasks[0].targets, p2.tasks[0].targets)
        self.assertEqual(p1.duplicates, [])


class OptInAndScripts(unittest.TestCase):
    def test_opt_in_profile_needs_confirmation(self):
        plan = plan_for(ts_of("10.0.0.5"), ["VULN-EXTERNAL-VULNERS"])
        self.assertEqual(plan.tasks, [])
        self.assertTrue(any("explicit confirmation" in w for w in plan.warnings))
        plan = plan_for(ts_of("10.0.0.5"), ["VULN-EXTERNAL-VULNERS"], opt_in=["VULN-EXTERNAL-VULNERS"])
        self.assertEqual(len(plan.tasks), 1)
        self.assertIn("opt-in confirmed", plan.tasks[0].confirm_note)
        self.assertEqual(plan.tasks[0].args[-1], "vulners")

    def test_embedded_scripts_are_filtered_to_available_ones(self):
        av = Availability({"http-title": {"safe"}, "http-headers": {"safe"}})
        (t,) = plan_for(ts_of("10.0.0.5"), ["SVC-HTTP-ENUM"], avail=av).tasks
        self.assertEqual(t.args[t.args.index("--script") + 1], "http-title,http-headers")
        self.assertTrue(any("http-methods" in w and "not run" in w for w in t.warnings))

    def test_profile_without_any_available_script_runs_without_script_flag_and_says_so(self):
        av = Availability({"something-else": {"safe"}})
        (t,) = plan_for(ts_of("10.0.0.5"), ["SVC-SSH-ENUM"], avail=av).tasks
        self.assertNotIn("--script", t.args)
        self.assertTrue(any("runs without scripts" in w for w in t.warnings))

    def test_missing_script_database_is_flagged(self):
        (t,) = plan_for(ts_of("10.0.0.5"), ["SVC-SSH-ENUM"], avail=Availability(None)).tasks
        self.assertIn("--script", t.args)
        self.assertTrue(any("could not be verified" in w for w in t.warnings))

    def test_banned_label_blocks_embedded_script(self):
        av = Availability({"ssh-hostkey": {"safe", "dos"}, "ssh2-enum-algos": {"safe"}, "sshv1": {"safe"}})
        (t,) = plan_for(ts_of("10.0.0.5"), ["SVC-SSH-ENUM"], avail=av).tasks
        self.assertNotIn("ssh-hostkey", t.args[t.args.index("--script") + 1])


class NseIndependentFromProfiles(unittest.TestCase):
    def sel(self, *ids):
        return NseSelection([nse_mod.by_id(i) for i in ids], [i for i in ids if nse_mod.by_id(i).opt_in])

    def test_nse_only_plan(self):
        plan = plan_for(ts_of("10.0.0.5"), [], self.sel("http-title", "ssh-hostkey"))
        self.assertEqual([t.kind for t in plan.tasks], ["nse"])
        t = plan.tasks[0]
        self.assertEqual(t.nse_ids, ["http-title", "ssh-hostkey"])
        self.assertFalse(t.needs_root)
        self.assertEqual(t.args[0], "-sT")

    def test_profiles_only_plan_has_no_nse_tasks(self):
        plan = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN"], self.sel())
        self.assertEqual({t.kind for t in plan.tasks}, {"profile"})

    def test_combined_plan_keeps_them_separate(self):
        plan = plan_for(ts_of("10.0.0.5"), ["REQ-02-TCP-ALL-SYN"], self.sel("http-title", "snmp-info"))
        self.assertEqual([t.kind for t in plan.tasks], ["profile", "nse", "nse"])
        for t in plan.tasks:
            if t.kind == "profile":
                self.assertNotIn("--script", t.args)
                self.assertEqual(t.nse_ids, [])
        self.assertTrue(plan.tasks[2].needs_root)        # the UDP script task needs root

    def test_nse_tasks_follow_target_chunking(self):
        plan = plan_for(ts_of("10.0.0.0/24"), [], self.sel("http-title"), opts=PlanOptions(concurrency=3))
        self.assertEqual(len(plan.tasks), 3)

    def test_unconfirmed_opt_in_script_is_reported(self):
        sel = NseSelection([nse_mod.by_id("ssl-enum-ciphers")], [])
        plan = plan_for(ts_of("10.0.0.5"), [], sel)
        self.assertEqual(plan.tasks, [])
        self.assertTrue(any("ssl-enum-ciphers" in w for w in plan.warnings))


class CommandBuilding(unittest.TestCase):
    def task(self, **kw):
        base = dict(task_id=1, kind="profile", profile_id="x", label="x", args=["-sT", "-p", "80"], targets=["10.0.0.5"])
        base.update(kw)
        return ScanTask(**base)

    def test_layout(self):
        t = self.task(extra_flags=["-n", "-Pn"], timing=4, exclude=["10.0.0.9"])
        cmd = build_command("/usr/bin/nmap", t, "/o/scan.xml", "/o/scan.nmap")
        self.assertEqual(cmd, ["/usr/bin/nmap", "-sT", "-p", "80", "-T4", "-n", "-Pn", "--exclude", "10.0.0.9", "-oX", "/o/scan.xml",
                               "-oN", "/o/scan.nmap", "--stats-every", "10s", "-v", "--reason", "10.0.0.5"])

    def test_script_expression_stays_one_argument(self):
        expr = nse_mod.by_id("cat-vuln").expression
        cmd = build_command("nmap", self.task(args=["-sT", "--script", expr]), "x", "y")
        self.assertEqual(cmd.count(expr), 1)
        self.assertEqual(cmd[cmd.index("--script") + 1], expr)

    def test_refuses_option_like_targets(self):
        for bad in ("-iL", "--script=x", "", "-oX"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    build_command("nmap", self.task(targets=[bad]), "x", "y")
        with self.assertRaises(ValueError):
            build_command("nmap", self.task(exclude=["-D"]), "x", "y")

    def test_targets_come_last_and_are_separate_arguments(self):
        cmd = build_command("nmap", self.task(targets=["10.0.0.1", "10.0.0.2", "h.example"]), "x", "y")
        self.assertEqual(cmd[-3:], ["10.0.0.1", "10.0.0.2", "h.example"])


class SameHostLocking(unittest.TestCase):
    def t(self, i, *keys):
        return ScanTask(task_id=i, kind="profile", profile_id="p", label="p", args=[], targets=[], lock_keys=list(keys))

    def test_conflicts(self):
        cases = [
            (("10.0.0.5/32",), ("10.0.0.5/32",), True),
            (("10.0.0.0/24",), ("10.0.0.5/32",), True),
            (("10.0.0.0/24",), ("10.0.1.0/24",), False),
            (("10.0.0.0/25",), ("10.0.0.0/24",), True),
            (("host:a.example",), ("host:a.example",), True),
            (("host:a.example", "192.0.2.1/32"), ("192.0.2.1/32",), True),
            (("host:a.example",), ("host:b.example",), False),
            (("::1/128",), ("10.0.0.1/32",), False),
            (("2001:db8::/112",), ("2001:db8::5/128",), True),
            (("10.0.0.1/32", "10.0.0.2/32"), ("10.0.0.2/32", "10.0.0.3/32"), True),
            ((), ("10.0.0.1/32",), False),
        ]
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(tasks_conflict(self.t(1, *a), self.t(2, *b)), expected)
                self.assertEqual(tasks_conflict(self.t(2, *b), self.t(1, *a)), expected)


if __name__ == "__main__":
    unittest.main()

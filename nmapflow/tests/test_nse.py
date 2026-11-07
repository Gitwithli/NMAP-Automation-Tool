import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nmapflow import nse
from nmapflow.nse import Availability, NseSelection

from .helpers import fake_availability


class CatalogTests(unittest.TestCase):
    def test_numbering_matches_documentation(self):
        cat = nse.catalog()
        self.assertEqual([e.num for e in cat], list(range(1, 56)))
        self.assertEqual({e.kind for e in cat[:5]}, {"category"})
        self.assertEqual({e.kind for e in cat[5:46]}, {"script"})
        self.assertEqual({e.kind for e in cat[46:]}, {"bundle"})
        self.assertEqual(nse.by_number(18).name, "ssl-enum-ciphers")
        self.assertEqual(nse.by_number(47).name, "HTTP bundle")
        self.assertIsNone(nse.by_number(0))
        self.assertIsNone(nse.by_number(56))

    def test_requested_scripts_present(self):
        names = {e.name for e in nse.catalog()}
        for s in ["http-title", "http-headers", "http-methods", "http-security-headers", "ssl-enum-ciphers", "ssh2-enum-algos",
                  "smb-protocols", "smb-security-mode", "smb-os-discovery", "dns-recursion", "ftp-anon", "smtp-commands"]:
            self.assertIn(s, names)
        for c in ["default", "discovery", "safe", "version"]:
            self.assertIn(c, names)

    def test_every_entry_documents_risk_and_intrusiveness(self):
        for e in nse.catalog():
            with self.subTest(entry=e.id):
                self.assertTrue(e.purpose and e.risk and e.intrusive)

    def test_guard_contains_every_banned_category(self):
        for c in ("intrusive", "dos", "exploit", "brute", "fuzzer", "external", "broadcast"):
            self.assertIn(c, nse.GUARD)
        self.assertEqual(nse.guarded("safe"), "(safe) and " + nse.GUARD)

    def test_category_expressions_are_guarded(self):
        for e in nse.catalog()[:5]:
            with self.subTest(entry=e.id):
                if e.id in ("cat-default", "cat-version"):
                    self.assertNotIn("brute", e.expression)
                else:
                    self.assertTrue(e.expression.endswith(nse.GUARD))
        self.assertIn("vuln and safe", nse.by_id("cat-vuln").expression)

    def test_only_ssl_enum_ciphers_is_opt_in(self):
        self.assertEqual([e.id for e in nse.catalog() if e.opt_in], ["ssl-enum-ciphers"])
        self.assertTrue(nse.by_id("ssl-enum-ciphers").opt_in_text)

    def test_no_disruptive_scripts_in_catalog(self):
        banned = ["brute", "dos", "exploit", "fuzz", "slowloris", "ms08-067", "zone-transfer", "open-relay", "enum-users", "http-enum",
                  "monlist", "empty-password", "ms12-020"]
        for e in nse.catalog():
            for s in e.scripts:
                for b in banned:
                    self.assertNotIn(b, s, s)

    def test_bundles_reference_real_catalog_scripts(self):
        scripts = {e.id for e in nse.catalog() if e.kind == "script"}
        for e in nse.catalog():
            if e.kind == "bundle":
                with self.subTest(bundle=e.id):
                    self.assertTrue(set(e.scripts) <= scripts)
                    self.assertNotIn("ssl-enum-ciphers", e.scripts)

    def test_merge_ports(self):
        self.assertEqual(nse.merge_ports(["80,443", "443,8080"]), "80,443,8080")
        self.assertEqual(nse.merge_ports(["5900-5905", "5903"]), "5900-5905")
        self.assertEqual(nse.merge_ports(["", "22"]), "22")
        self.assertEqual(nse.merge_ports([]), "")
        self.assertEqual(nse.merge_ports(["1,2,3,7"]), "1-3,7")


SAMPLE_DB = '''Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
Entry { filename = "ssl-enum-ciphers.nse", categories = { "discovery", "intrusive", } }
Entry { filename = "dns-brute.nse", categories = { "discovery", "intrusive", } }
Entry { filename = "smb-vuln-ms08-067.nse", categories = { "dos", "exploit", "intrusive", "vuln", } }
Entry { filename = "vulners.nse", categories = { "external", "safe", "vuln", } }
'''


class AvailabilityTests(unittest.TestCase):
    def db(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        p = d / "script.db"
        p.write_text(SAMPLE_DB)
        return p

    def test_parse_script_db(self):
        db = nse.parse_script_db(self.db())
        self.assertEqual(db["http-title"], {"default", "discovery", "safe"})
        self.assertEqual(db["smb-vuln-ms08-067"], {"dos", "exploit", "intrusive", "vuln"})

    def test_check_script(self):
        av = Availability(nse.parse_script_db(self.db()))
        self.assertEqual(av.check_script("http-title"), (True, ""))
        ok, why = av.check_script("missing-script")
        self.assertFalse(ok)
        self.assertIn("not installed", why)
        ok, why = av.check_script("dns-brute")
        self.assertFalse(ok)
        self.assertIn("intrusive", why)
        ok, why = av.check_script("smb-vuln-ms08-067")
        self.assertFalse(ok)
        for label in ("dos", "exploit", "intrusive"):
            self.assertIn(label, why)

    def test_opt_in_allows_only_the_named_label(self):
        av = Availability(nse.parse_script_db(self.db()))
        self.assertFalse(av.check_script("ssl-enum-ciphers")[0])
        self.assertTrue(av.check_script("ssl-enum-ciphers", frozenset({"intrusive"}))[0])
        self.assertFalse(av.check_script("smb-vuln-ms08-067", frozenset({"intrusive"}))[0])    # still has dos/exploit
        self.assertFalse(av.check_script("vulners")[0])
        self.assertTrue(av.check_script("vulners", frozenset({"external"}))[0])

    def test_invalid_script_names(self):
        av = fake_availability()
        for name in ["../etc/passwd", "a;b", "HTTP-TITLE", "x y", "", "-x", "a" * 80, "$(id)"]:
            with self.subTest(name=name):
                self.assertFalse(av.check_script(name)[0])

    def test_no_db(self):
        av = Availability(None)
        ok, why = av.check_script("http-title")
        self.assertFalse(ok)
        self.assertIn("script.db", why)

    def test_check_entry_kinds(self):
        av = Availability({"http-title": {"safe"}, "http-headers": {"safe"}})
        self.assertTrue(av.check(nse.by_id("cat-safe"))[0])                       # categories need no db entry
        ok, why = av.check(nse.by_id("bundle-http"))
        self.assertTrue(ok)
        self.assertIn("partly available", why)
        self.assertFalse(av.check(nse.by_id("bundle-ssh"))[0])
        self.assertFalse(av.check(nse.by_id("ssh-hostkey"))[0])

    def test_usable_scripts_reports_problems(self):
        av = Availability({"a-b": {"safe"}, "c-d": {"dos"}})
        ok, problems = av.usable_scripts(["a-b", "c-d", "e-f"])
        self.assertEqual(ok, ["a-b"])
        self.assertEqual(len(problems), 2)

    def test_find_script_db_prefers_env(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / "scripts").mkdir()
        (d / "scripts" / "script.db").write_text(SAMPLE_DB)
        with mock.patch.dict(os.environ, {"NMAPDIR": str(d)}):
            self.assertEqual(nse.find_script_db(), d / "scripts" / "script.db")

    def test_load_availability_without_db(self):
        with mock.patch.object(nse, "find_script_db", return_value=None):
            av = nse.load_availability("nmap")
        self.assertIsNone(av.db)
        self.assertTrue(av.messages)


class ExpandSelection(unittest.TestCase):
    def setUp(self):
        self.av = fake_availability()

    def sel(self, *ids):
        return NseSelection([nse.by_id(i) for i in ids], [i for i in ids if nse.by_id(i).opt_in])

    def test_empty_selection(self):
        groups, warns = nse.expand_selection(NseSelection(), self.av)
        self.assertEqual((groups, warns), ([], []))

    def test_scripts_group_by_protocol(self):
        groups, warns = nse.expand_selection(self.sel("http-title", "http-headers", "snmp-info", "dns-recursion"), self.av)
        self.assertEqual(warns, [])
        by = {g.id: g for g in groups}
        tcp, udp = by["nse-scripts-tcp"], by["nse-scripts-udp"]
        self.assertEqual(tcp.args[:4], ["-sT", "-p", "53,80,443,8080,8443", "-sV"])
        self.assertEqual(tcp.args[-2:], ["--script", "http-title,http-headers,dns-recursion"])
        self.assertEqual(udp.args, ["-sU", "-p", "53,161", "-sV", "--script", "snmp-info,dns-recursion"])

    def test_tcp_only_and_udp_only(self):
        g, _ = nse.expand_selection(self.sel("ssh-hostkey"), self.av)
        self.assertEqual([x.id for x in g], ["nse-scripts-tcp"])
        g, _ = nse.expand_selection(self.sel("ntp-info"), self.av)
        self.assertEqual([x.id for x in g], ["nse-scripts-udp"])

    def test_bundle_expands_to_member_scripts(self):
        g, _ = nse.expand_selection(self.sel("bundle-ssh"), self.av)
        self.assertEqual(g[0].args[-1], "ssh-hostkey,ssh2-enum-algos,sshv1")
        self.assertEqual(g[0].args[2], "22")

    def test_overlapping_selection_does_not_duplicate_scripts(self):
        g, _ = nse.expand_selection(self.sel("ssh-hostkey", "bundle-ssh"), self.av)
        self.assertEqual(g[0].args[-1].split(",").count("ssh-hostkey"), 1)

    def test_categories_are_separate_tasks_with_guard(self):
        g, _ = nse.expand_selection(self.sel("cat-safe", "cat-vuln", "cat-default"), self.av)
        self.assertEqual(len(g), 3)
        for grp in g:
            self.assertEqual(grp.args[:5], ["-sT", "--top-ports", "1000", "-sV", "--script"])
        exprs = {grp.args[-1] for grp in g}
        self.assertIn(nse.by_id("cat-vuln").expression, exprs)
        self.assertIn("default", exprs)
        for grp in g:
            if grp.args[-1] != "default":
                self.assertIn("not (intrusive or dos or exploit or brute or fuzzer or external or broadcast)", grp.args[-1])

    def test_category_udp_option(self):
        g, _ = nse.expand_selection(self.sel("cat-safe"), self.av, category_udp_top_ports=50)
        self.assertEqual(len(g), 2)
        self.assertEqual(g[1].args[:3], ["-sU", "--top-ports", "50"])

    def test_opt_in_requires_confirmation(self):
        unconfirmed = NseSelection([nse.by_id("ssl-enum-ciphers"), nse.by_id("ssl-cert")], [])
        g, warns = nse.expand_selection(unconfirmed, self.av)
        self.assertTrue(any("ssl-enum-ciphers" in w and "confirm" in w for w in warns))
        self.assertNotIn("ssl-enum-ciphers", g[0].args[-1])
        self.assertIn("ssl-cert", g[0].args[-1])
        confirmed = NseSelection([nse.by_id("ssl-enum-ciphers")], ["ssl-enum-ciphers"])
        g, warns = nse.expand_selection(confirmed, self.av)
        self.assertEqual(warns, [])
        self.assertIn("ssl-enum-ciphers", g[0].args[-1])
        self.assertIn("opt-in", g[0].confirm_note)

    def test_unavailable_scripts_are_reported_not_silently_dropped(self):
        av = Availability({"http-title": {"safe"}})
        g, warns = nse.expand_selection(self.sel("http-title", "http-headers"), av)
        self.assertEqual(g[0].args[-1], "http-title")
        self.assertTrue(any("http-headers" in w for w in warns))

    def test_script_with_banned_label_is_refused(self):
        av = Availability({"http-title": {"safe", "intrusive"}})
        g, warns = nse.expand_selection(self.sel("http-title"), av)
        self.assertEqual(g, [])
        self.assertTrue(any("intrusive" in w for w in warns))

    def test_generated_arguments_never_contain_script_args_or_banned_categories_unguarded(self):
        every = NseSelection([e for e in nse.catalog() if not e.opt_in], [])
        groups, _ = nse.expand_selection(every, self.av, category_udp_top_ports=20)
        for g in groups:
            with self.subTest(group=g.id):
                self.assertNotIn("--script-args", g.args)
                value = g.args[g.args.index("--script") + 1]
                if value.startswith("("):
                    self.assertTrue(value.endswith(nse.GUARD))


if __name__ == "__main__":
    unittest.main()

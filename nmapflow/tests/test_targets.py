import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nmapflow import targets as T
from nmapflow.targets import TargetError, TargetSet, parse_token


class ParseTokenValid(unittest.TestCase):
    def test_valid_single_targets(self):
        cases = [
            ("192.168.1.10", "ip", "192.168.1.10", "ipv4"),
            ("0.0.0.0", "ip", "0.0.0.0", "ipv4"),
            ("::1", "ip", "::1", "ipv6"),
            ("2001:db8::1", "ip", "2001:db8::1", "ipv6"),
            ("2001:0DB8:0:0:0:0:0:1", "ip", "2001:db8::1", "ipv6"),
            ("10.0.0.0/24", "cidr", "10.0.0.0/24", "ipv4"),
            ("10.0.0.5/24", "cidr", "10.0.0.0/24", "ipv4"),       # host bits are normalised
            ("10.0.0.1/32", "cidr", "10.0.0.1/32", "ipv4"),
            ("2001:db8::/112", "cidr", "2001:db8::/112", "ipv6"),
            ("Example.COM", "hostname", "example.com", "ipv4"),
            ("host-1.lab.local.", "hostname", "host-1.lab.local", "ipv4"),
            ("router", "hostname", "router", "ipv4"),
            ("a1.b2.c3", "hostname", "a1.b2.c3", "ipv4"),
        ]
        for raw, kind, norm, fam in cases:
            with self.subTest(raw=raw):
                (t,) = parse_token(raw)
                self.assertEqual((t.kind, t.normalized, t.family), (kind, norm, fam))
                self.assertEqual(t.raw, raw)

    def test_last_octet_range(self):
        ts = parse_token("192.168.10.2-5")
        self.assertEqual([t.normalized for t in ts], ["192.168.10.2", "192.168.10.3", "192.168.10.4", "192.168.10.5"])

    def test_full_range_crossing_octets(self):
        ts = parse_token("10.0.0.250-10.0.1.2")
        self.assertEqual(len(ts), 9)
        self.assertEqual(ts[0].normalized, "10.0.0.250")
        self.assertEqual(ts[-1].normalized, "10.0.1.2")

    def test_source_is_recorded(self):
        self.assertEqual(parse_token("1.2.3.4", "file")[0].source, "file")


class ParseTokenInvalid(unittest.TestCase):
    BAD = [
        "", "   ", "-iL", "--script=vuln", "-sS", "host;rm -rf /", "a b", "$(id)", "`id`", "a|b", "a&b",
        "x>y", "a'b", 'a"b', "999.1.1.1", "1.2.3", "1.2.3.4.5", "256.0.0.1", "10.0.0.0/33", "10.0.0.0/7",
        "2001:db8::/64", "2001:db8::/111", "192.168.1.9-2", "192.168.1.1-300", "bad_host", "-bad.example.com",
        "bad-.example.com", "a" * 254, "10.0.0.0-10.5.0.0", "http://example.com", "host:80", "exa mple.com",
        "1.2.3.4/abc", "12345", "1.1.1", "*.example.com", "host..example.com", ".example.com",
    ]

    def test_rejected(self):
        for raw in self.BAD:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(TargetError):
                    parse_token(raw)

    def test_error_explains_option_confusion(self):
        with self.assertRaises(TargetError) as cm:
            parse_token("-iL")
        self.assertIn("option", str(cm.exception))


class TargetSetBehaviour(unittest.TestCase):
    def test_originals_preserved_and_dedup(self):
        ts = TargetSet()
        ts.add(["10.0.0.1", "10.0.0.1", "HOST.example", "host.example"])
        self.assertEqual(ts.originals, ["10.0.0.1", "10.0.0.1", "HOST.example", "host.example"])
        self.assertEqual([t.normalized for t in ts.targets], ["10.0.0.1", "host.example"])
        self.assertEqual(len([w for w in ts.warnings if "duplicate" in w]), 2)

    def test_invalid_entries_never_become_targets(self):
        ts = TargetSet()
        ts.add(["10.0.0.1", "bad;host", "-oX", "10.0.0.2"])
        self.assertEqual([t.normalized for t in ts.targets], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(len(ts.errors), 2)
        self.assertEqual(ts.originals, ["10.0.0.1", "bad;host", "-oX", "10.0.0.2"])

    def test_empty_set(self):
        ts = TargetSet()
        self.assertTrue(ts.is_empty())
        ts.add(["nope!"])
        self.assertTrue(ts.is_empty())

    def test_entry_limit(self):
        ts = TargetSet()
        with mock.patch.object(T, "MAX_TARGET_ENTRIES", 10):
            ts.add(["10.0.0.1-10.0.0.5"])
            ts.add(["10.0.1.1-10.0.1.20"])
        self.assertEqual(len(ts.targets), 5)
        self.assertTrue(any("limit" in e for e in ts.errors))

    def test_warnings_are_not_repeated_when_units_called_often(self):
        ts = TargetSet()
        ts.add(["10.0.0.5"])
        ts.add_exclusions(["10.0.0.5"])
        for _ in range(5):
            ts.units("ipv4")
        self.assertEqual(len([w for w in ts.warnings if "excluded" in w]), 1)

    def test_exclusions(self):
        ts = TargetSet()
        ts.add(["10.0.0.1", "10.0.0.2", "10.0.0.0/30"])
        ts.add_exclusions(["10.0.0.2"])
        toks = [u.token for u in ts.units("ipv4")]
        self.assertNotIn("10.0.0.2", toks)
        self.assertEqual(ts.exclusion_tokens("ipv4"), ["10.0.0.2"])

    def test_bad_exclusion_reported(self):
        ts = TargetSet()
        ts.add(["10.0.0.1"])
        ts.add_exclusions(["x;y"])
        self.assertTrue(any(e.startswith("exclusion") for e in ts.errors))

    def test_units_prune_ip_inside_cidr_and_nested_cidr(self):
        ts = TargetSet()
        ts.add(["10.0.0.0/24", "10.0.0.7", "10.0.0.0/25", "192.168.1.1"])
        toks = sorted(u.token for u in ts.units("ipv4"))
        self.assertEqual(toks, ["10.0.0.0/24", "192.168.1.1"])

    def test_family_split(self):
        ts = TargetSet()
        ts.add(["10.0.0.1", "::1", "2001:db8::/112"])
        self.assertEqual(ts.families(), ["ipv4", "ipv6"])
        self.assertEqual([u.token for u in ts.units("ipv6")], ["::1", "2001:db8::/112"])
        self.assertEqual(ts.total_addresses(), 1 + 1 + 65536)

    def test_hostname_resolution_and_family(self):
        ts = TargetSet()
        ts.add(["a.example", "b.example", "c.example", "d.example"])
        table = {"a.example": ["192.0.2.1"], "b.example": ["2001:db8::5"],
                 "c.example": ["192.0.2.2", "2001:db8::6"], "d.example": []}
        with mock.patch.object(T, "resolve_hostnames", return_value=table):
            ts.resolve()
        fam = {t.normalized: t.family for t in ts.targets}
        self.assertEqual(fam, {"a.example": "ipv4", "b.example": "ipv6", "c.example": "ipv4", "d.example": "ipv4"})
        self.assertTrue(any("d.example" in w and "did not resolve" in w for w in ts.warnings))
        ts2 = TargetSet()
        ts2.add(["c.example"])
        with mock.patch.object(T, "resolve_hostnames", return_value={"c.example": ["192.0.2.2", "2001:db8::6"]}):
            ts2.resolve(prefer_ipv6=True)
        self.assertEqual(ts2.targets[0].family, "ipv6")

    def test_hostname_lock_keys_include_resolved_addresses(self):
        ts = TargetSet()
        ts.add(["a.example"])
        with mock.patch.object(T, "resolve_hostnames", return_value={"a.example": ["192.0.2.1"]}):
            ts.resolve()
        (u,) = ts.units("ipv4")
        self.assertIn("host:a.example", u.lock_keys)
        self.assertIn("192.0.2.1/32", u.lock_keys)

    def test_public_and_private_detection(self):
        ts = TargetSet()
        ts.add(["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "8.8.8.8", "1.1.1.0/24", "172.16.0.0/16"])
        self.assertEqual(sorted(ts.public_targets()), ["1.1.1.0/24", "8.8.8.8"])

    def test_public_hostname_detected_after_resolution(self):
        ts = TargetSet()
        ts.add(["pub.example"])
        with mock.patch.object(T, "resolve_hostnames", return_value={"pub.example": ["93.184.216.34"]}):
            ts.resolve()
        self.assertEqual(ts.public_targets(), ["pub.example"])

    def test_extra_confirmation_reasons(self):
        ts = TargetSet()
        ts.add(["10.0.0.1"])
        self.assertEqual(ts.extra_confirmation_reasons(), [])
        ts.add(["8.8.8.8", "10.0.0.0/16"])
        reasons = ts.extra_confirmation_reasons()
        self.assertEqual(len(reasons), 2)
        self.assertTrue(any("public" in r.lower() for r in reasons))
        self.assertTrue(any("65,536" in r for r in reasons))

    def test_digest_tokens_change_with_scope(self):
        a, b = TargetSet(), TargetSet()
        a.add(["10.0.0.1"])
        b.add(["10.0.0.1"])
        self.assertEqual(a.digest_tokens(), b.digest_tokens())
        b.add(["10.0.0.2"])
        self.assertNotEqual(a.digest_tokens(), b.digest_tokens())
        a.add_exclusions(["10.0.0.9"])
        self.assertTrue(any(t.startswith("exclude:") for t in a.digest_tokens()))


class TargetFiles(unittest.TestCase):
    def write(self, text, name="t.txt", binary=False):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        p = d / name
        p.write_bytes(text if binary else text.encode())
        return str(p)

    def test_comments_commas_and_whitespace(self):
        p = self.write("# lab\n10.0.0.1, 10.0.0.2   # inline\n\n  host.example\n10.0.0.0/30\n")
        toks, problems = T.load_target_file(p)
        self.assertEqual(toks, ["10.0.0.1", "10.0.0.2", "host.example", "10.0.0.0/30"])
        self.assertEqual(problems, [])

    def test_empty_file(self):
        toks, problems = T.load_target_file(self.write("# nothing\n\n"))
        self.assertEqual(toks, [])
        self.assertTrue(problems)

    def test_missing_file(self):
        toks, problems = T.load_target_file("/nonexistent/targets.txt")
        self.assertEqual(toks, [])
        self.assertIn("cannot read", problems[0])

    def test_too_large(self):
        p = self.write("10.0.0.1\n" * 20)
        with mock.patch.object(T, "MAX_FILE_BYTES", 50):
            toks, problems = T.load_target_file(p)
        self.assertEqual(toks, [])
        self.assertIn("larger", problems[0])

    def test_invalid_utf8_does_not_crash(self):
        toks, _ = T.load_target_file(self.write(b"10.0.0.1\n\xff\xfe\n", binary=True))
        self.assertIn("10.0.0.1", toks)

    def test_hostile_lines_are_rejected_by_target_set(self):
        toks, _ = T.load_target_file(self.write("10.0.0.1\n-iL /etc/passwd\n$(reboot)\n"))
        ts = TargetSet()
        ts.add(toks, "file")
        self.assertEqual([t.normalized for t in ts.targets], ["10.0.0.1"])
        self.assertGreaterEqual(len(ts.errors), 2)


class Resolution(unittest.TestCase):
    def test_resolve_hostnames_uses_getaddrinfo_and_survives_errors(self):
        import socket

        def fake(name, *a, **k):
            if name == "ok.example":
                return [(2, 1, 6, "", ("192.0.2.9", 0)), (10, 1, 6, "", ("2001:db8::9", 0, 0, 0))]
            raise socket.gaierror("no such host")

        with mock.patch.object(T.socket, "getaddrinfo", side_effect=fake):
            res = T.resolve_hostnames(["ok.example", "bad.example"])
        self.assertEqual(res["ok.example"], ["192.0.2.9", "2001:db8::9"])
        self.assertEqual(res["bad.example"], [])

    def test_resolve_empty(self):
        self.assertEqual(T.resolve_hostnames([]), {})


if __name__ == "__main__":
    unittest.main()

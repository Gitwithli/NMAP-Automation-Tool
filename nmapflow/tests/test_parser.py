import tempfile
import unittest
from pathlib import Path

from nmapflow import parser
from nmapflow.parser import parse_bytes, parse_file

FIX = Path(__file__).parent / "fixtures"

HEAD = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner="nmap" args="nmap -x" start="1700000000" startstr="Tue" version="7.94">\n'
FOOT = ('<runstats><finished time="1" timestr="Tue Nov 14" elapsed="2.50" summary="Nmap done" exit="success"/>'
        '<hosts up="{up}" down="{down}" total="{total}"/></runstats></nmaprun>')


def doc(hosts="", up=1, down=0, total=1):
    return (HEAD + hosts + FOOT.format(up=up, down=down, total=total)).encode()


FULL_HOST = '''<host starttime="1" endtime="2"><status state="up" reason="syn-ack"/>
<address addr="192.168.1.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="srv.lab" type="PTR"/><hostname name="srv.lab" type="user"/></hostnames>
<ports><extraports state="closed" count="995"><extrareasons reason="conn-refused" count="995"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.2" extrainfo="protocol 2.0" method="probed"><cpe>cpe:/a:openbsd:openssh:9.2</cpe></service><script id="ssh-hostkey" output="256 aa:bb"/></port>
<port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/></port>
<port protocol="udp" portid="161"><state state="open|filtered" reason="no-response"/><service name="snmp" tunnel="ssl"/></port>
</ports>
<os><osmatch name="Linux 5.15" accuracy="95"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os>
<uptime seconds="1234"/><distance value="2"/>
<hostscript><script id="smb-os-discovery" output="OS: Windows"/></hostscript>
<trace><hop ttl="1" ipaddr="192.168.1.1" rtt="0.5" host="gw"/><hop ttl="2" ipaddr="192.168.1.10"/></trace>
</host>'''


class FullDocument(unittest.TestCase):
    def setUp(self):
        self.r = parse_bytes(doc(FULL_HOST))
        self.h = self.r.hosts[0]

    def test_run_information(self):
        r = self.r
        self.assertTrue(r.complete)
        self.assertFalse(r.repaired)
        self.assertEqual((r.hosts_up, r.hosts_down, r.hosts_total), (1, 0, 1))
        self.assertEqual((r.elapsed, r.summary, r.exit_status, r.nmap_version), (2.5, "Nmap done", "success", "7.94"))
        self.assertEqual(r.errors, [])

    def test_host(self):
        h = self.h
        self.assertEqual((h.address, h.addrtype, h.state, h.reason), ("192.168.1.10", "ipv4", "up", "syn-ack"))
        self.assertEqual((h.mac, h.vendor), ("AA:BB:CC:DD:EE:FF", "Acme"))
        self.assertEqual(h.hostnames, ["srv.lab"])
        self.assertEqual((h.distance, h.uptime_s), ("2", "1234"))
        self.assertEqual(h.extraports, ["995 closed (995 conn-refused)"])

    def test_ports_and_services(self):
        ports = {(p.protocol, p.number): p for p in self.h.ports}
        self.assertEqual(set(ports), {("tcp", 22), ("tcp", 80), ("udp", 161)})
        ssh = ports[("tcp", 22)]
        self.assertEqual((ssh.state, ssh.service, ssh.product, ssh.version, ssh.extrainfo), ("open", "ssh", "OpenSSH", "9.2", "protocol 2.0"))
        self.assertEqual(ssh.cpes, ["cpe:/a:openbsd:openssh:9.2"])
        self.assertEqual([(s.id, s.output) for s in ssh.scripts], [("ssh-hostkey", "256 aa:bb")])
        self.assertEqual(ports[("tcp", 80)].state, "filtered")
        self.assertEqual(ports[("tcp", 80)].service, "")
        self.assertEqual(ports[("udp", 161)].state, "open|filtered")
        self.assertEqual(ports[("udp", 161)].tunnel, "ssl")

    def test_os_scripts_trace(self):
        h = self.h
        self.assertEqual(h.os_matches[0].name, "Linux 5.15")
        self.assertEqual(h.os_matches[0].accuracy, "95")
        self.assertIn("Linux", h.os_matches[0].classes[0])
        self.assertEqual([(s.id, s.output) for s in h.host_scripts], [("smb-os-discovery", "OS: Windows")])
        self.assertEqual([(x.ttl, x.address) for x in h.trace], [("1", "192.168.1.1"), ("2", "192.168.1.10")])


class TolerantParsing(unittest.TestCase):
    def test_missing_optional_fields(self):
        r = parse_bytes(doc('<host><address addr="10.0.0.1"/></host>'))
        h = r.hosts[0]
        self.assertEqual((h.address, h.state, h.ports, h.os_matches, h.hostnames), ("10.0.0.1", "unknown", [], [], []))

    def test_port_without_state_or_service(self):
        r = parse_bytes(doc('<host><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="22"/></ports></host>'))
        p = r.hosts[0].ports[0]
        self.assertEqual((p.number, p.state, p.service), (22, "unknown", ""))

    def test_bad_port_number(self):
        r = parse_bytes(doc('<host><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="zzz"><state state="open"/></port></ports></host>'))
        self.assertEqual(r.hosts[0].ports[0].number, 0)

    def test_host_with_only_mac(self):
        r = parse_bytes(doc('<host><address addr="AA:BB" addrtype="mac"/></host>'))
        self.assertEqual(r.hosts[0].address, "AA:BB")

    def test_host_without_address(self):
        r = parse_bytes(doc('<host><status state="up"/></host>'))
        self.assertEqual(r.hosts[0].address, "(unknown)")

    def test_no_hosts_up(self):
        r = parse_bytes(doc("", up=0, down=1, total=1))
        self.assertEqual((r.hosts, r.hosts_up, r.hosts_down, r.hosts_total), ([], 0, 1, 1))
        self.assertTrue(r.complete)

    def test_counts_derived_when_runstats_hosts_missing(self):
        data = (HEAD + '<host><status state="up"/><address addr="1.1.1.1"/></host><runstats><finished time="1" elapsed="1" summary="s" exit="success"/></runstats></nmaprun>').encode()
        r = parse_bytes(data)
        self.assertEqual((r.hosts_up, r.hosts_total), (1, 1))

    def test_ipv6_host(self):
        r = parse_bytes(doc('<host><status state="up"/><address addr="::1" addrtype="ipv6"/></host>'))
        self.assertEqual((r.hosts[0].address, r.hosts[0].addrtype), ("::1", "ipv6"))

    def test_scaninfo_collected(self):
        r = parse_bytes(HEAD.encode() + b'<scaninfo type="syn" protocol="tcp" numservices="1000"/>' + FOOT.format(up=0, down=0, total=0).encode())
        self.assertEqual(r.scaninfo, ["syn/tcp (1000 ports)"])

    def test_non_integer_attributes_do_not_crash(self):
        data = (HEAD + '<runstats><finished elapsed="abc" summary="s"/><hosts up="x" down="" total="?"/></runstats></nmaprun>').encode()
        r = parse_bytes(data)
        self.assertEqual((r.elapsed, r.hosts_up, r.hosts_total), (None, 0, 0))


class BrokenInput(unittest.TestCase):
    def test_truncated_after_a_complete_host(self):
        data = doc(FULL_HOST + '<host><status state="up"/><address addr="192.168.1.11"/><ports><port')
        r = parse_bytes(data[:data.index(b"<runstats>")] + b'<host><status state="up"/><address addr="9.9.9.9"/><ports><por')
        self.assertTrue(r.repaired)
        self.assertFalse(r.complete)
        self.assertEqual([h.address for h in r.hosts], ["192.168.1.10"])
        self.assertTrue(any("incomplete" in e for e in r.errors))

    def test_truncated_before_any_host(self):
        r = parse_bytes((HEAD + '<scaninfo type="syn" protocol="tcp" numser').encode())
        self.assertTrue(r.repaired)
        self.assertEqual(r.hosts, [])

    def test_truncated_in_header(self):
        r = parse_bytes(b'<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner="nmap" args="nmap')
        self.assertEqual(r.hosts, [])
        self.assertTrue(r.errors)

    def test_garbage(self):
        for blob in (b"not xml at all", b"<html><body>hi</body></html>", b"\x00\x01\x02", b"<nmaprun>"):
            with self.subTest(blob=blob[:20]):
                r = parse_bytes(blob)
                self.assertTrue(r.errors)
                self.assertEqual(r.hosts, [])

    def test_wrong_root_element(self):
        r = parse_bytes(b"<scan><host/></scan>")
        self.assertIn("unexpected root", r.errors[0])

    def test_missing_run_summary_is_reported(self):
        r = parse_bytes((HEAD + FULL_HOST + "</nmaprun>").encode())
        self.assertFalse(r.complete)
        self.assertTrue(any("no run summary" in e for e in r.errors))
        self.assertEqual(len(r.hosts), 1)

    def test_entity_declarations_are_refused(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
        r = parse_bytes(evil)
        self.assertIn("entity", r.errors[0])
        self.assertEqual(r.hosts, [])

    def test_one_bad_host_does_not_lose_the_others(self):
        orig = parser._parse_host
        calls = {"n": 0}

        def flaky(h):
            calls["n"] += 1
            if calls["n"] == 2:
                raise ValueError("odd host")
            return orig(h)

        data = doc('<host><address addr="1.1.1.1"/></host><host><address addr="2.2.2.2"/></host><host><address addr="3.3.3.3"/></host>', 3, 0, 3)
        parser._parse_host = flaky
        try:
            r = parse_bytes(data)
        finally:
            parser._parse_host = orig
        self.assertEqual([h.address for h in r.hosts], ["1.1.1.1", "3.3.3.3"])
        self.assertTrue(any("could not be read" in e for e in r.errors))

    def test_dtd_and_stylesheet_of_real_nmap_are_accepted(self):
        data = b'<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n<!-- c -->\n<nmaprun start="1"><runstats><finished elapsed="1" exit="success"/></runstats></nmaprun>'
        r = parse_bytes(data)
        self.assertEqual(r.errors, [])
        self.assertTrue(r.complete)


class FileHandling(unittest.TestCase):
    def tmp(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_missing_file(self):
        r = parse_file(self.tmp() / "nope.xml")
        self.assertIn("cannot read", r.errors[0])

    def test_empty_file(self):
        p = self.tmp() / "e.xml"
        p.write_bytes(b"  \n")
        self.assertIn("empty", parse_file(p).errors[0])

    def test_oversized_file(self):
        p = self.tmp() / "big.xml"
        p.write_bytes(doc(FULL_HOST))
        old = parser.MAX_XML_BYTES
        parser.MAX_XML_BYTES = 10
        try:
            self.assertIn("larger", parse_file(p).errors[0])
        finally:
            parser.MAX_XML_BYTES = old

    def test_parsing_never_modifies_the_file(self):
        p = self.tmp() / "t.xml"
        full = doc(FULL_HOST)
        p.write_bytes(full[: len(full) // 2])
        before = p.read_bytes()
        parse_file(p)
        self.assertEqual(p.read_bytes(), before)

    def test_directory_instead_of_file(self):
        self.assertTrue(parse_file(self.tmp()).errors)


class RealNmapOutput(unittest.TestCase):
    """Fixtures captured from a real Nmap 7.94 scanning this machine's own loopback.
    (The build sandbox has no IPv6, so IPv6 parsing is covered by hand-written XML above.)"""

    def test_real_localhost_scan(self):
        r = parse_file(FIX / "real_localhost.xml")
        self.assertTrue(r.complete)
        self.assertEqual(r.errors, [])
        self.assertEqual(r.hosts_up, 1)
        h = r.hosts[0]
        self.assertEqual(h.address, "127.0.0.1")
        self.assertEqual(h.state, "up")
        states = {p.number: p.state for p in h.ports}
        self.assertEqual(set(states), {9, 22, 8080})
        self.assertTrue(r.nmap_version.startswith("7."))

    def test_real_down_host_scan(self):
        r = parse_file(FIX / "real_down_host.xml")
        self.assertTrue(r.complete)
        self.assertEqual(r.hosts, [])
        self.assertEqual((r.hosts_up, r.hosts_total), (0, 1))
        self.assertEqual(r.hosts_down, 1)

    def test_real_file_survives_truncation_at_every_tenth_byte(self):
        data = (FIX / "real_localhost.xml").read_bytes()
        for cut in range(0, len(data) - 1, max(1, len(data) // 60)):
            with self.subTest(cut=cut):
                r = parse_bytes(data[:cut])               # must never raise
                self.assertIsInstance(r.errors, list)


if __name__ == "__main__":
    unittest.main()

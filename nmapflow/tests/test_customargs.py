import unittest

from nmapflow.customargs import ArgError, valid_port_spec, validate_custom_args


class PortSpecs(unittest.TestCase):
    def test_valid(self):
        for s in ["80", "1-1023", "22,80,443", "T:80,U:53", "-", "U:161", "T:1-100,U:53,161", "0-65535", "S:132"]:
            with self.subTest(s=s):
                self.assertTrue(valid_port_spec(s))

    def test_invalid(self):
        for s in ["", "abc", "80;ls", "70000", "5-2", "80,", ",80", "1-", "$(id)", "80 90", "T:", "99999-100000", "A:80", "-5"]:
            with self.subTest(s=s):
                self.assertFalse(valid_port_spec(s))


class AllowedArguments(unittest.TestCase):
    def test_accepted(self):
        cases = {
            "-sS -p 80,443": ["-sS", "-p", "80,443"],
            "-sT -sV --top-ports 50": ["-sT", "-sV", "--top-ports", "50"],
            "-p80": ["-p", "80"],
            "-p-": ["-p-"],
            "--top-ports=100 -sU": ["--top-ports", "100", "-sU"],
            "-PS22,80 -PA80 -PU53": ["-PS22,80", "-PA80", "-PU53"],
            "--version-intensity 3 -sV": ["--version-intensity", "3", "-sV"],
            "--max-retries 2 --host-timeout 30m": ["--max-retries", "2", "--host-timeout", "30m"],
            "--max-rate 500": ["--max-rate", "500"],
            "-sS -sC -O --traceroute --reason --open": ["-sS", "-sC", "-O", "--traceroute", "--reason", "--open"],
            "'-sV'": ["-sV"],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(validate_custom_args(text), expected)


class RejectedArguments(unittest.TestCase):
    def test_rejected_with_reason(self):
        cases = {
            "-sS --script vuln": "NSE menu",
            "--script=default": "NSE menu",
            "--script-args x=y": "not allowed",
            "-oX out.xml": "managed by the tool",
            "-oN out": "managed by the tool",
            "-oG out": "managed by the tool",
            "-oA out": "managed by the tool",
            "-iL list.txt": "targets",
            "--excludefile f": "exclusions",
            "--exclude 10.0.0.1": "exclusions",
            "10.0.0.1": "target",
            "example.com": "target",
            "-T4": "timing",
            "-T0": "timing",
            "--max-rate 5000": "1 to 1000",
            "--min-rate 100": "overwhelm",
            "-D RND:5": "decoy",
            "-S 1.2.3.4": "spoofing",
            "--spoof-mac 0": "spoofing",
            "-f": "fragmentation",
            "--mtu 8": "fragmentation",
            "--badsum": "checksum",
            "-sI zombie": "idle",
            "-b ftp": "bounce",
            "--datadir /tmp": "data directory",
            "--resume x": "resume",
            "--interactive": "interactive",
            "--privileged": "not supported",
            "-6": "automatically",
            "-p 70000": "valid port",
            "--top-ports 0": "1 to 65535",
            "--version-intensity 10": "0 to 9",
            "--host-timeout banana": "valid time",
            "-p": "needs a value",
            "-PS99999": "invalid port",
            "--unknown-flag": "allowed",
            "-x": "allowed",
            "": "no arguments",
            "   ": "no arguments",
            "-sS 'unterminated": "could not read",
        }
        for text, reason in cases.items():
            with self.subTest(text=text):
                with self.assertRaises(ArgError) as cm:
                    validate_custom_args(text)
                self.assertIn(reason.lower(), str(cm.exception).lower())

    def test_shell_metacharacters_are_just_rejected_text(self):
        for text in ["-sS; rm -rf /", "-sS | cat", "-sS && id", "-sS `id`", "-sS $(id)", "-sS > /etc/x"]:
            with self.subTest(text=text):
                with self.assertRaises(ArgError):
                    validate_custom_args(text)

    def test_too_many_arguments(self):
        with self.assertRaises(ArgError):
            validate_custom_args(" ".join(["-sS"] * 41))


if __name__ == "__main__":
    unittest.main()

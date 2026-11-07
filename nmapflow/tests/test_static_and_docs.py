"""Static safety checks on the source code, and checks that README / PROFILES.md / TESTING.md / DEBUGGING.md
describe the code that is actually shipped."""

import ast
import importlib
import json
import pkgutil
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import nmapflow
from nmapflow import cli
from nmapflow import config as config_mod
from nmapflow import nse as nse_mod
from nmapflow import profiles as P

from .helpers import LabTestCase

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "nmapflow"
SOURCES = sorted(PKG.glob("*.py")) + [ROOT / "nmapflow.py"]
README = (ROOT / "README.md").read_text(encoding="utf-8")
TESTING = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf-8")
DEBUGGING = (ROOT / "docs" / "DEBUGGING.md").read_text(encoding="utf-8")


def calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class StaticSafety(unittest.TestCase):
    def trees(self):
        for path in SOURCES:
            yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))

    def test_no_dangerous_calls(self):
        banned = {"eval", "exec", "compile", "__import__", "os.system", "os.popen", "os.spawnl", "os.spawnv", "os.execv", "os.execl",
                  "subprocess.getoutput", "subprocess.getstatusoutput", "pickle.load", "pickle.loads", "marshal.loads", "yaml.load"}
        for path, tree in self.trees():
            for c in calls(tree):
                name = dotted(c.func)
                with self.subTest(file=path.name, call=name):
                    self.assertNotIn(name, banned)

    def test_no_shell_true_anywhere(self):
        for path, tree in self.trees():
            for c in calls(tree):
                for kw in c.keywords:
                    if kw.arg == "shell":
                        self.fail(f"{path.name}:{c.lineno} passes shell=")
        for path in SOURCES:
            self.assertNotIn("shell=True", path.read_text(encoding="utf-8"))

    def test_subprocess_calls_get_argument_lists(self):
        for path, tree in self.trees():
            for c in calls(tree):
                if dotted(c.func) in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "subprocess.check_call"):
                    first = c.args[0] if c.args else None
                    with self.subTest(file=path.name, line=c.lineno):
                        self.assertIsNotNone(first)
                        self.assertNotIsInstance(first, (ast.Constant, ast.JoinedStr, ast.BinOp))
                        if isinstance(first, ast.Call):
                            self.assertNotEqual(dotted(first.func), "str.format")

    def test_subprocess_is_confined_to_three_modules(self):
        users = set()
        for path, tree in self.trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and dotted(node.func).startswith("subprocess.") and dotted(node.func) != "subprocess.list2cmdline":
                    if dotted(node.func) in ("subprocess.run", "subprocess.Popen"):
                        users.add(path.name)
        self.assertEqual(users, {"runner.py", "netdetect.py", "cli.py"})

    def test_nmap_output_options_are_only_assembled_in_the_planner(self):
        allowed = {"planner.py", "customargs.py"}                                  # customargs only lists them as forbidden
        for path in SOURCES:
            text = path.read_text(encoding="utf-8")
            if '"-oX"' in text:
                self.assertIn(path.name, allowed, path.name)
        self.assertIn('"-oX", xml_path', (PKG / "planner.py").read_text())

    def test_standard_library_only(self):
        stdlib = set(sys.stdlib_module_names)
        for path, tree in self.trees():
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    mods = [node.module.split(".")[0]]
                for m in mods:
                    with self.subTest(file=path.name, module=m):
                        self.assertTrue(m in stdlib or m == "nmapflow", f"{m} is not part of the standard library")
        self.assertFalse((ROOT / "requirements.txt").exists())

    def test_syntax_is_python_310_compatible_and_modules_import(self):
        for info in pkgutil.iter_modules(nmapflow.__path__):
            with self.subTest(module=info.name):
                importlib.import_module(f"nmapflow.{info.name}")

    def test_launchers(self):
        for argv in ([sys.executable, "nmapflow.py", "--version"], [sys.executable, "-m", "nmapflow", "--version"]):
            with self.subTest(argv=argv[1:]):
                r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), "nmapflow 1.0.0")

    def test_launcher_has_python_version_guard(self):
        self.assertIn("(3, 10)", (ROOT / "nmapflow.py").read_text())


class Documentation(unittest.TestCase):
    def test_profiles_md_is_exactly_the_generated_catalog(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "p.md"
            P.export_markdown(out)
            self.assertEqual((ROOT / "docs" / "PROFILES.md").read_text(encoding="utf-8"), out.read_text(encoding="utf-8"))

    def test_profile_counts_everywhere(self):
        n = len(P.catalog())
        for name, text in (("README", README), ("TESTING", TESTING)):
            found = re.findall(r"\b(\d{3}) (?:scan )?profiles", text)
            self.assertTrue(found, name)
            for f in found:
                self.assertEqual(int(f), n, name)
        self.assertIn(f"Total profiles: {n}", (ROOT / "docs" / "PROFILES.md").read_text())

    def test_nse_counts(self):
        self.assertIn(f"{len(nse_mod.catalog())} NSE entries", README)
        self.assertEqual(nse_mod.by_number(47).name, "HTTP bundle")
        self.assertEqual(nse_mod.by_number(48).name, "TLS bundle")
        self.assertIn("nse> 47,48", README)

    def test_readme_module_table_matches_the_package(self):
        documented = set(re.findall(r"^\| `([a-z_]+\.py)` \|", README, re.M))
        actual = {p.name for p in PKG.glob("*.py")} - {"__init__.py", "__main__.py"}
        self.assertEqual(documented, actual)

    def test_readme_cli_options_match_the_parser(self):
        parser = cli.build_arg_parser()
        options = {o for a in parser._actions for o in a.option_strings if o.startswith("--") and o != "--help"}
        block = "\n".join(re.findall(r"```bash\n(.*?)```", README, re.S))
        documented = set(re.findall(r"(--[a-z-]+)", block)) - {"--break-system-packages"}
        self.assertEqual(documented, options)

    def test_readme_settings_match_the_config(self):
        section = README.split("## Settings", 1)[1].split("##", 1)[0]
        fields = set(config_mod.Config.__dataclass_fields__)
        mentioned = {n for n in re.findall(r"`([a-z0-9_]+)`", section) if "_" in n or n in fields}
        self.assertEqual(mentioned, fields)

    def test_readme_install_and_requirements(self):
        self.assertIn("sudo apt update && sudo apt install -y nmap iproute2", README)
        self.assertIn("3.10", README)
        self.assertIn("sudo python3 nmapflow.py", README)
        self.assertIn("python3 nmapflow.py --list-profiles", README)
        self.assertIn("sudo apt update && sudo apt install -y nmap", (PKG / "cli.py").read_text(encoding="utf-8"))

    def test_documented_defaults_match_the_code(self):
        c = config_mod.Config()
        self.assertIn(f"`timing` ({c.timing})", README)
        self.assertIn(f"`concurrency` ({c.concurrency}, max {config_mod.MAX_CONCURRENCY})", README)
        self.assertIn(f"`timeout_minutes` ({c.timeout_minutes}, 0 = none)", README)
        self.assertIn(f"`output_dir` (`{c.output_dir}`)", README)

    def test_referenced_modules_and_tests_exist(self):
        test_modules = {i.name: importlib.import_module(f"tests.{i.name}") for i in pkgutil.iter_modules([str(ROOT / "tests")])
                        if i.name.startswith("test_")}
        for text in (README, TESTING, DEBUGGING):
            for token in set(re.findall(r"`(test_\w+(?:\.\w+)*)`", text)):
                parts = token.split(".")
                with self.subTest(ref=token):
                    if parts[0] in test_modules:
                        if len(parts) == 2 and parts[1] == "py":
                            continue
                        mod = test_modules[parts[0]]
                        if len(parts) >= 2:
                            self.assertTrue(hasattr(mod, parts[1]), f"{parts[0]}.{parts[1]}")
                        if len(parts) == 3:
                            self.assertTrue(hasattr(getattr(mod, parts[1]), parts[2]), token)
                    elif len(parts) == 1:        # a bare test method name
                        self.assertTrue(any(hasattr(c, parts[0]) for m in test_modules.values() for c in vars(m).values()
                                            if isinstance(c, type) and issubclass(c, unittest.TestCase)), token)
                    else:
                        self.fail(f"unknown test reference {token}")
        for mod in set(re.findall(r"`([a-z_]+\.py)`", README)):
            self.assertTrue((PKG / mod).exists() or (ROOT / mod).exists() or mod.startswith("test_"), mod)

    def test_testing_md_counts_match_reality(self):
        loader = unittest.TestLoader()
        total = 0
        rows = dict(re.findall(r"^\| `(test_[a-z_]+)\.py` \| (\d+) \|", TESTING, re.M))
        for info in pkgutil.iter_modules([str(ROOT / "tests")]):
            if not info.name.startswith("test_"):
                continue
            n = loader.loadTestsFromName(f"tests.{info.name}").countTestCases()
            total += n
            with self.subTest(file=info.name):
                self.assertEqual(int(rows.get(info.name, -1)), n, f"TESTING.md lists {rows.get(info.name)} tests for {info.name}, found {n}")
        self.assertEqual(set(rows), {i.name for i in pkgutil.iter_modules([str(ROOT / 'tests')]) if i.name.startswith("test_")})
        stated = set(re.findall(r"\*\*(\d+) tests", TESTING))
        self.assertEqual(stated, {str(total)}, f"TESTING.md states {stated}, actual total {total}")
        self.assertIn(f"{total} tests;", README)

    def test_debugging_md_examples_are_valid(self):
        self.assertIsNotNone(P.by_id("REQ-05-TCP-TOP1000-ACK-SV"))
        for opt in re.findall(r"nmapflow\.py (--[a-z-]+)", DEBUGGING):
            self.assertIn(opt, {o for a in cli.build_arg_parser()._actions for o in a.option_strings})
        self.assertIn("script.db", DEBUGGING)

    def test_documented_codes_and_messages_exist_in_the_source(self):
        src = "\n".join(p.read_text(encoding="utf-8") for p in SOURCES)
        for text in ("Nmap was not found.", "Rejected input (these will NOT be scanned)", "No host responded", "Only ",
                     "Type AUTHORIZED to confirm", "Type RUN", "xml:", "Settings: "):
            self.assertIn(text, src)
        for text in ("Nmap output (XML) is incomplete", "needs root privileges", "script not available and not run"):
            self.assertIn(text, src)
        self.assertIn("_GRACE_INT, _GRACE_TERM = 8.0, 4.0", src)                      # DEBUGGING.md: SIGINT, +8 s SIGTERM, +4 s SIGKILL


class SessionFilesMatchDocumentation(LabTestCase):
    def test_every_file_named_in_the_docs_is_really_produced(self):
        from nmapflow.report_html import write_report
        from nmapflow.report_xml import write_xml
        lab = self.lab()
        ts = lab.targets("10.0.0.5")
        plan = lab.plan(ts, [self.profile("REQ-09-TCP-ALL-CONNECT")])
        s, _ = lab.run(plan, ts)
        write_xml(s)
        write_report(s)
        top = {p.name for p in s.dir.iterdir()}
        self.assertEqual(top - {".lock"}, {"report.html", "session.xml", "session.json", "session.log", "tasks"})
        task_files = {p.name for p in (s.dir / plan.tasks[0].task_dir).iterdir()}
        self.assertEqual(task_files, {"scan.xml", "scan.nmap", "command.txt", "stdout.log", "stderr.log", "meta.json"})
        for name in task_files | top:
            if name in (".lock", "tasks"):
                continue
            self.assertTrue(name in README or name in DEBUGGING, name)
        data = json.loads((s.dir / "session.json").read_text())
        for key in ("xml_sha256", "status", "exit_code", "error"):
            self.assertIn(key, data["tasks"][0])
            self.assertIn(key, DEBUGGING if key == "xml_sha256" else DEBUGGING + README + TESTING + "status exit_code error")


if __name__ == "__main__":
    unittest.main()

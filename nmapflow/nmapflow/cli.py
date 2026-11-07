"""Interactive terminal interface and command-line entry point."""

from __future__ import annotations

import argparse
import dataclasses
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from . import config as config_mod
from . import nse as nse_mod
from . import privileges, profiles as prof_mod
from .config import MAX_CONCURRENCY, Config
from .customargs import ArgError
from .models import COMPLETED, SKIPPED, ScanProfile, ScanTask
from .netdetect import detect_subnets
from .nse import Availability, NseSelection
from .planner import Plan, PlanOptions, build_plan, display_command
from .report_html import write_report
from .report_xml import write_xml
from .runner import Executor
from .session import AUTH_STATEMENT, Session, SessionError, list_sessions
from .targets import TargetSet, load_target_file
from .utils import (TOOL_NAME, TOOL_VERSION, human_duration, setup_logger, shell_display, style)


class ExitApp(Exception):
    """Raised to leave the program (end of input or user choice)."""


class BackToMenu(Exception):
    """Raised when the user presses Ctrl+C at a prompt: abandon the current workflow."""


# ------------------------------------------------------------------ prompts
def ask(prompt: str, default: str = "") -> str:
    try:
        text = input(prompt).strip()
    except EOFError:
        print()
        raise ExitApp()
    except KeyboardInterrupt:
        print()
        raise BackToMenu()
    return text or default


def yes_no(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    answer = ask(f"{prompt} [{hint}] ").lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def hr(char: str = "-") -> None:
    print(char * min(shutil.get_terminal_size((100, 20)).columns, 100))


def wrap(text: str, indent: str = "  ") -> None:
    width = min(shutil.get_terminal_size((100, 20)).columns, 100)
    for line in textwrap.wrap(text, width=width, initial_indent=indent, subsequent_indent=indent):
        print(line)


def parse_numbers(text: str, maxnum: int) -> list[int]:
    """'4, 7,8' or '4-8' -> [4,7,8]. Raises ValueError with a readable message."""
    out: list[int] = []
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                raise ValueError(f"'{part}' is a backwards range")
            nums = range(lo, hi + 1)
        elif part.isdigit():
            nums = [int(part)]
        else:
            raise ValueError(f"'{part}' is not a number")
        for n in nums:
            if not 1 <= n <= maxnum:
                raise ValueError(f"{n} is not in the list (1-{maxnum})")
            if n not in out:
                out.append(n)
    return out


# ----------------------------------------------------------------- the app
class App:
    def __init__(self, cfg: Config, nmap_bin: str, nmap_version: str, avail: Availability,
                 cfg_path: Path) -> None:
        self.cfg, self.nmap_bin, self.nmap_version, self.avail, self.cfg_path = cfg, nmap_bin, nmap_version, avail, cfg_path
        self.privileged = privileges.is_privileged()

    # --------------------------------------------------------------- menus
    def run(self) -> int:
        print(style(f"\n{TOOL_NAME} {TOOL_VERSION}", "bold") + f"  |  Nmap {self.nmap_version}  |  "
              f"root: {'yes' if self.privileged else 'no' if self.privileged is False else 'unknown'}")
        print("For systems you own or are explicitly authorized to assess.")
        if self.privileged is False:
            wrap("Not running as root: SYN/ACK/UDP scans and OS detection will be offered but need 'sudo'. "
                 "TCP connect scans and most NSE scripts work without it.", "  ")
        while True:
            try:
                print()
                hr("=")
                print(" 1) Single host\n 2) Multiple hosts\n 3) Whole local network\n"
                      " 4) View previous scan sessions\n 5) Exit\n c) Settings")
                hr("=")
                choice = ask("Select: ").lower()
                if choice == "1":
                    self.new_scan("single")
                elif choice == "2":
                    self.new_scan("multiple")
                elif choice == "3":
                    self.new_scan("network")
                elif choice == "4":
                    self.view_sessions()
                elif choice in ("5", "q", "exit", "quit"):
                    return 0
                elif choice == "c":
                    self.settings_menu()
                else:
                    print("Please enter 1-5 (or c for settings).")
            except BackToMenu:
                print("Cancelled; back at the main menu.")
            except ExitApp:
                return 0

    # ------------------------------------------------------------- targets
    def get_targets(self, mode: str) -> TargetSet | None:
        ts = TargetSet()
        if mode == "single":
            while True:
                text = ask("Target (one IPv4/IPv6 address or hostname, blank to cancel): ")
                if not text:
                    return None
                if len(text.split()) != 1:
                    print("Please enter exactly one target. Use option 2 for several.")
                    continue
                trial = TargetSet()
                trial.add([text])
                if trial.errors:
                    print("  Rejected: " + trial.errors[0])
                    continue
                if trial.targets[0].kind not in ("ip", "hostname") or len(trial.targets) != 1:
                    print("That is a range. Use option 2 (multiple hosts) or 3 (network) for ranges.")
                    continue
                ts = trial
                break
        elif mode == "multiple":
            print("Enter targets separated by spaces, e.g.  192.168.10.2 192.168.10.5 host.example")
            print("Also accepted: CIDR (10.0.0.0/24), ranges (192.168.10.2-20), and @file.txt to import a list.")
            while True:
                line = ask("Targets (blank to cancel): ")
                if not line:
                    return None
                trial = TargetSet()
                tokens: list[str] = []
                for tok in re.split(r"[\s,]+", line):
                    if not tok:
                        continue
                    if tok.startswith("@"):
                        ftoks, problems = load_target_file(tok[1:])
                        trial.errors.extend(problems)
                        tokens.extend(ftoks)
                    else:
                        tokens.append(tok)
                trial.add(tokens)
                if trial.errors:
                    print(style("Rejected input (these will NOT be scanned):", "yellow"))
                    for err in trial.errors:
                        print("  - " + err)
                    if not trial.targets or not yes_no("Continue with the valid targets only?", False):
                        continue
                if not trial.targets:
                    continue
                ts = trial
                break
        else:  # network
            subnets, msg = detect_subnets()
            if msg:
                print(msg)
            print("Detected local IPv4 subnets (nothing has been scanned):")
            for i, s in enumerate(subnets, 1):
                print(f"  {i}) {s.network:<18} interface {s.interface:<10} address {s.address}" + (f"  [{s.note}]" if s.note else ""))
            print("  m) enter a CIDR range manually")
            while True:
                pick = ask("Select a subnet number, or m (blank to cancel): ").lower()
                if not pick:
                    return None
                cidr = ""
                if pick == "m":
                    cidr = ask("CIDR range (e.g. 192.168.10.0/24): ")
                elif pick.isdigit() and 1 <= int(pick) <= len(subnets):
                    cidr = subnets[int(pick) - 1].network
                else:
                    print("Please choose one of the listed numbers or m.")
                    continue
                trial = TargetSet()
                trial.add([cidr], "subnet")
                if trial.errors or not trial.targets or trial.targets[0].kind != "cidr":
                    print("  Rejected: " + (trial.errors[0] if trial.errors else "not a CIDR range"))
                    continue
                ts = trial
                break
        ex = ask("Targets to EXCLUDE (optional, same syntax; blank for none): ")
        if ex:
            ts.add_exclusions(re.split(r"[\s,]+", ex.strip()))
            for err in [x for x in ts.errors if x.startswith("exclusion")]:
                print("  Rejected " + err)
        print("Resolving hostnames...")
        ts.resolve(self.cfg.prefer_ipv6)
        return ts

    def confirm_scope(self, ts: TargetSet) -> bool:
        print()
        hr("=")
        print(style("SCOPE CONFIRMATION", "bold"))
        hr("=")
        print(f"Entered:   {', '.join(ts.originals)}")
        shown = [f"{t.normalized}" + (f" -> {', '.join(t.resolved)}" if t.resolved else "") for t in ts.targets]
        print(f"Targets:   {len(ts.targets)} entries, about {ts.total_addresses()} address(es), families: {', '.join(ts.families())}")
        for line in shown[:15]:
            print("   - " + line)
        if len(shown) > 15:
            print(f"   ... and {len(shown) - 15} more")
        if ts.exclusions:
            print("Excluded:  " + ", ".join(e.normalized for e in ts.exclusions))
        for w in dict.fromkeys(ts.warnings):
            print(style("Warning:   " + w, "yellow"))
        for reason in ts.extra_confirmation_reasons():
            print()
            wrap(style("ATTENTION: ", "red", "bold") + reason, "")
            if ask("Type YES to include this in the scope: ") != "YES":
                print("Not confirmed; scan cancelled.")
                return False
        print()
        wrap(AUTH_STATEMENT, "")
        answer = ask("Type AUTHORIZED to confirm (anything else cancels): ")
        if answer != "AUTHORIZED":
            print("Not confirmed; nothing was scanned.")
            return False
        return True

    # ------------------------------------------------------------ profiles
    def select_profiles(self) -> tuple[list[ScanProfile], list[str]] | None:
        selected: list[ScanProfile] = []
        opt_in: list[str] = []
        cats = prof_mod.categories()
        defaults = [prof_mod.by_id(i) for i in self.cfg.default_profiles]
        defaults = [d for d in defaults if d]
        print()
        hr("=")
        print(style("SCAN PROFILES", "bold") + f"  ({len(prof_mod.catalog())} available)")
        hr("=")
        if defaults and yes_no(f"Use your {len(defaults)} default profile(s) ({', '.join(d.id for d in defaults)})?", True):
            return defaults, opt_in
        self._print_categories(cats)
        self._profile_help()
        while True:
            line = ask(f"[{len(selected)} selected] profiles> ")
            low = line.lower()
            try:
                if low in ("done", "d"):
                    return selected, opt_in
                if low in ("quit", "q", "back"):
                    return None
                if low in ("help", "?", "h"):
                    self._profile_help()
                elif low in ("cats", "categories"):
                    self._print_categories(cats)
                elif low == "clear":
                    selected.clear()
                    opt_in.clear()
                elif low in ("none", "skip"):
                    selected.clear()
                    return selected, opt_in
                elif low.startswith(("list ", "l ")) or re.fullmatch(r"l\d+|list", low):
                    arg = re.sub(r"^(list|l)\s*", "", low)
                    if arg in ("", "all"):
                        self._print_profiles(prof_mod.catalog(), selected)
                    else:
                        idx = int(arg)
                        if not 1 <= idx <= len(cats):
                            raise ValueError(f"category must be 1-{len(cats)}")
                        self._print_profiles(prof_mod.in_category(cats[idx - 1][0]), selected)
                elif re.fullmatch(r"c\d+", low):
                    idx = int(low[1:])
                    if not 1 <= idx <= len(cats):
                        raise ValueError(f"category must be 1-{len(cats)}")
                    key = cats[idx - 1][0]
                    if key == "custom":
                        print("Custom profiles need details. Type 'custom'.")
                        continue
                    for p in prof_mod.in_category(key):
                        self._add_profile(p, selected, opt_in, quiet=True)
                    print(f"Added category '{cats[idx - 1][1]}'. {len(selected)} profile(s) selected.")
                elif low.startswith("show "):
                    for n in parse_numbers(low[5:], len(prof_mod.catalog())):
                        print(prof_mod.render(prof_mod.by_number(n)))
                elif low.startswith("/"):
                    results = prof_mod.search(low[1:])
                    if not results:
                        print("No match.")
                    else:
                        self._print_profiles(results, selected)
                elif low.startswith(("remove ", "rm ")):
                    nums = parse_numbers(low.split(None, 1)[1], len(prof_mod.catalog()))
                    selected[:] = [p for p in selected if p.number not in nums]
                elif low == "custom":
                    p = self._custom_profile()
                    if p:
                        self._add_profile(p, selected, opt_in)
                elif low:
                    for n in parse_numbers(low, len(prof_mod.catalog())):
                        p = prof_mod.by_number(n)
                        if p.custom:
                            p = self._custom_profile(p.custom)
                            if not p:
                                continue
                        self._add_profile(p, selected, opt_in)
            except ArgError as exc:
                print("  Rejected: " + str(exc))
            except ValueError as exc:
                print("  " + str(exc))

    def _profile_help(self) -> None:
        print("Commands: numbers (4  or  4,7,8  or  4-8) add profiles | cN add a whole category | lN list category N | list all\n"
              "          show N (exact Nmap arguments) | /text search | custom | remove N | clear | none | done")

    def _print_categories(self, cats) -> None:
        for i, (key, name, count) in enumerate(cats, 1):
            print(f"  c{i:<3}{name} ({count})")

    def _print_profiles(self, profs: list[ScanProfile], selected: list[ScanProfile]) -> None:
        ids = {p.id for p in selected}
        for p in profs:
            mark = "*" if p.id in ids else " "
            root = " root" if p.needs_root else "     "
            print(f"{mark}{p.number:>4}. {p.name[:62]:<62} {p.risk:<9}{root}  {p.duration}")

    def _add_profile(self, p: ScanProfile, selected: list[ScanProfile], opt_in: list[str], quiet: bool = False) -> None:
        if any(x.id == p.id for x in selected):
            return
        if p.opt_in:
            print()
            wrap(style("OPT-IN REQUIRED: ", "red", "bold") + p.opt_in, "")
            if ask(f"Type YES to include '{p.name}': ") != "YES":
                print("Not added.")
                return
            opt_in.append(p.id)
        selected.append(p)
        if not quiet:
            print(f"  + {p.name}  [{p.risk}, {p.duration}{', needs root' if p.needs_root else ''}]")
        for w in p.warnings:
            print(style("    ! " + w, "yellow"))

    def _custom_profile(self, kind: str = "") -> ScanProfile | None:
        if not kind:
            print("  1) Custom port-range scan\n  2) Custom Nmap arguments")
            kind = {"1": "ports", "2": "args"}.get(ask("Select: "), "")
            if not kind:
                return None
        if kind == "ports":
            proto = ask("Protocol: tcp or udp [tcp]: ", "tcp").lower()
            if proto not in ("tcp", "udp"):
                print("Choose tcp or udp.")
                return None
            tech = "-sS"
            if proto == "tcp":
                choice = ask("Technique: 1) SYN (-sS)  2) connect (-sT)  3) ACK (-sA)  4) window (-sW) [1]: ", "1")
                tech = {"1": "-sS", "2": "-sT", "3": "-sA", "4": "-sW"}.get(choice)
                if not tech:
                    print("Unknown choice.")
                    return None
            ports = ask("Ports (examples: 80 | 1-1023 | 22,80,443 | - for all): ")
            adds = ask("Add-ons (any of -sV -sC -O, space separated, blank for none): ")
            addons = adds.split() if adds else []
            return prof_mod.make_custom_ports(proto, tech, ports, addons)
        text = ask("Nmap options (no targets, no -T, no scripts): ")
        return prof_mod.make_custom_args(text)

    # ---------------------------------------------------------------- NSE
    def select_nse(self) -> NseSelection | None:
        sel = NseSelection()
        entries = nse_mod.catalog()
        print()
        hr("=")
        print(style("NSE SCRIPTS (optional, run as their own scans)", "bold"))
        hr("=")
        wrap("NSE scripts are small probes that run against ports Nmap has found. They are independent of the scan profiles above: "
             "you can run scripts alone or together with profiles. Only safe, non-intrusive scripts are offered; "
             "brute, dos, exploit, fuzzer, intrusive, external and broadcast scripts never run.", "")
        for w in self.avail.messages:
            print(style("Note: " + w, "yellow"))
        defaults = [nse_mod.by_id(i) for i in self.cfg.default_nse]
        defaults = [d for d in defaults if d]
        if defaults and yes_no(f"Use your default NSE selection ({', '.join(d.id for d in defaults)})?", True):
            return NseSelection(defaults, [d.id for d in defaults if d.opt_in])
        if self.avail.db is None:
            print("NSE selection is unavailable because Nmap's script database was not found.")
            return sel
        if not yes_no("Add NSE scripts?", False):
            return sel
        self._print_nse(entries, sel)
        print("Commands: numbers (4,7,8 or 6-11) | show N | list | clear | none | done")
        while True:
            line = ask(f"[{len(sel.entries)} selected] nse> ")
            low = line.lower()
            try:
                if low in ("done", "d"):
                    return sel
                if low in ("none", "skip"):
                    return NseSelection()
                if low in ("quit", "q", "back"):
                    return None
                if low == "clear":
                    sel.entries.clear()
                    sel.confirmed_opt_in.clear()
                elif low in ("list", "l"):
                    self._print_nse(entries, sel)
                elif low.startswith("show "):
                    for n in parse_numbers(low[5:], len(entries)):
                        self._show_nse(entries[n - 1])
                elif low:
                    for n in parse_numbers(low, len(entries)):
                        self._add_nse(entries[n - 1], sel)
            except ValueError as exc:
                print("  " + str(exc))

    def _print_nse(self, entries, sel: NseSelection) -> None:
        chosen = {e.id for e in sel.entries}
        kind = ""
        for e in entries:
            if e.kind != kind:
                kind = e.kind
                print(style({"category": "Categories", "script": "Individual scripts", "bundle": "Bundles"}[kind], "bold"))
            ok, why = self.avail.check(e)
            mark = "*" if e.id in chosen else " "
            flag = ""
            if not ok:
                flag = style("  [unavailable]", "red")
            elif e.opt_in:
                flag = style("  [opt-in: intrusive-labelled]", "yellow")
            ports = ""
            if e.kind != "category":
                ports = "  ports " + ", ".join(x for x in [f"T:{e.tcp_ports}" if e.tcp_ports else "", f"U:{e.udp_ports}" if e.udp_ports else ""] if x)
            print(f"{mark}{e.num:>3}. {e.name:<24} {e.risk:<16}{ports}{flag}")

    def _show_nse(self, e) -> None:
        ok, why = self.avail.check(e)
        print(f"[{e.num}] {e.name} ({e.kind})")
        wrap(f"Purpose: {e.purpose}")
        wrap(f"Risk: {e.risk}. Intrusive/disruptive: {e.intrusive}.")
        if e.kind == "category":
            wrap(f"Nmap expression: {e.expression}")
        else:
            wrap(f"Scripts: {', '.join(e.scripts)}. TCP ports: {e.tcp_ports or '-'}  UDP ports: {e.udp_ports or '-'}")
        if not ok or why:
            wrap(f"Availability: {why or 'ok'}")

    def _add_nse(self, e, sel: NseSelection) -> None:
        if any(x.id == e.id for x in sel.entries):
            return
        ok, why = self.avail.check(e)
        if not ok:
            print(f"  {e.name}: not available ({why})")
            return
        if e.opt_in:
            print()
            wrap(style("OPT-IN REQUIRED: ", "red", "bold") + e.opt_in_text, "")
            if ask(f"Type YES to include {e.name}: ") != "YES":
                print("Not added.")
                return
            sel.confirmed_opt_in.append(e.id)
        sel.entries.append(e)
        print(f"  + {e.name}" + (f"  (note: {why})" if why else ""))

    # -------------------------------------------------------------- timing
    def select_timing(self) -> int:
        print()
        hr("=")
        print(style("TIMING TEMPLATE", "bold"))
        hr("=")
        wrap("Timing changes how fast Nmap sends probes and how long it waits. It affects speed and reliability, not what Nmap is able to detect.", "")
        for n, text in ((1, "Very slow"), (2, "Slow"), (3, "Normal/default"), (4, "Fast"),
                        (5, "Very aggressive; may cause inaccurate results or overwhelm fragile systems")):
            print(f"  T{n} - {text}")
        while True:
            ans = ask(f"Timing [T{self.cfg.timing}]: ").lower().lstrip("t")
            if not ans:
                return self.cfg.timing
            if ans.isdigit() and 1 <= int(ans) <= 5:
                if int(ans) == 5 and not yes_no("T5 can miss open ports and disturb fragile devices. Use it anyway?", False):
                    continue
                return int(ans)
            print("Enter 1-5.")

    # --------------------------------------------------------- run options
    def run_options(self) -> Config:
        cfg = dataclasses.replace(self.cfg)
        while True:
            print()
            hr("=")
            print(style("RUN OPTIONS", "bold"))
            hr("=")
            print(f"  concurrency          {cfg.concurrency}  (parallel scans on DIFFERENT hosts; max {MAX_CONCURRENCY})")
            print(f"  host discovery       {'on' if cfg.host_discovery else 'off (-Pn: treat every target as up)'}")
            print(f"  resolve DNS names    {'yes' if cfg.resolve_dns else 'no (-n)'}")
            print(f"  per-scan timeout     {cfg.timeout_minutes} min (0 = none)")
            print(f"  hosts per task       {cfg.hosts_per_task} (0 = automatic)")
            print(f"  output folder        {cfg.output_path()}")
            if not yes_no("Change any of these for this run?", False):
                return cfg
            cfg = self._edit_settings(cfg, include_defaults=False)
            if yes_no("Save these as your defaults?", False):
                self.cfg = dataclasses.replace(cfg, timing=self.cfg.timing,
                                               default_profiles=self.cfg.default_profiles, default_nse=self.cfg.default_nse)
                self._save_config()

    def _edit_settings(self, cfg: Config, include_defaults: bool) -> Config:
        def edit(name: str, label: str, kind: str = "text") -> None:
            cur = getattr(cfg, name)
            raw = ask(f"{label} [{cur}]: ")
            if not raw:
                return
            if kind == "bool":
                raw_v: object = raw.lower() in ("y", "yes", "true", "on", "1")
            elif kind == "list":
                raw_v = [x for x in re.split(r"[,\s]+", raw) if x] if raw.lower() != "none" else []
            else:
                raw_v = raw
            v, err = config_mod._coerce(name, raw_v, cur)
            if err:
                print("  " + err)
            else:
                setattr(cfg, name, v)
        edit("concurrency", f"Concurrency 1-{MAX_CONCURRENCY}")
        edit("host_discovery", "Host discovery (yes/no)", "bool")
        edit("resolve_dns", "Resolve DNS names (yes/no)", "bool")
        edit("timeout_minutes", "Per-scan timeout in minutes (0 = none)")
        edit("hosts_per_task", "Hosts per task (0 = automatic)")
        if include_defaults:
            edit("timing", "Default timing 1-5")
            edit("output_dir", "Output folder")
            edit("prefer_ipv6", "Prefer IPv6 for dual-stack hostnames (yes/no)", "bool")
            edit("default_profiles", "Default profile IDs (comma separated, 'none' to clear)", "list")
            edit("default_nse", "Default NSE entry IDs (comma separated, 'none' to clear)", "list")
            edit("nse_category_udp_top_ports", "UDP top-N ports for NSE category tasks (0 = TCP only)")
        return cfg

    def settings_menu(self) -> None:
        print()
        hr("=")
        print(style("SETTINGS", "bold") + f"  ({self.cfg_path})")
        hr("=")
        for k, v in dataclasses.asdict(self.cfg).items():
            print(f"  {k:<28}{v}")
        if yes_no("Edit settings?", False):
            self.cfg = self._edit_settings(dataclasses.replace(self.cfg), include_defaults=True)
            self._save_config()

    def _save_config(self) -> None:
        try:
            p = config_mod.save(self.cfg, self.cfg_path)
            print(f"Saved settings to {p}")
        except OSError as exc:
            print(f"Could not save settings: {exc}")

    # ---------------------------------------------------------- new session
    def new_scan(self, mode: str) -> None:
        ts = self.get_targets(mode)
        if ts is None or ts.is_empty():
            return
        if not self.confirm_scope(ts):
            return
        picked = self.select_profiles()
        if picked is None:
            return
        profiles, opt_in = picked
        sel = self.select_nse()
        if sel is None:
            return
        if not profiles and sel.is_empty():
            print("Nothing selected: choose at least one profile or NSE script.")
            return
        timing = self.select_timing()
        cfg = self.run_options()
        cfg.timing = timing
        opts = PlanOptions(timing=timing, host_discovery=cfg.host_discovery, resolve_dns=cfg.resolve_dns,
                           concurrency=cfg.concurrency, hosts_per_task=cfg.hosts_per_task,
                           prefer_ipv6=cfg.prefer_ipv6, nse_category_udp_top_ports=cfg.nse_category_udp_top_ports,
                           privileged=self.privileged)
        plan = build_plan(ts, profiles, sel, self.avail, opts, opt_in)
        if not plan.tasks:
            for w in plan.warnings:
                print("  " + w)
            return
        if not self._handle_duplicates(plan) or not self._handle_privileges(plan):
            return
        if not self._review_plan(plan, ts, cfg):
            return
        self._execute(plan, ts, cfg, profiles, sel, opt_in)

    def _handle_duplicates(self, plan: Plan) -> bool:
        if not plan.duplicates:
            return True
        print(style(f"\n{len(plan.duplicates)} task(s) are identical to an earlier task (same options and targets):", "yellow"))
        for dup, orig in plan.duplicates:
            print(f"  task {dup} duplicates task {orig}")
        ans = ask("[k]eep only the first of each (duplicates recorded as skipped), [a]ll anyway, [q]uit: ", "k").lower()
        if ans == "q":
            return False
        if ans.startswith("k"):
            by = {t.task_id: t for t in plan.tasks}
            for dup, orig in plan.duplicates:
                by[dup].status = SKIPPED
                by[dup].skip_reason = f"duplicate of task {orig}"
        return True

    def _handle_privileges(self, plan: Plan) -> bool:
        needs = [t for t in plan.tasks if t.needs_root and t.status == "pending"]
        if not needs or self.privileged is not False:
            if needs and self.privileged is None:
                print("Note: root status cannot be determined on this platform; scans needing raw sockets may fail.")
            return True
        print(style(f"\n{len(needs)} task(s) need root, and you are not running as root:", "yellow"))
        for t in needs[:12]:
            print(f"  task {t.task_id}: {t.label}  ({'; '.join(t.root_reasons[:1])})")
        if len(needs) > 12:
            print(f"  ... and {len(needs) - 12} more")
        print("Restart with:  sudo python3 nmapflow.py")
        ans = ask("[s]kip those tasks (recorded as skipped), [r]un anyway (Nmap will report errors), [q]uit: ", "q").lower()
        if ans.startswith("s"):
            for t in needs:
                t.status, t.skip_reason = SKIPPED, "needs root privileges; tool was not run as root"
            if not any(t.status == "pending" for t in plan.tasks):
                print("Every selected scan needs root, so nothing is left to run. Restart with sudo.")
                return False
            return True
        return ans.startswith("r")

    def _review_plan(self, plan: Plan, ts: TargetSet, cfg: Config) -> bool:
        while True:
            print()
            hr("=")
            print(style("SCAN PLAN - REVIEW", "bold"))
            hr("=")
            for w in dict.fromkeys(plan.warnings):
                print(style("Note: " + w, "yellow"))
            width = min(shutil.get_terminal_size((100, 20)).columns, 100)
            for t in plan.tasks:
                state = "" if t.status == "pending" else style(f" [{t.status.upper()}: {t.skip_reason or t.error}]", "yellow")
                print(f"\n{t.task_id:>3}. {t.label}{state}")
                print(f"     risk {t.risk} | duration {t.duration} | root {'yes' if t.needs_root else 'no'}")
                if t.status == "pending":
                    cmd = shell_display(display_command(t))
                    for line in textwrap.wrap("command: " + cmd, width=width - 5, subsequent_indent="         "):
                        print("     " + line)
                for w in t.warnings:
                    for line in textwrap.wrap("! " + w, width=width - 5, subsequent_indent="  "):
                        print(style("     " + line, "yellow"))
            pending = [t for t in plan.tasks if t.status == "pending"]
            print()
            hr()
            print(f"{len(pending)} scan(s) will run | targets: {len(ts.targets)} entries (~{ts.total_addresses()} addresses) | "
                  f"timing T{cfg.timing} | concurrency {cfg.concurrency} | timeout {cfg.timeout_minutes} min")
            if not pending:
                print("Nothing left to run.")
                return False
            cmd = ask("Type RUN to start | r N,M remove tasks | b/q cancel: ")
            low = cmd.lower()
            if cmd == "RUN":
                return True
            if low in ("b", "q", "back", "quit", "cancel"):
                print("Cancelled; nothing was scanned.")
                return False
            if low.startswith("r "):
                try:
                    for n in parse_numbers(low[2:], len(plan.tasks)):
                        t = plan.tasks[n - 1]
                        if t.status == "pending":
                            t.status, t.skip_reason = SKIPPED, "removed by user at plan review"
                except ValueError as exc:
                    print("  " + str(exc))
            else:
                print("Type RUN (capital letters) to start.")

    # ------------------------------------------------------------ execution
    def _execute(self, plan: Plan, ts: TargetSet, cfg: Config, profiles: list[ScanProfile],
                 sel: NseSelection, opt_in: list[str]) -> None:
        out_dir = cfg.output_path()
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            free = shutil.disk_usage(out_dir).free
            if free < 100 * 1024 * 1024:
                print(f"Only {free // (1024 * 1024)} MB free in {out_dir}; at least 100 MB is required.")
                return
            session = Session.create(out_dir)
        except (OSError, SessionError) as exc:
            print(f"Cannot create the session folder in {out_dir}: {exc}")
            return
        log = setup_logger(session.dir / "session.log")
        try:
            session.data.update({
                "nmap_version": self.nmap_version, "nmap_path": self.nmap_bin, "privileged": self.privileged,
                "config": dataclasses.asdict(cfg),
                "scope": {"originals": ts.originals, "targets": [t.to_dict() for t in ts.targets],
                          "exclusions": [t.to_dict() for t in ts.exclusions], "warnings": list(dict.fromkeys(ts.warnings))},
                "profiles": [{"id": p.id, "name": p.name, "stages": [list(s) for s in p.stages]} for p in profiles],
                "nse_selection": [e.id for e in sel.entries],
                "opt_in_confirmations": opt_in + sel.confirmed_opt_in,
                "plan_warnings": plan.warnings,
            })
            from .planner import targets_digest
            session.set_authorization("AUTHORIZED", targets_digest(ts))
            session.set_plan_confirmation(len([t for t in plan.tasks if t.status == "pending"]))
            session.tasks = plan.tasks
            session.save()
            log.info("session %s created; scope: %s", session.id, ", ".join(ts.originals))
            print(f"\nSession folder: {session.dir}")
            print("Press Ctrl+C at any time to cancel safely (partial results are kept).")
            ex = Executor(plan, session, cfg, self.nmap_bin, log, say=print, ask_cancel=self._ask_cancel)
            try:
                ex.run()
            except SessionError as exc:
                print(style(f"Refused to scan: {exc}", "red"))
                return
            self._finish(session, plan)
        finally:
            session.release()

    def _ask_cancel(self, running: list[ScanTask]) -> str:
        print(style("\n\nInterrupted.", "yellow"))
        for t in running:
            print(f"  running: task {t.task_id} {t.label}")
        while True:
            try:
                ans = ask("[c]ontinue scanning | [k] skip the running scan(s) and go on | [s]top everything (keep partial results): ", "c").lower()
            except (ExitApp, BackToMenu, EOFError, KeyboardInterrupt):
                return "stop"                  # no terminal / second Ctrl+C: stop safely, keep partial results
            if ans.startswith("c"):
                return "continue"
            if ans.startswith("k"):
                return "skip"
            if ans.startswith("s"):
                return "stop"

    def _finish(self, session: Session, plan: Plan) -> None:
        counts: dict[str, int] = {}
        for t in plan.tasks:
            counts[t.status] = counts.get(t.status, 0) + 1
        print()
        hr("=")
        print(style("SESSION FINISHED", "bold") + "  " + ", ".join(f"{n} {s.replace('_', ' ')}" for s, n in counts.items()))
        hr("=")
        try:
            xml_path = write_xml(session)
            html_path = write_report(session)
            print(f"HTML report:        {html_path}")
            print(f"Session XML:        {xml_path}   (custom format; original Nmap XML files are untouched)")
            print(f"Session folder:     {session.dir}")
        except Exception as exc:
            print(style(f"Could not build the reports: {exc}. Raw results are in {session.dir}/tasks", "red"))
        bad = [t for t in plan.tasks if t.status != COMPLETED]
        if bad:
            print(style(f"{len(bad)} scan(s) did not complete; see 'Errors and incomplete scans' in the report.", "yellow"))
        print("A completed scan does not prove a host is secure or that every vulnerability was found.")

    # ------------------------------------------------------------ sessions
    def view_sessions(self) -> None:
        base = self.cfg.output_path()
        items = list_sessions(base)
        if not items:
            print(f"No scan sessions found in {base}.")
            return
        print()
        for i, (path, data) in enumerate(items[:50], 1):
            if data is None:
                print(f"{i:>3}. {path.name}  (no readable session.json)")
                continue
            tasks = data.get("tasks", [])
            done = sum(1 for t in tasks if t.get("status") == COMPLETED)
            tg = [t.get("normalized", "") for t in (data.get("scope") or {}).get("targets", [])]
            print(f"{i:>3}. {path.name}  {done}/{len(tasks)} scans completed  targets: {', '.join(tg[:3])}{' ...' if len(tg) > 3 else ''}")
        pick = ask("Open which session? (number, blank to go back): ")
        if not pick.isdigit() or not 1 <= int(pick) <= min(50, len(items)):
            return
        path, data = items[int(pick) - 1]
        try:
            session = Session.load(path)
        except SessionError as exc:
            print(exc)
            return
        from . import aggregate
        integ = aggregate.verify_integrity(session)
        print(f"\nSession {session.id}  created {session.created}  finished {session.data.get('finished')}")
        auth = session.data.get("authorization") or {}
        print(f"Authorized by {auth.get('operator', '?')} at {auth.get('timestamp', '?')}")
        for t in session.tasks:
            print(f"  {t.task_id:>3}. [{t.status:<9}] {t.label[:60]:<60} {human_duration(t.duration_s):>9}  xml:{integ.get(t.task_id, 'n/a')}")
            if t.error or t.skip_reason:
                print(f"        {t.error or t.skip_reason}")
        print(f"Folder: {session.dir}")
        if (session.dir / "report.html").exists():
            print(f"Report: {session.dir / 'report.html'}")
        if ask("[r] rebuild HTML + session XML from the saved XML files, Enter to go back: ").lower() == "r":
            write_xml(session)
            print("Rebuilt: " + str(write_report(session)))


# -------------------------------------------------------------- entry point
def _nmap_version(nmap_bin: str) -> str:
    try:
        out = subprocess.run([nmap_bin, "--version"], capture_output=True, text=True, timeout=15, check=False).stdout
        m = re.search(r"Nmap version (\S+)", out)
        return m.group(1) if m else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Interactive Nmap automation and reporting tool. "
                                "Authorized use only. Scans always require interactive confirmation.")
    p.add_argument("--version", action="store_true", help="show the version and exit")
    p.add_argument("--list-profiles", action="store_true", help="print the scan-profile catalog with exact Nmap arguments")
    p.add_argument("--show-profile", metavar="ID_OR_NUMBER", help="print one profile in detail")
    p.add_argument("--list-nse", action="store_true", help="print the NSE catalog")
    p.add_argument("--export-catalog", metavar="FILE", help="write the profile catalog as Markdown")
    p.add_argument("--config", metavar="FILE", help="settings file (default: config.json next to the launcher)")
    p.add_argument("--reports-dir", metavar="DIR", help="output folder (overrides the setting)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.version:
        print(f"{TOOL_NAME} {TOOL_VERSION}")
        return 0
    if args.list_profiles:
        for key, name, count in prof_mod.categories():
            print(f"\n== {name} ({count}) ==")
            for p in prof_mod.in_category(key):
                print(f"{p.number:>4}. {p.id:<34} {p.risk:<9} {p.duration:<19} " + "  ->  ".join(" ".join(s) for s in p.stages))
        return 0
    if args.show_profile:
        key = args.show_profile
        p = prof_mod.by_number(int(key)) if key.isdigit() else prof_mod.by_id(key)
        if not p:
            print(f"No such profile: {key}")
            return 1
        print(prof_mod.render(p))
        return 0
    if args.export_catalog:
        prof_mod.export_markdown(Path(args.export_catalog))
        print(f"Wrote {args.export_catalog}")
        return 0
    if args.list_nse:
        for e in nse_mod.catalog():
            print(f"{e.num:>3}. {e.name:<24} {e.kind:<9} {e.risk:<16} {e.purpose}")
        return 0

    cfg_path = Path(args.config) if args.config else config_mod.DEFAULT_CONFIG_PATH
    cfg, problems = config_mod.load(cfg_path)
    for pr in problems:
        print(f"Settings: {pr}")
    if args.reports_dir:
        cfg.output_dir = args.reports_dir
    nmap_bin = cfg.nmap_path or shutil.which("nmap") or ""
    if not nmap_bin or not shutil.which(nmap_bin):
        print("Nmap was not found.\nInstall it on Kali/Debian/Ubuntu with:\n    sudo apt update && sudo apt install -y nmap\n"
              "then run this tool again. (Set 'nmap_path' in config.json if it is installed elsewhere.)", file=sys.stderr)
        return 2
    nmap_bin = shutil.which(nmap_bin) or nmap_bin
    version = _nmap_version(nmap_bin)
    avail = nse_mod.load_availability(nmap_bin)
    app = App(cfg, nmap_bin, version, avail, cfg_path)
    try:
        return app.run()
    except KeyboardInterrupt:
        print()
        return 130

"""Planner: turns targets x profiles x NSE selection into a list of ScanTasks.

Rules:
  * every requested scan becomes a task with a status; nothing is dropped silently
  * duplicates are flagged (the CLI asks what to do); they are never removed silently
  * IPv4 and IPv6 targets are separated (IPv6 needs -6)
  * with concurrency > 1 the targets are split into chunks so DIFFERENT hosts can be scanned in parallel
  * this module is pure: no disk, no network, no process launching
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import math
from dataclasses import dataclass, field

from . import nse
from .models import PENDING, ScanProfile, ScanTask
from .nse import Availability, NseSelection
from .privileges import root_reasons
from .targets import TargetSet, Unit


@dataclass
class PlanOptions:
    timing: int = 3
    host_discovery: bool = True
    resolve_dns: bool = False
    concurrency: int = 1
    hosts_per_task: int = 0
    prefer_ipv6: bool = False
    nse_category_udp_top_ports: int = 0
    privileged: bool | None = None


@dataclass
class Plan:
    tasks: list[ScanTask] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duplicates: list[tuple[int, int]] = field(default_factory=list)   # (duplicate task, original task)
    targets_digest: str = ""
    confirmed: bool = False


def targets_digest(ts: TargetSet) -> str:
    return hashlib.sha256("\n".join(ts.digest_tokens()).encode()).hexdigest()


# ------------------------------------------------------------------ chunking
MAX_EXPANSION = 65536


def _expand_unit(u: Unit) -> list[Unit]:
    if u.kind != "cidr":
        return [u]
    net = ipaddress.ip_network(u.token)
    return [Unit(str(a), "ip", 1, [str(ipaddress.ip_network(a))]) for a in net]


def _split_cidr(u: Unit, parts: int) -> list[Unit]:
    net = ipaddress.ip_network(u.token)
    diff = max(0, math.ceil(math.log2(parts)))
    diff = min(diff, net.max_prefixlen - net.prefixlen)
    if diff == 0:
        return [u]
    return [Unit(str(s), "cidr", s.num_addresses, [str(s)]) for s in net.subnets(prefixlen_diff=diff)]


def chunk_units(units: list[Unit], concurrency: int, hosts_per_task: int) -> list[list[Unit]]:
    """Group units into tasks. 0 = automatic: one task when concurrency is 1, otherwise
    up to `concurrency` balanced tasks. N > 0 = at most N hosts per task."""
    if not units:
        return []
    if hosts_per_task > 0:
        if sum(u.addresses for u in units) > MAX_EXPANSION:
            raise ValueError(f"too many addresses to split per host (more than {MAX_EXPANSION})")
        flat: list[Unit] = []
        for u in units:
            flat.extend(_expand_unit(u))
        n = max(1, min(hosts_per_task, 4096))
        return [flat[i:i + n] for i in range(0, len(flat), n)]
    if concurrency <= 1:
        return [units]
    work = list(units)
    if len(work) < concurrency:
        biggest = max(range(len(work)), key=lambda i: work[i].addresses)
        if work[biggest].kind == "cidr" and work[biggest].addresses > 1:
            parts = math.ceil(concurrency / len(work))
            work = work[:biggest] + _split_cidr(work[biggest], parts) + work[biggest + 1:]
    k = min(concurrency, len(work))
    buckets: list[list[Unit]] = [[] for _ in range(k)]
    loads = [0] * k
    for u in sorted(work, key=lambda x: -x.addresses):
        i = loads.index(min(loads))
        buckets[i].append(u)
        loads[i] += u.addresses
    return [b for b in buckets if b]


# ------------------------------------------------------------------ command
def has_flag(args: list[str] | tuple[str, ...], *flags: str) -> bool:
    return any(a in flags for a in args)


def build_command(nmap_bin: str, task: ScanTask, xml_path: str, normal_path: str) -> list[str]:
    """The ONE place where an Nmap command line is assembled. Returns an argument list
    (never a string): it is passed to subprocess without a shell."""
    for t in task.targets + task.exclude:
        if not t or t.startswith("-"):
            raise ValueError(f"refusing target that looks like an option: {t!r}")
    cmd = [nmap_bin, *task.args, f"-T{task.timing}", *task.extra_flags]
    if task.exclude:
        cmd += ["--exclude", ",".join(task.exclude)]
    cmd += ["-oX", xml_path, "-oN", normal_path, "--stats-every", "10s", "-v", "--reason"]
    cmd += task.targets
    return cmd


def display_command(task: ScanTask, max_targets: int = 6) -> list[str]:
    """The command as shown in the plan review: built by build_command so it can never drift from what
    is run. Output paths are placeholders and long target lists are shortened with '...'."""
    shown = dataclasses.replace(task, targets=task.targets[:max_targets])
    cmd = build_command("nmap", shown, "<scan.xml>", "<scan.nmap>")
    if len(task.targets) > max_targets:
        cmd.append("...")
    return cmd


# --------------------------------------------------------------------- build
def _extra_flags(args: list[str], family: str, opts: PlanOptions, warnings: list[str]) -> list[str]:
    flags: list[str] = []
    if family == "ipv6":
        flags.append("-6")
    list_only = has_flag(args, "-sL")
    discovery_only = has_flag(args, "-sn")
    if not opts.resolve_dns and not list_only:
        flags.append("-n")
    if not opts.host_discovery:
        if discovery_only or list_only:
            warnings.append("This is a host-discovery profile, so the 'skip host discovery' setting (-Pn) was not applied.")
        else:
            flags.append("-Pn")
    return flags


def _filter_profile_scripts(profile: ScanProfile, args: list[str], avail: Availability
                            ) -> tuple[list[str], list[str]]:
    """Check explicit NSE names embedded in a profile; rewrite --script to the usable subset."""
    if not profile.scripts or "--script" not in args:
        return args, []
    warns: list[str] = []
    if avail.db is None:
        return args, ["Nmap's script.db was not found: scripts could not be verified (Nmap will report an error if one is missing)."]
    usable, problems = avail.usable_scripts(list(profile.scripts), profile.allow_labels)
    for p in problems:
        warns.append(f"script not available and not run: {p}")
    i = args.index("--script")
    new = list(args)
    if usable:
        new[i + 1] = ",".join(usable)
    else:
        del new[i:i + 2]
        warns.append("No script of this profile is available; the scan runs without scripts.")
    return new, warns


def build_plan(targets: TargetSet, profiles: list[ScanProfile], nse_selection: NseSelection | None,
               avail: Availability, opts: PlanOptions, opt_in_confirmed: list[str] | None = None) -> Plan:
    """Create the full task list. See module docstring for the rules."""
    plan = Plan(targets_digest=targets_digest(targets))
    opt_in_confirmed = opt_in_confirmed or []
    specs: list[dict] = []          # one per Nmap process definition (before families/chunks)

    for prof in profiles:
        if prof.opt_in and prof.id not in opt_in_confirmed:
            plan.warnings.append(f"Profile '{prof.name}' needs explicit confirmation and was not scheduled.")
            continue
        for si, stage in enumerate(prof.stages, 1):
            args = list(stage)
            args, sw = _filter_profile_scripts(prof, args, avail)
            label = prof.name + (f" - stage {si}/{len(prof.stages)}" if len(prof.stages) > 1 else "")
            specs.append(dict(kind="profile", pid=prof.id, label=label, args=args, stage=si, stages=len(prof.stages),
                              risk=prof.risk, duration=prof.duration, warnings=list(prof.warnings) + sw,
                              confirm=f"opt-in confirmed: {prof.id}" if prof.opt_in else "", nse_ids=[]))
    if nse_selection and not nse_selection.is_empty():
        groups, gw = nse.expand_selection(nse_selection, avail, opts.nse_category_udp_top_ports)
        plan.warnings.extend(gw)
        for g in groups:
            risk = "Moderate" if any(x in g.args for x in ("-sU",)) or "vuln" in g.label else "Low"
            specs.append(dict(kind="nse", pid=g.id, label=g.label, args=list(g.args), stage=1, stages=1,
                              risk=risk, duration="Seconds to minutes" if "-sU" not in g.args else "Minutes to hours",
                              warnings=([g.notes] if g.notes else []) + g.warnings, confirm=g.confirm_note,
                              nse_ids=g.entry_ids))

    next_id = 1
    seen: dict[tuple, int] = {}
    for spec in specs:
        for family in targets.families():
            units = targets.units(family)
            try:
                chunks = chunk_units(units, opts.concurrency, opts.hosts_per_task)
            except ValueError as exc:
                msg = f"{exc}; using automatic splitting instead of 'hosts per task'."
                if msg not in plan.warnings:
                    plan.warnings.append(msg)
                chunks = chunk_units(units, opts.concurrency, 0)
            for ci, chunk in enumerate(chunks, 1):
                tokens = [u.token for u in chunk]
                locks = list(dict.fromkeys(k for u in chunk for k in u.lock_keys))
                warnings: list[str] = []
                flags = _extra_flags(spec["args"], family, opts, warnings)
                reasons = root_reasons(spec["args"])
                label = spec["label"] + (f" [{family}]" if len(targets.families()) > 1 else "") + \
                    (f" - hosts {ci}/{len(chunks)}" if len(chunks) > 1 else "")
                task = ScanTask(
                    task_id=next_id, kind=spec["kind"], profile_id=spec["pid"], label=label,
                    args=list(spec["args"]), targets=tokens, exclude=targets.exclusion_tokens(family),
                    stage=spec["stage"], stages=spec["stages"], chunk=ci, chunks=len(chunks), family=family,
                    timing=opts.timing, extra_flags=flags, nse_ids=list(spec["nse_ids"]), lock_keys=locks,
                    needs_root=bool(reasons), root_reasons=reasons, risk=spec["risk"], duration=spec["duration"],
                    warnings=spec["warnings"] + warnings, confirm_note=spec["confirm"], status=PENDING)
                key = (tuple(task.args), tuple(task.targets), tuple(task.exclude), task.family, tuple(task.extra_flags))
                if key in seen:
                    plan.duplicates.append((task.task_id, seen[key]))
                    task.warnings.append(f"Identical to task {seen[key]} (same options and targets).")
                else:
                    seen[key] = task.task_id
                plan.tasks.append(task)
                next_id += 1
    if not plan.tasks:
        plan.warnings.append("Nothing to schedule.")
    return plan

"""Runs Nmap tasks safely.

* Nmap is started with subprocess.Popen(list_of_args) - never a shell, never a command string.
* One reader thread per output stream writes stdout.log / stderr.log; Nmap itself writes scan.xml
  and scan.nmap. Stdout is read for progress display only; results come from the XML.
* Different hosts may be scanned in parallel (configurable); two tasks that overlap on any host
  never run at the same time.
* Ctrl+C asks what to do; cancelling stops the Nmap process gracefully (SIGINT, then SIGTERM,
  then SIGKILL) and keeps partial output.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import signal
import subprocess
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import MAX_CONCURRENCY, Config
from .models import CANCELLED, COMPLETED, FAILED, PENDING, RUNNING, TIMED_OUT, ScanTask
from .parser import parse_file
from .planner import Plan, build_command
from .session import Session
from .utils import (atomic_write_json, atomic_write_text, fix_ownership_tree, human_duration, now_iso,
                    sha256_file, shell_display, style)

_PROGRESS_RE = re.compile(r"(?P<phase>[A-Za-z0-9 /_()-]+?) Timing: About (?P<pct>[\d.]+)% done; "
                          r"ETC: (?P<etc>[^(]+?)\s*\((?P<rem>[^)]*) remaining\)")
_OPEN_RE = re.compile(r"^Discovered open port ")
_GRACE_INT, _GRACE_TERM = 8.0, 4.0


@dataclass
class Progress:
    pct: float | None = None
    phase: str = ""
    etc: str = ""
    remaining: str = ""
    open_ports: int = 0
    tail: deque = field(default_factory=lambda: deque(maxlen=8))
    last_print: float = 0.0
    last_pct_printed: float = -100.0


def _lock_objects(keys: list[str]) -> list:
    out = []
    for k in keys:
        if k.startswith("host:"):
            out.append(k)
        else:
            try:
                out.append(ipaddress.ip_network(k, strict=False))
            except ValueError:
                out.append("host:" + k)
    return out


def tasks_conflict(a: ScanTask, b: ScanTask) -> bool:
    """True when two tasks touch the same host (so they must not run together)."""
    for x in _lock_objects(a.lock_keys):
        for y in _lock_objects(b.lock_keys):
            if isinstance(x, str) or isinstance(y, str):
                if x == y:
                    return True
            elif x.version == y.version and x.overlaps(y):
                return True
    return False


class Executor:
    """Runs every pending task in a plan and records the outcome of each one."""

    def __init__(self, plan: Plan, session: Session, cfg: Config, nmap_bin: str, log: logging.Logger,
                 say: Callable[[str], None] = print,
                 ask_cancel: Callable[[list[ScanTask]], str] | None = None) -> None:
        self.plan, self.session, self.cfg, self.nmap_bin, self.log = plan, session, cfg, nmap_bin, log
        self._say_fn, self.ask_cancel = say, ask_cancel
        self.cancel_all, self.force = threading.Event(), threading.Event()
        self.skip_events: dict[int, threading.Event] = {t.task_id: threading.Event() for t in plan.tasks}
        self.progress: dict[int, Progress] = {}
        self._print_lock = threading.Lock()
        self.stopped_by_user = False

    # ---------------------------------------------------------------- output
    def say(self, msg: str) -> None:
        with self._print_lock:
            self._say_fn(msg)

    def _position(self, task: ScanTask) -> str:
        return f"[{task.task_id}/{len(self.plan.tasks)}]"

    # ------------------------------------------------------------------- run
    def run(self) -> None:
        self.session.require_confirmed(self.plan.targets_digest)   # raises if not confirmed
        limit = max(1, min(self.cfg.concurrency, MAX_CONCURRENCY))
        pending = [t for t in self.plan.tasks if t.status == PENDING]
        running: dict[Future, ScanTask] = {}
        self.session.tasks = self.plan.tasks
        self.session.save()
        self.log.info("execution started: %d tasks, concurrency %d", len(pending), limit)
        with ThreadPoolExecutor(max_workers=limit, thread_name_prefix="nmap") as pool:
            while pending or running:
                try:
                    if self.cancel_all.is_set() and not self.stopped_by_user:
                        self._stop(pending, running)       # cancel requested from outside the Ctrl+C path
                        break
                    self._launch(pool, pending, running, limit)
                    if running:
                        done, _ = wait(list(running), timeout=1.0, return_when=FIRST_COMPLETED)
                        for fut in done:
                            running.pop(fut, None)
                        self._print_progress([running[f] for f in running])
                except KeyboardInterrupt:
                    action = self._decide(list(running.values()))
                    if action == "stop":
                        self._stop(pending, running)
                        break
                    if action == "skip":
                        for t in running.values():
                            self.skip_events[t.task_id].set()
        for t in self.plan.tasks:        # safety net: nothing may stay pending/running
            if t.status in (PENDING, RUNNING):
                t.status, t.error = CANCELLED, t.error or "not completed"
        self.session.data["finished"] = now_iso()
        self.session.data["interrupted"] = self.stopped_by_user or self.cancel_all.is_set()
        self.session.save()
        self.log.info("execution finished")

    def _launch(self, pool: ThreadPoolExecutor, pending: list[ScanTask],
                running: dict[Future, ScanTask], limit: int) -> None:
        for task in list(pending):
            if len(running) >= limit:
                return
            if any(tasks_conflict(task, other) for other in running.values()):
                continue
            pending.remove(task)
            task.status = RUNNING
            running[pool.submit(self._run_task, task)] = task

    def _decide(self, running: list[ScanTask]) -> str:
        if self.ask_cancel is None:
            return "stop"
        try:
            decision = self.ask_cancel(running)
        except BaseException:                  # a broken prompt must never leave scans running unattended
            return "stop"
        return decision if decision in ("continue", "skip", "stop") else "stop"

    def _stop(self, pending: list[ScanTask], running: dict[Future, ScanTask]) -> None:
        self.stopped_by_user = True
        self.cancel_all.set()
        self.say(style("Stopping: terminating running scans and keeping partial results "
                       "(press Ctrl+C again to force-kill)...", "yellow"))
        for t in pending:
            t.status, t.error = CANCELLED, "cancelled by user before it started"
            self.log.info("task %d cancelled before start", t.task_id)
        pending.clear()
        while running:
            try:
                done, _ = wait(list(running), timeout=1.0, return_when=FIRST_COMPLETED)
                for f in done:
                    running.pop(f, None)
            except KeyboardInterrupt:
                self.force.set()

    # -------------------------------------------------------------- progress
    def _print_progress(self, running: list[ScanTask]) -> None:
        now = time.monotonic()
        for t in running:
            p = self.progress.get(t.task_id)
            if not p or p.pct is None:
                continue
            if p.pct - p.last_pct_printed >= 5 or now - p.last_print >= 30:
                p.last_pct_printed, p.last_print = p.pct, now
                self.say(f"  {self._position(t)} {t.label[:60]}: {p.pct:5.1f}% {p.phase}"
                         f" | ETC {p.etc} ({p.remaining} left) | open ports so far: {p.open_ports}")

    # ------------------------------------------------------------ one task
    def _run_task(self, task: ScanTask) -> None:
        try:
            self._run_task_inner(task)
        except Exception as exc:         # never let one task kill the whole run
            self.log.exception("task %d crashed", task.task_id)
            task.status, task.error = FAILED, f"internal error: {exc}"
            task.finished = task.finished or now_iso()
            self.say(style(f"{self._position(task)} FAILED (internal error): {exc}", "red"))
        finally:
            try:
                self.session.save()
            except Exception:
                self.log.exception("could not save session.json")

    def _run_task_inner(self, task: ScanTask) -> None:
        tdir = self.session.task_dir(task)
        xml_path, nmap_out = tdir / "scan.xml", tdir / "scan.nmap"
        for p in (xml_path, nmap_out):
            if p.exists():
                raise RuntimeError(f"{p} already exists; original results are never overwritten")
        cmd = build_command(self.nmap_bin, task, str(xml_path), str(nmap_out))
        task.command = cmd
        atomic_write_text(tdir / "command.txt", shell_display(cmd) + "\n")
        task.status, task.started = RUNNING, now_iso()
        self.say(style(f"\n{self._position(task)} START  {task.label}", "bold"))
        self.say(f"       command: {shell_display(cmd)}")
        self.log.info("task %d start: %s", task.task_id, shell_display(cmd))
        start = time.monotonic()
        prog = self.progress.setdefault(task.task_id, Progress())
        extra: dict = {}
        if os.name == "posix":
            extra["start_new_session"] = True      # Ctrl+C in the terminal won't hit Nmap directly
        elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            extra["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                    errors="replace", bufsize=1, **extra)          # no shell
        except OSError as exc:
            self._finish(task, tdir, start, FAILED, f"could not start Nmap: {exc.strerror or exc}", None)
            return
        readers = [
            threading.Thread(target=self._pump, args=(proc.stdout, tdir / "stdout.log", prog, True), daemon=True),
            threading.Thread(target=self._pump, args=(proc.stderr, tdir / "stderr.log", prog, False), daemon=True),
        ]
        for r in readers:
            r.start()
        timeout_s = self.cfg.timeout_minutes * 60 if self.cfg.timeout_minutes else 0
        skip_ev = self.skip_events[task.task_id]
        reason = ""
        while proc.poll() is None:
            if self.cancel_all.is_set():
                reason = "cancelled"
            elif skip_ev.is_set():
                reason = "skipped"
            elif timeout_s and time.monotonic() - start > timeout_s:
                reason = "timeout"
            if reason:
                self._terminate(proc)
                break
            time.sleep(0.05)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for r in readers:
            r.join(timeout=5)
        for stream in (proc.stdout, proc.stderr):      # never leak pipe file descriptors
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        rc = proc.returncode
        if reason == "timeout":
            status, err = TIMED_OUT, f"exceeded the {self.cfg.timeout_minutes}-minute limit; partial output kept"
        elif reason == "cancelled":
            status, err = CANCELLED, "cancelled by user; partial output kept"
        elif reason == "skipped":
            status, err = CANCELLED, "skipped by user while running; partial output kept"
        elif rc == 0:
            status, err = COMPLETED, ""
        else:
            tail = [ln for ln in prog.tail if ln.strip() and ln.strip() != "QUITTING!"]
            status = FAILED
            err = (" | ".join(tail[-3:]) if tail else f"Nmap exited with code {rc}")
        self._finish(task, tdir, start, status, err, rc)

    def _finish(self, task: ScanTask, tdir: Path, start: float, status: str, err: str, rc: int | None) -> None:
        xml_path, nmap_out = tdir / "scan.xml", tdir / "scan.nmap"
        task.exit_code, task.finished = rc, now_iso()
        task.duration_s = time.monotonic() - start
        parsed = parse_file(xml_path) if xml_path.exists() else None
        if status == COMPLETED:
            if parsed is None:
                status, err = FAILED, "Nmap finished but wrote no XML file"
            elif not parsed.complete:
                status, err = FAILED, "Nmap output (XML) is incomplete: " + "; ".join(parsed.errors or ["no run summary"])
        task.status, task.error = status, err
        task.xml_complete = bool(parsed and parsed.complete)
        if xml_path.exists():
            try:
                task.xml_sha256 = sha256_file(xml_path)
                for p in (xml_path, nmap_out):
                    if p.exists():
                        os.chmod(p, 0o444)       # originals become read-only
            except OSError as exc:
                self.log.warning("task %d: could not fingerprint/lock XML: %s", task.task_id, exc)
        atomic_write_json(tdir / "meta.json", task.to_dict())
        fix_ownership_tree(tdir)
        colour = {COMPLETED: "green", FAILED: "red", TIMED_OUT: "yellow", CANCELLED: "yellow"}.get(status, "")
        extra = ""
        if parsed:
            opens = sum(1 for h in parsed.hosts for p in h.ports if p.state == "open")
            extra = f" | hosts up: {parsed.hosts_up}/{parsed.hosts_total} | open ports: {opens}"
        self.say(style(f"{self._position(task)} {status.upper()}  ({human_duration(task.duration_s)}){extra}", colour)
                 + (f"\n       {err}" if err else ""))
        if parsed and parsed.hosts_up == 0 and status == COMPLETED:
            self.say("       No host responded. It may be down or blocking probes; consider disabling host discovery (-Pn).")
        self.log.info("task %d %s rc=%s err=%s", task.task_id, status, rc, err)

    def _pump(self, stream, path: Path, prog: Progress, is_stdout: bool) -> None:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                os.chmod(path, 0o600)
                for line in stream:
                    fh.write(line)
                    fh.flush()
                    if is_stdout:
                        m = _PROGRESS_RE.search(line)
                        if m:
                            prog.pct = float(m.group("pct"))
                            prog.phase = m.group("phase").strip()
                            prog.etc, prog.remaining = m.group("etc").strip(), m.group("rem").strip()
                        elif _OPEN_RE.match(line):
                            prog.open_ports += 1
                    prog.tail.append(line.strip())
        except (OSError, ValueError):
            pass

    def _terminate(self, proc: subprocess.Popen) -> None:
        """SIGINT (lets Nmap flush output) -> SIGTERM -> SIGKILL."""
        if proc.poll() is not None:
            return
        try:
            if os.name == "posix":
                proc.send_signal(signal.SIGINT)
            else:
                proc.terminate()
        except (OSError, ProcessLookupError):
            return
        if self._wait_exit(proc, 0.5 if self.force.is_set() else _GRACE_INT):
            return
        try:
            proc.terminate()
        except OSError:
            return
        if self._wait_exit(proc, 0.5 if self.force.is_set() else _GRACE_TERM):
            return
        try:
            proc.kill()
        except OSError:
            pass

    def _wait_exit(self, proc: subprocess.Popen, seconds: float) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if proc.poll() is not None:
                return True
            if self.force.is_set():
                return False
            time.sleep(0.1)
        return proc.poll() is not None

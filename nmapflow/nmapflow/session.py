"""Scan sessions: folder layout, persistence (session.json), locking, listing old sessions.

reports/YYYY-MM-DD_HH-MM-SS/
    session.json  session.xml  report.html  session.log
    tasks/003_<label>/  scan.xml  scan.nmap  command.txt  stdout.log  stderr.log  meta.json
Original Nmap output files are written once by Nmap, then made read-only; they are never edited.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ScanTask
from .utils import (TOOL_NAME, TOOL_VERSION, atomic_write_json, fix_ownership,
                    make_private_dir, now_iso, slugify, timestamp_dirname)

AUTH_STATEMENT = ("I confirm that I own these systems or have explicit written authorization "
                  "to scan them, and that the scope shown above is correct.")


class SessionError(RuntimeError):
    pass


@dataclass
class Session:
    dir: Path
    id: str
    created: str
    data: dict[str, Any] = field(default_factory=dict)
    tasks: list[ScanTask] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ------------------------------------------------------------ creation
    @classmethod
    def create(cls, base: Path) -> "Session":
        make_private_dir(base)
        fix_ownership(base)
        name = timestamp_dirname()
        path = base / name
        n = 2
        while path.exists():
            path = base / f"{name}-{n}"
            n += 1
        make_private_dir(path)
        make_private_dir(path / "tasks")
        sess = cls(dir=path, id=path.name, created=now_iso())
        sess.data = {
            "format": "nmapflow-session-json", "version": 1, "id": sess.id, "created": sess.created,
            "finished": None, "interrupted": False, "tool": TOOL_NAME, "tool_version": TOOL_VERSION,
            "operator": _safe_user(), "host": platform.node(), "platform": platform.platform(),
        }
        # lock file: stops two instances from writing into one session
        try:
            fd = os.open(path / ".lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
        except FileExistsError as exc:
            raise SessionError("session folder is locked by another process") from exc
        fix_ownership(path)
        fix_ownership(path / "tasks")
        return sess

    def release(self) -> None:
        try:
            (self.dir / ".lock").unlink()
        except OSError:
            pass

    # ------------------------------------------------------------- records
    def set_scope(self, scope: dict[str, Any]) -> None:
        self.data["scope"] = scope

    def set_authorization(self, typed: str, digest: str) -> None:
        self.data["authorization"] = {"statement": AUTH_STATEMENT, "typed": typed, "timestamp": now_iso(),
                                      "targets_digest": digest, "operator": _safe_user()}

    def set_plan_confirmation(self, task_count: int) -> None:
        self.data["plan_confirmation"] = {"timestamp": now_iso(), "task_count": task_count}

    def require_confirmed(self, plan_digest: str) -> None:
        """Refuse to run anything unless the scope was explicitly authorized AND the plan was
        explicitly confirmed AND the plan still covers exactly the confirmed targets."""
        auth = self.data.get("authorization")
        if not auth or auth.get("typed") != "AUTHORIZED":
            raise SessionError("scope has not been explicitly authorized; refusing to scan")
        if not self.data.get("plan_confirmation"):
            raise SessionError("scan plan has not been confirmed; refusing to scan")
        if auth.get("targets_digest") != plan_digest:
            raise SessionError("the plan's targets differ from the authorized scope; refusing to scan")

    def task_dir(self, task: ScanTask) -> Path:
        rel = f"tasks/{task.task_id:03d}_{slugify(task.label, 50)}"
        task.task_dir = rel
        path = self.dir / rel
        make_private_dir(path)
        fix_ownership(path)
        return path

    def save(self) -> None:
        with self._lock:
            self.data["tasks"] = [t.to_dict() for t in self.tasks]
            atomic_write_json(self.dir / "session.json", self.data)
            fix_ownership(self.dir / "session.json")

    # --------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: Path) -> "Session":
        f = path / "session.json"
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SessionError(f"cannot read {f}: {exc}") from exc
        if not isinstance(data, dict) or data.get("format") != "nmapflow-session-json":
            raise SessionError(f"{f} is not an nmapflow session file")
        sess = cls(dir=path, id=str(data.get("id", path.name)), created=str(data.get("created", "")), data=data)
        sess.tasks = [ScanTask.from_dict(t) for t in data.get("tasks", []) if isinstance(t, dict)]
        return sess


def _safe_user() -> str:
    try:
        return os.environ.get("SUDO_USER") or getpass.getuser()
    except Exception:
        return "unknown"


def list_sessions(base: Path) -> list[tuple[Path, dict[str, Any] | None]]:
    """Newest first. A folder without a readable session.json is listed with None."""
    out: list[tuple[Path, dict[str, Any] | None]] = []
    if not base.is_dir():
        return out
    for p in sorted((x for x in base.iterdir() if x.is_dir()), reverse=True):
        try:
            d = json.loads((p / "session.json").read_text(encoding="utf-8"))
            out.append((p, d if isinstance(d, dict) else None))
        except (OSError, ValueError):
            out.append((p, None))
    return out

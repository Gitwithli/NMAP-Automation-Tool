"""Small helpers shared by all modules: time, files, logging, terminal colours."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

TOOL_NAME = "nmapflow"
TOOL_VERSION = "1.0.0"


# --------------------------------------------------------------------- time
def now_iso() -> str:
    """Current local time as an ISO 8601 string with UTC offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def timestamp_dirname() -> str:
    """Folder name used for a scan session: YYYY-MM-DD_HH-MM-SS."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def human_duration(seconds: float | None) -> str:
    """Format seconds as e.g. '1h 02m 05s'."""
    if seconds is None:
        return "-"
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


# -------------------------------------------------------------------- text
_BAD_XML_CHARS = re.compile("[^\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def strip_control(text: str) -> str:
    """Remove characters that are illegal in XML 1.0 (control codes, lone surrogates). Scan output and
    error text can contain such bytes; without this, session.xml would not be well-formed."""
    return _BAD_XML_CHARS.sub("", text)


def slugify(text: str, maxlen: int = 60) -> str:
    """Make a filesystem-safe name from arbitrary text."""
    slug = re.sub(r"-{2,}", "-", re.sub(r"[^A-Za-z0-9_.-]+", "-", text)).strip("-.")
    return (slug or "item")[:maxlen]


def shell_display(argv: Sequence[str]) -> str:
    """Render an argument list as one readable line. For DISPLAY ONLY: the tool
    never passes this string to a shell."""
    if os.name == "nt":
        return subprocess.list2cmdline(list(argv))
    import shlex
    return " ".join(shlex.quote(a) for a in argv)


# ------------------------------------------------------------------- files
def make_private_dir(path: Path) -> Path:
    """Create a directory (and parents) readable only by the owner."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Write text to path via a temp file + rename so readers never see half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False, default=str) + "\n")


def sha256_file(path: Path) -> str:
    """SHA-256 hex digest of a file (used to prove original Nmap output is unchanged)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fix_ownership(path: Path) -> None:
    """When running under sudo, hand files back to the invoking user."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid and uid.isdigit() and gid.isdigit()):
        return
    try:
        os.chown(path, int(uid), int(gid), follow_symlinks=False)
    except OSError:
        pass


def fix_ownership_tree(root: Path) -> None:
    fix_ownership(root)
    for p in root.rglob("*"):
        fix_ownership(p)


# ----------------------------------------------------------------- logging
def setup_logger(log_path: Path | None, name: str = TOOL_NAME) -> logging.Logger:
    """Logger that writes to the session log file only (the terminal uses print)."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        logger.addHandler(handler)
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass
    else:
        logger.addHandler(logging.NullHandler())
    return logger


# ------------------------------------------------------------------ colour
_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
          "blue": "34", "magenta": "35", "cyan": "36"}


def colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() and (os.name != "nt" or bool(os.environ.get("WT_SESSION")))


def style(text: str, *names: str) -> str:
    """Wrap text in ANSI colour codes when the terminal supports them."""
    if not colour_enabled() or not names:
        return text
    codes = ";".join(_CODES[n] for n in names if n in _CODES)
    return f"\033[{codes}m{text}\033[0m"

"""Consolidated session XML.

This is NOT native Nmap XML. A native Nmap file has one <nmaprun> root describing a single run, so
several independent runs cannot be merged into it without inventing values. session.xml therefore
records the session (scope, authorization, settings) and one <task> per scan with the relative
path and SHA-256 of that scan's untouched, original Nmap XML.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .session import Session
from .utils import TOOL_NAME, TOOL_VERSION, atomic_write_text, fix_ownership, strip_control


def _sub(parent: ET.Element, tag: str, text: str | None = None, **attrs) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: strip_control(str(v)) for k, v in attrs.items() if v is not None})
    if text is not None:
        el.text = strip_control(str(text))
    return el


def build_xml(session: Session) -> ET.Element:
    d = session.data
    root = ET.Element("nmapflow-session", {
        "format": "nmapflow-session-xml", "version": "1", "id": strip_control(session.id), "created": strip_control(session.created),
        "finished": strip_control(str(d.get("finished") or "")), "interrupted": str(bool(d.get("interrupted"))).lower()})
    root.append(ET.Comment(" Custom nmapflow format; NOT native Nmap XML. Original Nmap XML files are referenced, not copied or modified. "))
    _sub(root, "tool", name=TOOL_NAME, version=d.get("tool_version", TOOL_VERSION))
    _sub(root, "nmap", version=d.get("nmap_version", ""), path=d.get("nmap_path", ""))
    _sub(root, "environment", operator=d.get("operator", ""), host=d.get("host", ""),
         platform=d.get("platform", ""), privileged=str(d.get("privileged")))
    auth = d.get("authorization") or {}
    a = _sub(root, "authorization", timestamp=auth.get("timestamp", ""), typed=auth.get("typed", ""),
             operator=auth.get("operator", ""))
    a.set("targets_digest", strip_control(str(auth.get("targets_digest", ""))))
    _sub(a, "statement", auth.get("statement", ""))
    pc = d.get("plan_confirmation") or {}
    _sub(root, "plan-confirmation", timestamp=pc.get("timestamp", ""), task_count=pc.get("task_count", ""))
    scope = d.get("scope") or {}
    sc = _sub(root, "scope")
    for o in scope.get("originals", []):
        _sub(sc, "original-input", o)
    for t in scope.get("targets", []):
        _sub(sc, "target", t.get("normalized"), kind=t.get("kind"), family=t.get("family"),
             raw=t.get("raw"), resolved=",".join(t.get("resolved", [])))
    for t in scope.get("exclusions", []):
        _sub(sc, "exclusion", t.get("normalized"), kind=t.get("kind"))
    for w in scope.get("warnings", []):
        _sub(sc, "warning", w)
    st = _sub(root, "settings")
    for k, v in (d.get("config") or {}).items():
        _sub(st, "setting", str(v), name=k)
    for oi in d.get("opt_in_confirmations", []):
        _sub(root, "opt-in-confirmation", oi)
    tasks = _sub(root, "tasks")
    for t in session.tasks:
        te = _sub(tasks, "task", id=t.task_id, kind=t.kind, profile=t.profile_id, status=t.status,
                  stage=f"{t.stage}/{t.stages}", chunk=f"{t.chunk}/{t.chunks}", family=t.family,
                  started=t.started or "", finished=t.finished or "", duration_s=
                  "" if t.duration_s is None else f"{t.duration_s:.1f}", exit_code="" if t.exit_code is None else t.exit_code,
                  risk=t.risk, needs_root=str(t.needs_root).lower())
        _sub(te, "label", t.label)
        _sub(te, "command", " ".join(t.command) if t.command else "")
        for x in t.targets:
            _sub(te, "target", x)
        if t.error:
            _sub(te, "error", t.error)
        if t.skip_reason:
            _sub(te, "skip-reason", t.skip_reason)
        for w in t.warnings:
            _sub(te, "warning", w)
        if t.task_dir:
            _sub(te, "nmap-xml", href=f"{t.task_dir}/scan.xml", sha256=t.xml_sha256, complete=str(t.xml_complete).lower())
            _sub(te, "nmap-output", href=f"{t.task_dir}/scan.nmap")
            _sub(te, "stdout-log", href=f"{t.task_dir}/stdout.log")
            _sub(te, "stderr-log", href=f"{t.task_dir}/stderr.log")
    return root


def write_xml(session: Session) -> Path:
    root = build_xml(session)
    ET.indent(root)
    text = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
    path = session.dir / "session.xml"
    atomic_write_text(path, text)
    fix_ownership(path)
    return path

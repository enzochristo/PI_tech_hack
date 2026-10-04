"""Texto bruto -> fatos utilizáveis (comando -> interpretador+script, modo -> flags, log -> PID)."""

from __future__ import annotations

import posixpath
import re
import shlex
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from .model import FileEntry, Inventory, LogEvent, Process, Service

INTERPRETERS = ("bash", "sh", "dash", "zsh", "python", "perl", "ruby", "node")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
ACCEPTED_RE = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
JOURNAL_RE = re.compile(
    r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+([\w.\-]+)(?:\[(\d+)\])?:\s+(.*)$")


def parse_command(cmd: str) -> tuple[str | None, list[str], str | None, str | None]:
    """Retorna (executable, args, interpreter, script)."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        argv = cmd.split()
    if not argv or not argv[0].startswith("/"):
        # ex.: "sshd: aluno@pts/0" é título de processo, não um caminho
        return None, argv[1:], None, None
    executable, args = argv[0], argv[1:]
    base = posixpath.basename(executable)
    if base.startswith(INTERPRETERS):
        for a in args:
            if a.startswith("/"):
                return executable, args, executable, a
            if not a.startswith("-"):
                break
    return executable, args, None, None


def mode_flags(mode: str) -> dict[str, bool]:
    m = int(mode, 8)
    return {
        "setuid": bool(m & 0o4000),
        "setgid": bool(m & 0o2000),
        "sticky": bool(m & 0o1000),
        "group_writable": bool(m & 0o020),
        "world_writable": bool(m & 0o002),
    }


def parent_dirs(path: str) -> list[str]:
    """/opt/backup/backup.sh -> ['/opt/backup', '/opt', '/']"""
    out, cur = [], posixpath.dirname(path)
    while cur and cur != path:
        out.append(cur)
        path, cur = cur, posixpath.dirname(cur)
    return out


def remote_hosts(executable: str | None, args: list[str]) -> list[str]:
    if not executable or posixpath.basename(executable) not in ("curl", "wget"):
        return []
    return [h for a in args if "://" in a and (h := urlparse(a).hostname)]


def _journal_ts(mon: str, day: str, hms: str, year: int, tz: timezone) -> str:
    h, mi, s = (int(x) for x in hms.split(":"))
    return datetime(year, MONTHS[mon], int(day), h, mi, s, tzinfo=tz).isoformat(timespec="seconds")


def normalize(raw: dict) -> Inventory:
    meta = raw["meta"]
    sign = -1 if str(meta.get("timezone", "-03:00")).startswith("-") else 1
    hh, mm = str(meta.get("timezone", "-03:00")).lstrip("+-").split(":")
    tz = timezone(sign * timedelta(hours=int(hh), minutes=int(mm)))
    year = int(meta.get("year", datetime.now().year))

    processes = []
    for r in raw["processes"]:
        exe, args, interp, script = parse_command(r["cmd"])
        processes.append(Process(
            pid=int(r["pid"]), ppid=int(r["ppid"]), user=r["user"], stat=r["stat"], cmd=r["cmd"],
            collected_at=r["timestamp"], executable=exe, args=args, interpreter=interp,
            script=script, src=r["src"]))

    files = [FileEntry(
        path=r["path"], type=r["type"], owner=r["owner"], group=r["group"], mode=r["mode"],
        mtime=r["mtime"], flags=mode_flags(r["mode"]), src=r["src"]) for r in raw["permissions"]]

    services = []
    for r in raw["services"]:
        exe, args, interp, script = parse_command(r["execstart"])
        services.append(Service(
            unit=r["unit"], active=r["active"], user=r["user"], execstart=r["execstart"],
            executable=exe, args=args, interpreter=interp, script=script, src=r["src"],
            main_pid=r.get("main_pid")))

    logs = []
    for r in raw["journal"]:
        m = JOURNAL_RE.match(r["line"])
        if not m:
            continue
        mon, day, hms, host, ident, pid, msg = m.groups()
        logs.append(LogEvent(
            timestamp=_journal_ts(mon, day, hms, year, tz), host=host, ident=ident,
            pid=int(pid) if pid else None, message=msg, src=r["src"]))

    return Inventory(processes, files, services, logs, raw["artifacts"], meta)

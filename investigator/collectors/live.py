"""Coletor ao vivo (snapshot sob demanda): mesma saída do coletor de dataset.

Fontes: /proc/<pid>/{status,cmdline,exe}, systemctl show, os.stat, journalctl -o json.
Permissões orientadas por contexto: só arquivos usados por processos e serviços, seus diretórios pai e
uma busca de SUID restrita a /usr/local, /opt, /home e /tmp.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import posixpath
import pwd
import re
import shlex
import stat as st
import subprocess
import sys
from datetime import datetime

from ..normalize import INTERPRETERS, parent_dirs, parse_command

SUID_DIRS = ("/usr/local", "/opt", "/home", "/tmp")
WRITABLE_DIRS = ("/usr/local", "/opt")  # /tmp e /home têm muito arquivo o+w legítimo: ruído
MAX_JOURNAL = 1000


def _name(fn, key, default):
    try:
        return fn(key)[0]
    except KeyError:
        return str(default)


def _processes() -> list[dict]:
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    rows = []
    for entry in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else -1):
        if not entry.isdigit():
            continue
        try:
            status = dict(l.split(":\t", 1) for l in open(f"/proc/{entry}/status").read().splitlines() if ":\t" in l)
            argv = open(f"/proc/{entry}/cmdline", "rb").read().split(b"\0")
            argv = [a.decode(errors="replace") for a in argv if a]
        except OSError:
            continue  # processo terminou durante a coleta
        if not argv:
            continue  # thread de kernel: sem cmdline
        try:
            exe = os.readlink(f"/proc/{entry}/exe")
            if not argv[0].startswith("/") and posixpath.basename(argv[0]) == posixpath.basename(exe):
                argv[0] = exe
        except OSError:
            pass
        uid = int(status["Uid"].split()[0])
        rows.append({"timestamp": now, "pid": entry, "ppid": status["PPid"].strip(),
                     "user": _name(pwd.getpwuid, uid, uid), "stat": status["State"].split()[0],
                     "cmd": shlex.join(argv) if argv[0].startswith("/") else " ".join(argv),
                     "src": f"/proc/{entry}"})
    return rows


def _systemctl(*args: str) -> str:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=30).stdout


def _services() -> list[dict]:
    try:
        units = [l.split()[0] for l in _systemctl("list-units", "--type=service", "--state=running",
                                                  "--no-legend", "--plain").splitlines() if l.strip()]
    except (OSError, subprocess.SubprocessError):
        print("aviso: systemctl indisponível; serviços não coletados", file=sys.stderr)
        return []
    rows = []
    for unit in units:
        props = dict(l.split("=", 1) for l in _systemctl("show", unit, "-p", "User,ExecStart,MainPID").splitlines()
                     if "=" in l)
        m = re.search(r"argv\[\]=(.*?) ;", props.get("ExecStart", ""))
        if not m:
            continue
        pid = int(props.get("MainPID", "0") or 0)
        rows.append({"unit": unit, "active": "running", "user": props.get("User") or "root",
                     "execstart": m.group(1), "main_pid": pid or None, "src": f"systemctl show {unit}"})
    return rows


def _entry(path: str, tz) -> dict | None:
    try:
        s = os.stat(path)  # segue symlinks: o modo 0777 do link em si não é uma permissão efetiva
    except OSError:
        return None
    return {"path": path, "type": "directory" if st.S_ISDIR(s.st_mode) else "file",
            "owner": _name(pwd.getpwuid, s.st_uid, s.st_uid), "group": _name(grp.getgrgid, s.st_gid, s.st_gid),
            "mode": f"{s.st_mode & 0o7777:04o}",
            "mtime": datetime.fromtimestamp(s.st_mtime, tz).isoformat(timespec="seconds"),
            "src": f"stat {path}"}


def _candidate_files() -> set[str]:
    """Setuid em SUID_DIRS (R4) e arquivos regulares o+w em WRITABLE_DIRS (R6: gravável sem consumidor)."""
    found = set()
    for base in SUID_DIRS:
        for root, _, files in os.walk(base, onerror=lambda e: None):
            for f in files:
                p = os.path.join(root, f)
                try:
                    mode = os.lstat(p).st_mode
                except OSError:
                    continue
                if mode & st.S_ISUID or (base in WRITABLE_DIRS and st.S_ISREG(mode) and mode & st.S_IWOTH):
                    found.add(p)
    return found


def _permissions(procs: list[dict], services: list[dict], tz) -> list[dict]:
    paths = set(_candidate_files())
    for cmd in [p["cmd"] for p in procs] + [s["execstart"] for s in services]:
        exe, _, _, script = parse_command(cmd)
        paths.update(x for x in (exe, script) if x)
    for p in list(paths):
        paths.update(parent_dirs(p))
    return [e for p in sorted(paths) if (e := _entry(p, tz))]


def _journal(tz) -> list[dict]:
    try:
        out = subprocess.run(["journalctl", "-o", "json", "--no-pager", "-n", str(MAX_JOURNAL)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        print("aviso: journalctl indisponível; journal não coletado", file=sys.stderr)
        return []
    rows = []
    for n, line in enumerate(out.splitlines(), 1):
        try:
            j = json.loads(line)
            ts = datetime.fromtimestamp(int(j["__REALTIME_TIMESTAMP"]) / 1e6, tz)
            msg = j["MESSAGE"] if isinstance(j["MESSAGE"], str) else ""
        except (ValueError, KeyError):
            continue
        ident, pid = j.get("SYSLOG_IDENTIFIER", "unknown"), j.get("_PID")
        rows.append({"line": f"{ts.strftime('%b %d %H:%M:%S')} {j.get('_HOSTNAME', 'host')} "
                             f"{ident}{f'[{pid}]' if pid else ''}: {msg}", "src": f"journalctl:{n}"})
    return rows


def collect() -> dict:
    tz = datetime.now().astimezone().tzinfo
    offset = datetime.now().astimezone().utcoffset()
    total = int(offset.total_seconds() // 60)
    sign = "-" if total < 0 else "+"
    procs, services = _processes(), _services()
    raw = {"processes": procs, "services": services, "journal": _journal(tz),
           "permissions": _permissions(procs, services, tz),
           "meta": {"timezone": f"{sign}{abs(total) // 60:02d}:{abs(total) % 60:02d}",
                    "year": datetime.now().year}}
    # cadeia de custódia: hash da coleta serializada, por seção
    raw["artifacts"] = [{"name": f"live:{k}", "sha256": hashlib.sha256(
        json.dumps(raw[k], sort_keys=True).encode()).hexdigest()} for k in
        ("processes", "permissions", "services", "journal")]
    return raw

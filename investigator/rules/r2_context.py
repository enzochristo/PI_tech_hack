"""R2: processo + cadeia de PPID + usuário -> contexto de execução (elevação sem registro de sudo/su)."""

from __future__ import annotations

import posixpath

from ..graph import Graph
from ..model import Finding, Inventory
from ..normalize import ACCEPTED_RE
from .common import Builder, make_finding

META = "r2_context.toml"


def _ancestors(procs: dict, p) -> list:
    chain, seen = [], {p.pid}
    while p.ppid in procs and p.ppid not in seen:
        p = procs[p.ppid]
        seen.add(p.pid)
        chain.append(p)
    return chain


def run(inv: Inventory, g: Graph) -> list[Finding]:
    procs = {p.pid: p for p in inv.processes}
    out = []
    for p in inv.processes:
        parent = procs.get(p.ppid)
        if p.user != "root" or not parent or parent.user == "root":
            continue
        if posixpath.basename(parent.executable or "") in ("sudo", "su"):
            continue
        elevation_logs = [e for e in inv.logs if e.ident in ("sudo", "su") and parent.user in e.message]
        if elevation_logs:
            continue  # elevação registrada: contexto explicado
        chain = _ancestors(procs, p)
        b = Builder()
        b.add(p.src, f"processo {p.pid} (PPID {p.ppid}, user root): {p.cmd}", p.to_ecs())
        origin = "sessão de login não identificada"
        for a in chain:
            b.add(a.src, f"ancestral {a.pid} (PPID {a.ppid}, user {a.user}): {a.cmd}", a.to_ecs())
            for ev in inv.logs:
                m = ACCEPTED_RE.search(ev.message)
                if m and ev.pid == a.pid and m.group(1) == parent.user:
                    b.add(ev.src, f"sessão SSH de {m.group(1)} aceita em {ev.timestamp} (origem {m.group(2)})")
                    origin = f"sessão SSH de {m.group(1)}"
        b.add("journal.log (ausência)", f"nenhuma linha de sudo/su referente a {parent.user} nas {len(inv.logs)} linhas coletadas")
        out.append(make_finding(
            META, str(p.pid), "Processo root originado de processo de usuário comum",
            f"processo {p.pid} (root) é filho de {parent.pid} ({parent.user}); origem: {origin}.", b))
    return out

"""R3: processo + serviço + log + mtime -> reconstrução temporal. Pré-requisito: R1."""

from __future__ import annotations

from datetime import datetime

from ..graph import Graph
from ..model import Finding, Inventory
from ..normalize import ACCEPTED_RE
from .common import Builder, make_finding

META = "r3_timeline.toml"


def run(inv: Inventory, g: Graph, prior: list[Finding]) -> list[Finding]:
    out, seen_users = [], set()
    r1s = [f for f in prior if f.rule_id == "R1"]
    for r1 in r1s:
        svc = next(s for s in inv.services if r1.target in (s.script, s.executable) and s.user == "root")
        entry = next((x for x in inv.files if x.path == r1.target), None)
        for ev in inv.logs:
            m = ACCEPTED_RE.search(ev.message)
            if not m or m.group(1) == "root" or (r1.uid, m.group(1)) in seen_users:
                continue
            user = m.group(1)
            seen_users.add((r1.uid, user))
            b = Builder()
            for e in inv.logs:  # início do serviço, pelo nome da unit
                if e.ident == "systemd" and svc.unit in e.message and ("Start" in e.message):
                    b.add(e.src, f"{e.timestamp}: {e.message}")
            b.add(ev.src, f"{ev.timestamp}: sessão SSH de {user} aceita (origem {m.group(2)})")
            order = ""
            if entry:
                before = datetime.fromisoformat(entry.mtime) < datetime.fromisoformat(ev.timestamp)
                b.add(entry.src, f"{entry.mtime}: mtime de {entry.path}")
                order = (f"; o mtime do recurso é {'anterior' if before else 'POSTERIOR'} ao login"
                         + ("" if before else " (compatível com alteração pelo usuário)"))
            b.add(f"{r1.uid} (R1)", f"{svc.unit} executa {r1.target} como root, alterável por não-root")
            out.append(make_finding(
                META, user, "Usuário comum presente enquanto recurso alterável é usado por root",
                f"{user} entrou em {ev.timestamp} e {r1.target} (usado por {svc.unit}) é alterável por não-root{order}.", b))
    return out

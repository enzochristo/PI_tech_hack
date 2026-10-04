"""R5: processo filho + serviço root + URL -> saída de rede privilegiada (inconclusiva por padrão).

Reclassificada para severidade maior quando o script do serviço foi marcado por R1: quem altera o
script controla o que o root envia para fora.
"""

from __future__ import annotations

from ..graph import Graph
from ..model import Finding, Inventory
from .common import Builder, add_service_evidence, file_fact, make_finding

META = "r5_outbound.toml"


def run(inv: Inventory, g: Graph, prior: list[Finding]) -> list[Finding]:
    r1_targets = {f.target: f for f in prior if f.rule_id == "R1"}
    out = []
    for p in inv.processes:
        if p.user != "root":
            continue
        hosts = [e.dst[1] for e in g.out(("process", p.pid), "connects_to")]
        owners = [e.src for e in g.into(("process", p.ppid), "has_process")]
        if not hosts or not owners:
            continue  # só interessa curl/wget filho de serviço
        svc = g.attr(owners[0], "obj")
        parent = g.attr(("process", p.ppid), "obj")
        for host in hosts:
            b = Builder()
            add_service_evidence(b, g, svc)
            b.add(p.src, f"processo {p.pid} (PPID {p.ppid}, user root): {p.cmd} -> destino {host}", p.to_ecs())
            for pid in (p.pid, parent.pid):
                for e in g.into(("process", pid), "logged_by"):
                    ev = g.attr(e.src, "obj")
                    b.add(ev.src, f"{ev.ident}[{ev.pid}]: {ev.message}")
            script = svc.script or svc.executable
            entry = next((x for x in inv.files if x.path == script), None)
            flagged = r1_targets.get(script)
            severity, note = None, ""
            if entry:
                b.add(entry.src, file_fact(entry) + (" -> alterável por não-root (R1)" if flagged else " -> só root altera"),
                      entry.to_ecs())
            if flagged:
                severity = 3
                note = f" Reclassificada: o script {script} é alterável por não-root ({flagged.uid}), então quem o altera controla o que o root envia."
            out.append(make_finding(
                META, host, "Serviço root executa cliente de rede para destino remoto",
                f"{svc.unit} (via processo {p.pid}) conecta a {host}; sem outras evidências não é C2 nem exfiltração.{note}",
                b, severity=severity))
    return out

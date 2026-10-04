"""R7: serviço root + script protegido -> registra que o caso foi verificado e está correto."""

from __future__ import annotations

from ..graph import Graph
from ..model import Finding, Inventory
from .common import PRIVILEGED, Builder, add_service_evidence, exposure, file_fact, make_finding

META = "r7_legit.toml"


def run(inv: Inventory, g: Graph) -> list[Finding]:
    out = []
    for svc in inv.services:
        if svc.user != PRIVILEGED or not svc.script:
            continue
        resources = exposure(g, svc)
        chain = dict(resources)[svc.script]
        if chain[0].entry is None or any(c.reasons for _, ch in resources for c in ch):
            continue  # sem dado sobre o script, ou R1 se aplica
        b = Builder()
        add_service_evidence(b, g, svc)
        notes = []
        for c in chain:
            if c.entry:
                b.add(c.entry.src, f"{file_fact(c.entry)} -> só root pode alterar", c.entry.to_ecs())
                if c.entry.flags["group_writable"]:  # g+w com grupo root: protegido, mas depende da participação
                    notes.append(f"membros do grupo {c.entry.group} (g+w em {c.path}) não coletados")
            notes += c.notes
        unknown = [c.path for c in chain if c.entry is None]
        if unknown:
            notes.append(f"permissões de {', '.join(unknown)} não coletadas")
        out.append(make_finding(
            META, svc.script, "Serviço root usa script protegido contra alteração",
            f"{svc.unit} executa {svc.script} como root; o script e os diretórios coletados só são graváveis por root.",
            b, missing=notes))
    return out

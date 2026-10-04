"""R1: serviço root + processo + permissão -> relação de privilégio insegura.

Verifica o recurso e todos os diretórios até a raiz: um script 0700 de root dentro de um diretório
gravável por qualquer um (sem sticky bit) pode ser apagado e recriado (checagem do PEASS-ng).
"""

from __future__ import annotations

from ..graph import Graph
from ..model import Finding, Inventory
from .common import (PRIVILEGED, Builder, add_service_evidence, exposure, file_fact,
                     make_finding)

META = "r1_privilege.toml"


def run(inv: Inventory, g: Graph) -> list[Finding]:
    out = []
    for svc in inv.services:
        if svc.user != PRIVILEGED:
            continue
        for path, chain in exposure(g, svc):
            flagged = [c for c in chain if c.reasons]
            if not flagged:
                continue
            b = Builder()
            add_service_evidence(b, g, svc)
            for c in chain[:1] + [c for c in flagged if c is not chain[0]]:
                if c.entry:
                    b.add(c.entry.src, f"{file_fact(c.entry)} -> alterável por: {', '.join(c.reasons) or 'nenhuma identidade não privilegiada'}",
                          c.entry.to_ecs())
            direct = flagged[0] is chain[0]
            who = "; ".join(f"{c.path}: {', '.join(c.reasons)}" for c in flagged)
            unknown = [c.path for c in chain if c.entry is None]
            missing = [f"permissões de {', '.join(unknown)} não coletadas"] if unknown else []
            if not any(e.source.startswith("processes.csv") for e in b.items):
                missing.append(f"processo de {svc.unit} não encontrado no snapshot (serviço sem processo associado)")
            out.append(make_finding(
                META, path,
                "Serviço root executa recurso gravável por identidade não privilegiada" if direct
                else "Serviço root executa recurso substituível via diretório pai gravável",
                f"{svc.unit} executa {path} como root; alterável por -> {who}.",
                b, missing=missing,
                interpretation=f"{who} pode alterar {'o recurso' if direct else 'o diretório que contém o recurso'} "
                               f"usado por {svc.unit} (UID 0)"
                               + ("" if direct else "; sem permissão sobre o arquivo, ainda é possível apagá-lo e recriá-lo")
                               + "."))
    return out

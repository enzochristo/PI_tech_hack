"""R6: permissão excessiva sem consumidor -> configuração inadequada isolada."""

from __future__ import annotations

from ..graph import Graph
from ..model import Finding, Inventory
from .common import Builder, file_fact, make_finding

META = "r6_misconfig.toml"


def run(inv: Inventory, g: Graph) -> list[Finding]:
    out = []
    for f in inv.files:
        if f.is_dir or not f.flags["world_writable"]:
            continue
        consumers = [e for etype in ("executes", "uses_script") for e in g.into(("file", f.path), etype)]
        if consumers:
            continue  # tem consumidor: é caso de R1 (se root) ou de outra regra
        b = Builder()
        b.add(f.src, f"{file_fact(f)} -> alterável por qualquer usuário", f.to_ecs())
        b.add("processes.csv + services.txt",
              f"ausência: nenhum dos {len(inv.processes)} processos nem dos {len(inv.services)} serviços coletados usa {f.path}")
        out.append(make_finding(
            META, f.path, "Arquivo com permissão excessiva sem consumidor privilegiado identificado",
            f"{f.path} tem modo {f.mode}, mas não é usado por nenhum processo ou serviço do snapshot.", b))
    return out

"""Análise de capacidade de alteração (R1/R7): o arquivo e todos os diretórios até a raiz."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..graph import Graph
from ..model import Evidence, FileEntry, Finding, Service
from ..normalize import parent_dirs
from . import load_meta

PRIVILEGED = "root"


@dataclass
class ChainItem:
    path: str
    entry: FileEntry | None  # None = permissões não coletadas
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def alter_reasons(e: FileEntry) -> tuple[list[str], list[str]]:
    """Quem não-privilegiado pode alterar/substituir esta entrada. Retorna (motivos, notas de descarte)."""
    reasons, notes = [], []
    sticky_dir = e.is_dir and e.flags["sticky"]
    if e.flags["world_writable"]:
        if sticky_dir:
            notes.append(f"{e.path}: o+w descartado (sticky bit impede substituir arquivo de outro dono)")
        else:
            reasons.append("qualquer usuário (o+w)")
    if e.flags["group_writable"] and e.group != PRIVILEGED:
        if sticky_dir:
            notes.append(f"{e.path}: g+w descartado (sticky bit)")
        else:
            reasons.append(f"grupo {e.group} (g+w)")
    if e.owner != PRIVILEGED:
        reasons.append(f"dono {e.owner}")
    return reasons, notes


def chain_for(g: Graph, path: str) -> list[ChainItem]:
    items = []
    for p in [path, *parent_dirs(path)]:
        node = ("dir", p) if ("dir", p) in g.nodes else ("file", p)
        entry = g.attr(node, "obj")
        item = ChainItem(p, entry)
        if entry:
            item.reasons, item.notes = alter_reasons(entry)
        items.append(item)
    return items


def exposure(g: Graph, svc: Service) -> list[tuple[str, list[ChainItem]]]:
    """Recursos usados pelo serviço (binário e script) e a cadeia de permissões de cada um."""
    paths = [p for p in (svc.executable, svc.script) if p]
    return [(p, chain_for(g, p)) for p in paths]


def service_processes(g: Graph, svc: Service):
    return [(e.dst[1], e) for e in g.out(("service", svc.unit), "has_process")]


class Builder:
    """Monta Evidence com IDs sequenciais e sem duplicar a mesma origem+fato."""

    def __init__(self) -> None:
        self.items: list[Evidence] = []

    def add(self, source: str, fact: str, ecs: dict | None = None) -> None:
        if any(e.source == source and e.fact == fact for e in self.items):
            return
        self.items.append(Evidence(f"E{len(self.items) + 1}", source, fact, ecs or {}))


def add_service_evidence(b: Builder, g: Graph, svc: Service) -> None:
    b.add(svc.src, f"{svc.unit}: User={svc.user}, ExecStart={svc.execstart}", svc.to_ecs())
    for pid, edge in service_processes(g, svc):
        p = g.attr(("process", pid), "obj")
        how = "mesmo comando do ExecStart" if p.cmd == svc.execstart else "PID citado no journal"
        b.add(p.src, f"processo {p.pid} (PPID {p.ppid}, user {p.user}): {p.cmd} [{how}]", p.to_ecs())


def file_fact(e: FileEntry) -> str:
    flags = [k for k, v in e.flags.items() if v]
    return f"{e.path} modo {e.mode} {e.owner}:{e.group}" + (f" [{', '.join(flags)}]" if flags else "")


def make_finding(meta_file: str, target: str, title: str, description: str, b: Builder,
                 interpretation: str | None = None, missing=(), confidence: int | None = None, severity: int | None = None) -> Finding:
    m = load_meta(meta_file)
    return Finding(
        rule_id=m["id"], target=target, title=title, description=description,
        severity=severity or m["severity"], confidence=confidence or m["confidence"],
        classification=m["classification"], evidences=b.items,
        interpretation=interpretation or m["interpretation"],
        missing_evidence=list(dict.fromkeys([*m["missing_evidence"], *missing])),
        not_proven=m["not_proven"], false_positives=m["false_positives"],
        correlates=m.get("correlates", []))

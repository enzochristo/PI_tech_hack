"""Grafo de proveniência (1ª camada do HOLMES): entidades e relações entre processos, serviços e arquivos.

Nós:    ("process", pid) ("service", unit) ("file"|"dir", path) ("user", nome)
        ("logevent", origem) ("remote", host)
Arestas: parent_of, runs_as, executes (processo/serviço -> binário), uses_script (-> script),
         has_process (serviço -> processo), inside_dir, logged_by (evento -> processo), connects_to
Cada aresta guarda as origens (arquivo:linha) que a sustentam.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .model import Inventory
from .normalize import parent_dirs, remote_hosts

Node = tuple[str, object]


@dataclass
class Edge:
    type: str
    src: Node
    dst: Node
    sources: tuple[str, ...]


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[Node, dict] = {}
        self._out: dict[Node, list[Edge]] = defaultdict(list)
        self._in: dict[Node, list[Edge]] = defaultdict(list)

    def add_node(self, kind: str, key, **attrs) -> Node:
        node = (kind, key)
        self.nodes.setdefault(node, {}).update(attrs)
        return node

    def add_edge(self, etype: str, a: Node, b: Node, sources=()) -> None:
        e = Edge(etype, a, b, tuple(sources))
        self._out[a].append(e)
        self._in[b].append(e)

    def out(self, node: Node, etype: str | None = None) -> list[Edge]:
        return [e for e in self._out[node] if etype in (None, e.type)]

    def into(self, node: Node, etype: str | None = None) -> list[Edge]:
        return [e for e in self._in[node] if etype in (None, e.type)]

    def attr(self, node: Node, name: str):
        return self.nodes.get(node, {}).get(name)

    # ---- visualização (eventos de log ficam de fora para não poluir) ----
    def _visible(self) -> list[Edge]:
        return [e for edges in self._out.values() for e in edges
                if "logevent" not in (e.src[0], e.dst[0])]

    @staticmethod
    def _label(n: Node) -> str:
        return f"{n[0]}:{n[1]}"

    def to_text(self) -> str:
        by_type: dict[str, list[Edge]] = defaultdict(list)
        for e in self._visible():
            by_type[e.type].append(e)
        lines = ["GRAFO DE PROVENIÊNCIA (arestas por tipo; eventos de log omitidos)"]
        for etype, edges in sorted(by_type.items()):
            lines.append(f"\n{etype}  ({len(edges)})")
            lines += [f"  {self._label(e.src)}  ->  {self._label(e.dst)}" for e in edges[:40]]
            if len(edges) > 40:
                lines.append(f"  ... +{len(edges) - 40} arestas")
        return "\n".join(lines)

    def to_dot(self) -> str:
        shapes = {"process": "ellipse", "service": "box", "file": "note", "dir": "folder",
                  "user": "diamond", "remote": "hexagon"}
        lines = ["digraph provenance {", "  rankdir=LR; node [fontsize=10]; edge [fontsize=9];"]
        used: set[Node] = set()
        edges = self._visible()
        for e in edges:
            used |= {e.src, e.dst}
        for n in used:
            lines.append(f'  "{self._label(n)}" [shape={shapes.get(n[0], "ellipse")}];')
        for e in edges:
            lines.append(f'  "{self._label(e.src)}" -> "{self._label(e.dst)}" [label="{e.type}"];')
        return "\n".join(lines + ["}"])


def build_graph(inv: Inventory) -> Graph:
    g = Graph()
    procs = {p.pid: g.add_node("process", p.pid, obj=p) for p in inv.processes}

    for f in inv.files:
        g.add_node("dir" if f.is_dir else "file", f.path, obj=f)

    def file_node(path: str) -> Node:
        # caminho citado por um comando mas sem linha em permissions.csv: nó sem atributos
        return ("dir", path) if ("dir", path) in g.nodes else g.add_node("file", path)

    for p in inv.processes:
        node = procs[p.pid]
        g.add_edge("runs_as", node, g.add_node("user", p.user), [p.src])
        if p.ppid in procs:
            g.add_edge("parent_of", procs[p.ppid], node, [p.src])
        if p.executable:
            g.add_edge("executes", node, file_node(p.executable), [p.src])
        if p.script:
            g.add_edge("uses_script", node, file_node(p.script), [p.src])
        for host in remote_hosts(p.executable, p.args):
            g.add_edge("connects_to", node, g.add_node("remote", host), [p.src])

    svcs = {}
    for s in inv.services:
        node = svcs[s.unit] = g.add_node("service", s.unit, obj=s)
        g.add_edge("runs_as", node, g.add_node("user", s.user), [s.src])
        if s.executable:
            g.add_edge("executes", node, file_node(s.executable), [s.src])
        if s.script:
            g.add_edge("uses_script", node, file_node(s.script), [s.src])

    # serviço -> processo: mesmo comando do ExecStart, ou PID citado no journal pelo nome do serviço.
    # O log é ligado ao processo pelo PID, nunca pelo nome do executável.
    links: dict[tuple[str, int], list[str]] = defaultdict(list)
    for s in inv.services:
        for p in inv.processes:
            if p.cmd == s.execstart:
                links[(s.unit, p.pid)] += [s.src, p.src]
        if s.main_pid in procs:
            links[(s.unit, s.main_pid)].append(s.src)
        for ev in inv.logs:
            if ev.pid in procs and ev.ident == s.name:
                links[(s.unit, ev.pid)].append(ev.src)
    for (unit, pid), sources in links.items():
        g.add_edge("has_process", svcs[unit], procs[pid], dict.fromkeys(sources))

    for ev in inv.logs:
        node = g.add_node("logevent", ev.src, obj=ev)
        if ev.pid in procs:
            g.add_edge("logged_by", node, procs[ev.pid], [ev.src])

    # inside_dir: cada arquivo/diretório aponta para o pai imediato; a cadeia até "/" se forma sozinha
    pending = [n for n in g.nodes if n[0] in ("file", "dir")]
    while pending:
        node = pending.pop()
        parents = parent_dirs(node[1])
        if not parents:
            continue
        pnode = ("dir", parents[0])
        if pnode not in g.nodes:
            g.add_node("dir", parents[0])
            pending.append(pnode)
        g.add_edge("inside_dir", node, pnode)
    return g

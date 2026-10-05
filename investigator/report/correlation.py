"""Matriz de correlação entre fontes (processos, serviços, permissões, logs).

Cada regra declara em seu .toml as fontes que cruza (`correlates`). A matriz é derivada dessas declarações:
- estática: o que a ferramenta É CAPAZ de correlacionar (todas as regras);
- dinâmica: o que foi de fato correlacionado neste snapshot (regras que geraram finding).
"""

from __future__ import annotations

from itertools import combinations

from ..rules import RULES_DIR, load_meta

SOURCES = ["processos", "servicos", "permissoes", "logs"]
LABEL = {"processos": "Processos", "servicos": "Serviços", "permissoes": "Permissões", "logs": "Logs"}

# chave de ligação usada em cada par (como o grafo/normalização realmente liga as fontes)
JOIN_KEYS = {
    ("processos", "servicos"): "comando do processo = ExecStart; MainPID; PID citado no journal",
    ("processos", "permissoes"): "executável/script do comando = caminho do arquivo",
    ("servicos", "permissoes"): "script/binário do ExecStart = arquivo (e seus diretórios pai)",
    ("processos", "logs"): "PID da linha de log = PID do processo; PPID/usuário para sudo/su e sessão",
    ("servicos", "logs"): "identificador da linha de log = nome do serviço",
    ("permissoes", "logs"): "mtime do arquivo × horário do evento (linha do tempo)",
}


def _pairs(sources: list[str]) -> list[tuple[str, str]]:
    ordered = sorted(set(sources), key=SOURCES.index)
    return [tuple(p) for p in combinations(ordered, 2)] if len(ordered) > 1 else [(ordered[0], ordered[0])]


def _build(rule_sources: dict[str, list[str]]) -> dict[str, list[str]]:
    cells: dict[tuple[str, str], set[str]] = {}
    for rule, sources in rule_sources.items():
        for pair in _pairs(sources):
            cells.setdefault(pair, set()).add(rule)
    return {f"{a}×{b}": sorted(r) for (a, b), r in sorted(cells.items(), key=lambda kv: (SOURCES.index(kv[0][0]), SOURCES.index(kv[0][1])))}


def static_matrix() -> dict[str, list[str]]:
    metas = [load_meta(p.name) for p in sorted(RULES_DIR.glob("*.toml"))]
    return _build({m["id"]: m["correlates"] for m in metas if m.get("correlates")})


def dynamic_matrix(findings) -> dict[str, list[str]]:
    return _build({f.rule_id: f.correlates for f in findings if f.correlates})


def render(findings) -> str:
    static, dynamic = static_matrix(), dynamic_matrix(findings)
    lines = ["MATRIZ DE CORRELAÇÃO ENTRE FONTES",
             "(capacidade = regras que cruzam o par; neste snapshot = regras que geraram finding)", ""]
    header = f"{'':<12}" + "".join(f"{LABEL[s]:<22}" for s in SOURCES)
    for title, m in (("Capacidade da ferramenta", static), ("Neste snapshot", dynamic)):
        lines += [title, header]
        for a in SOURCES:
            row = f"{LABEL[a]:<12}"
            for b in SOURCES:
                key = f"{a}×{b}" if SOURCES.index(a) <= SOURCES.index(b) else f"{b}×{a}"
                row += f"{(','.join(m.get(key, [])) or '·'):<22}"
            lines.append(row)
        lines.append("")
    lines.append("Chaves de ligação:")
    lines += [f"  {LABEL[a]} × {LABEL[b]}: {k}" for (a, b), k in JOIN_KEYS.items()]
    return "\n".join(lines)

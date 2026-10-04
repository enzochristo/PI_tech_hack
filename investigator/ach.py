"""Matriz ACH (Analysis of Competing Hypotheses, Heuer).

Hipóteses nas colunas, evidências nas linhas, cada célula C (consistente), I (inconsistente) ou N (neutra).
Vence a hipótese com MENOS inconsistências. Empate no topo = INCONCLUSIVO. Confiança = margem para a 2ª.
As marcações são codificadas aqui, por regra (no método original quem marca é um analista humano).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .model import Evidence, Finding, Inventory
from .normalize import ACCEPTED_RE, parent_dirs

HYPOTHESES = {
    "H1": "configuração legítima, sem risco",
    "H2": "má configuração explorável, sem exploração observada",
    "H3": "a exploração já ocorreu",
}


HYP_BY_RULE = {
    "R2": {"H1": "elevação legítima (sudo/su) sem log coletado",
           "H2": "elevação por mecanismo não registrado (ex.: setuid), sem abuso comprovado",
           "H3": "escalada de privilégio indevida"},
    "R5": {"H1": "uso legítimo do serviço (ex.: checagem de status, métricas)",
           "H2": "destino ou uso inesperado, sem evidência de exfiltração",
           "H3": "canal de comando/exfiltração (C2) ativo"},
}


def _find(f: Finding, pred) -> Evidence | None:
    return next((e for e in f.evidences if pred(e)), None)


@dataclass
class Row:
    eid: str
    label: str
    marks: dict[str, str]
    fragile: bool = False
    core: bool = False  # evidência que define o próprio finding: não entra na análise de sensibilidade

    @property
    def diagnostic(self) -> bool:
        return len(set(self.marks.values())) > 1


def _m(h1: str, h2: str, h3: str) -> dict[str, str]:
    return {"H1": h1, "H2": h2, "H3": h3}


def decide(rows: list[Row], drop: Row | None = None) -> tuple[str, dict[str, int], list[str]]:
    inc = {h: sum(1 for r in rows if r is not drop and r.marks[h] == "I") for h in HYPOTHESES}
    best = min(inc.values())
    tied = [h for h in HYPOTHESES if inc[h] == best]
    return (tied[0] if len(tied) == 1 else "INCONCLUSIVO"), inc, tied


def _confidence(verdict: str, inc: dict[str, int]) -> int:
    if verdict == "INCONCLUSIVO":
        return 1
    margin = sorted(v for h, v in inc.items() if h != verdict)[0] - inc[verdict]
    return 2 if margin == 1 else 3


def _add(f: Finding, source: str, fact: str) -> str:
    e = Evidence(f"E{len(f.evidences) + 1}", source, fact)
    f.evidences.append(e)
    return e.id


def _ids(f: Finding, prefix: str) -> str:
    return "+".join(e.id for e in f.evidences if e.source.startswith(prefix)) or "-"


def _service_rows(f: Finding, inv: Inventory, svc) -> list[Row]:
    rows = [Row(f.evidences[0].id, "serviço executa como root", _m("C", "C", "C"))]
    for ev in inv.logs:
        if ev.pid and ev.ident == svc.name and "status=OK" in ev.message:
            eid = _add(f, ev.src, f"{ev.ident}[{ev.pid}]: {ev.message}")
            rows.append(Row(eid, "execução do serviço terminou com status=OK", _m("C", "C", "N")))
    return rows


def _r1_rows(f: Finding, inv: Inventory) -> list[Row]:
    svc = next(s for s in inv.services if f.target in (s.script, s.executable) and s.user == "root")
    rows = _service_rows(f, inv, svc)
    rows.insert(1, Row(_ids(f, "permissions.csv"), "recurso alterável por identidade não privilegiada",
                       _m("I", "C", "C"), core=True))
    entry = next((x for x in inv.files if x.path == f.target), None)
    for ev in inv.logs:
        m = ACCEPTED_RE.search(ev.message)
        if not m or m.group(1) == "root":
            continue
        user = m.group(1)
        eid = _add(f, ev.src, f"sessão SSH de {user} aceita em {ev.timestamp} (origem {m.group(2)})")
        rows.append(Row(eid, f"usuário comum ({user}) presente na máquina", _m("N", "C", "C")))
        if entry:
            before = datetime.fromisoformat(entry.mtime) < datetime.fromisoformat(ev.timestamp)
            mid = _add(f, entry.src, f"mtime de {entry.path} = {entry.mtime}, "
                                      f"{'anterior' if before else 'posterior'} ao login de {user} ({ev.timestamp})")
            # mtime anterior ao login contradiz exploração por esse usuário. Frágil: depende de relógio/fuso e
            # um atacante com privilégio pode forjar o mtime.
            rows.append(Row(mid, f"mtime {'anterior' if before else 'posterior'} ao login de {user}",
                            _m("N", "C", "I" if before else "C"), fragile=True))
    return rows


def _r7_rows(f: Finding, inv: Inventory) -> list[Row]:
    svc = next(s for s in inv.services if s.script == f.target)
    rows = _service_rows(f, inv, svc)
    unknown = any(not any(x.path == p for x in inv.files) for p in parent_dirs(f.target))
    rows.insert(1, Row(_ids(f, "permissions.csv"), "recurso e diretórios coletados só alteráveis por root",
                       _m("C", "I", "I"), fragile=unknown, core=True))
    return rows


def _r6_rows(f: Finding, inv: Inventory) -> list[Row]:
    return [
        Row(f.evidences[0].id, "arquivo alterável por qualquer usuário", _m("I", "C", "C"), core=True),
        # o snapshot não enxerga cron/timers: ausência de consumidor é evidência frágil
        Row(f.evidences[1].id, "nenhum serviço/processo coletado usa o arquivo", _m("C", "C", "I"), fragile=True),
    ]


def _r2_rows(f: Finding, inv: Inventory) -> list[Row]:
    rows = [Row(f.evidences[0].id, "processo root é filho de processo de usuário comum", _m("C", "C", "C"), core=True)]
    absence = _find(f, lambda e: "ausência" in e.source)
    # o journal pode estar incompleto: ausência de sudo/su é evidência frágil
    rows.append(Row(absence.id, "nenhum registro de sudo/su no journal", _m("I", "C", "C"), fragile=True))
    sess = _find(f, lambda e: e.fact.startswith("sessão SSH"))
    if sess:
        rows.append(Row(sess.id, "sessão de login do usuário de origem registrada", _m("N", "C", "C")))
    return rows


def _r5_rows(f: Finding, inv: Inventory) -> list[Row]:
    rows = [Row(f.evidences[0].id, "processo root, filho de serviço, conecta a destino remoto", _m("C", "C", "C"), core=True)]
    logs = [e.id for e in f.evidences if e.source.startswith("journal.log") and e.fact[:1].isalpha()]
    if logs:
        rows.append(Row("+".join(logs), "o serviço registra a atividade de rede no log", _m("C", "N", "N")))
    perm = _find(f, lambda e: e.source.startswith("permissions.csv"))
    if perm:
        if "alterável" in perm.fact:
            rows.append(Row(perm.id, "script do serviço alterável por não-root (R1)", _m("N", "C", "C")))
        else:
            # conexão não pode ter sido plantada por não-root; mas o conteúdo pode ser malicioso desde a instalação
            rows.append(Row(perm.id, "script do serviço só alterável por root", _m("C", "N", "I"), fragile=True))
    return rows


ROW_BUILDERS = {"R1": _r1_rows, "R7": _r7_rows, "R6": _r6_rows, "R2": _r2_rows, "R5": _r5_rows}


def analyze(f: Finding, inv: Inventory) -> None:
    if f.rule_id not in ROW_BUILDERS:
        return  # R3 (contexto) e R4 não têm hipóteses concorrentes modeladas
    hyps = HYP_BY_RULE.get(f.rule_id, HYPOTHESES)
    rows = ROW_BUILDERS[f.rule_id](f, inv)
    verdict, inc, tied = decide(rows)
    dependent = []
    for r in rows:
        if not r.core and any(v == "I" for v in r.marks.values()) and decide(rows, drop=r)[0] != verdict:
            dependent.append(r.eid)
    f.verdict = verdict
    f.confidence = _confidence(verdict, inc)
    if verdict == "INCONCLUSIVO":
        f.missing_evidence.append(
            f"empate entre {', '.join(tied)}: nenhuma evidência coletada distingue essas hipóteses")
    f.ach = {
        "hypotheses": hyps,
        "rows": [{"evidence": r.eid, "label": r.label, "marks": r.marks, "diagnostic": r.diagnostic,
                  "fragile": r.fragile} for r in rows],
        "inconsistencies": inc, "verdict": verdict, "tied": tied,
        "sensitivity": dependent,
    }

"""Grafo de cenário (2ª camada do HOLMES): nós = findings; pré-requisitos entre regras filtram falsos positivos.

Hoje só R1/R6/R7 existem, então não há pré-requisitos ativos; a estrutura recebe R3/R5 na Etapa 3.
"""

from __future__ import annotations

from .model import Finding

# regra -> regras cujo disparo é pré-requisito (finding sem pré-requisito disparado é descartado)
PREREQS: dict[str, list[str]] = {"R3": ["R1"]}


def apply_prerequisites(findings: list[Finding]) -> list[Finding]:
    fired = {f.rule_id for f in findings}
    return [f for f in findings if all(p in fired for p in PREREQS.get(f.rule_id, []))]


def score(findings: list[Finding]) -> float:
    """Produto ponderado (ideia do HOLMES) sobre os findings de RISCO: severidade/5 x confiança/3.
    1.0 = nenhum risco; quanto menor, maior a ameaça combinada do cenário. Adaptação nossa."""
    s = 1.0
    for f in findings:
        if f.classification == "RISCO":
            s *= 1 - (f.severity / 5) * (f.confidence / 3)
    return round(s, 3)

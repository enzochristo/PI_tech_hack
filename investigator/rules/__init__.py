"""Regras: metadados declarativos em TOML (estilo Sigma) + matcher em Python que consulta o grafo."""

from __future__ import annotations

import re
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10: parser mínimo para o subconjunto usado nos .toml das regras
    tomllib = None

RULES_DIR = Path(__file__).parent


def _mini_toml(text: str) -> dict:
    """Suporta `chave = "texto"`, `chave = inteiro` e listas de strings (inclusive multilinha)."""
    out: dict = {}
    items = re.findall(r'^(\w+)\s*=\s*(\[.*?\]|"(?:[^"\\]|\\.)*"|\d+)\s*$', text, re.S | re.M)
    for key, val in items:
        if val.startswith("["):
            out[key] = [s.encode().decode("unicode_escape") if "\\" in s else s
                        for s in re.findall(r'"((?:[^"\\]|\\.)*)"', val)]
        elif val.startswith('"'):
            out[key] = val[1:-1].replace('\\"', '"')
        else:
            out[key] = int(val)
    return out


def load_meta(filename: str) -> dict:
    text = (RULES_DIR / filename).read_text(encoding="utf-8")
    return tomllib.loads(text) if tomllib else _mini_toml(text)


def run_all(inv, graph) -> list:
    from . import (r1_privilege, r2_context, r3_timeline, r4_suid, r5_outbound, r6_misconfig,
                   r7_legit)
    findings: list = []

    def number() -> None:
        for f in findings:
            if not f.uid:
                f.uid = f"F-{findings.index(f) + 1:03d}"

    for mod in (r1_privilege, r6_misconfig, r7_legit, r4_suid, r2_context):
        findings += mod.run(inv, graph)
    number()
    # R3 e R5 dependem de R1 (grafo de cenário): recebem os findings já produzidos
    for mod in (r3_timeline, r5_outbound):
        findings += mod.run(inv, graph, list(findings))
    number()
    return findings

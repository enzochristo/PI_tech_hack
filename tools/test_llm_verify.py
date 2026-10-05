#!/usr/bin/env python3
"""Teste offline da camada LLM: usa uma API falsa (sem rede, sem chave) e confere o verificador."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from investigator import progress  # noqa: E402
from investigator.__main__ import analyze  # noqa: E402
from investigator.llm.client import explain  # noqa: E402
from investigator.llm.verify import render, verify  # noqa: E402
from investigator.report import ocsf  # noqa: E402

progress.enabled = False
inv, _, findings = analyze(sys.argv[1] if len(sys.argv) > 1 else "training/correlation")
report = ocsf.to_report(findings, inv)
r1 = next(f for f in report["findings"] if f["finding_info"]["analytic"]["uid"] == "R1")
uid = r1["finding_info"]["uid"]

CASES = [  # (afirmação, citações, deve ser aceita?)
    ("O backup-agent roda como root e executa /opt/backup/backup.sh, que qualquer usuário pode alterar.", ["E1", "E3"], True),
    ("Não há evidência de que o script foi alterado depois do login do aluno.", ["E6"], True),
    ("O script foi alterado.", [], False),                                        # sem citação
    ("O serviço usa o script de backup.", ["E99"], False),                        # evidência inexistente
    ("O atacante leu /etc/shadow antes do backup.", ["E3"], False),               # caminho inventado
    ("A conexão partiu de 8.8.8.8.", ["E2"], False),                              # IP inventado
    ("O processo 99999 executou o script.", ["E2"], False),                       # PID inventado
    ("A exploração foi confirmada pelo log.", ["E4"], False),                     # exagero (veredito não é H3)
]
fake = {"findings": [{
    "uid": uid,
    "narrative": [{"text": t, "cites": c} for t, c, _ in CASES[:6]],
    "extra_hypotheses": [{"text": t, "cites": c} for t, c, _ in CASES[6:]],
    "second_opinion": {"agrees": True, "comment": "Concordo com H2 pelas evidências citadas.", "cites": ["E3", "E6"]},
}]}

body_seen = {}


def stub_post(body, key, timeout):
    body_seen.update(body)
    return {"choices": [{"message": {"content": json.dumps(fake)}}]}


result, model, skipped = explain(report, post=stub_post)
v = verify(result, report)
rec = v["findings"][uid]
kept = {c["text"] for c in rec["narrative"] + rec["extra_hypotheses"]}
bad = 0
for text, _, should_keep in CASES:
    ok = (text in kept) == should_keep
    bad += not ok
    print(f"{'OK ' if ok else 'ERRO'} {'aceita  ' if text in kept else 'descartada'}  {text[:70]}")
print(f"second_opinion mantida: {rec['second_opinion'] is not None}")
assert "dados crus" not in json.dumps(body_seen), "payload inesperado"
sent = json.loads(body_seen["messages"][1]["content"].split("\n", 1)[1])
assert all(set(f) >= {"uid", "evidences"} for f in sent), "a LLM deve receber findings estruturados"
assert "processes.csv" not in json.dumps(sent).split('"source"')[0], "dados crus vazaram"
print(f"\ntaxa de afirmações sem suporte: {v['unsupported_rate']:.0%} ({v['discarded_claims']}/{v['total_claims']})")

# segunda opinião em branco não deve contar como afirmação descartada
blank = {"findings": [{"uid": uid, "narrative": [{"text": CASES[0][0], "cites": ["E1", "E3"]}],
                       "extra_hypotheses": [], "second_opinion": {"agrees": True, "comment": "", "cites": []}}]}
vb = verify(blank, report)
assert vb["total_claims"] == 1 and vb["discarded_claims"] == 0, vb
print("OK  segunda opinião em branco não conta como afirmação")

sys.exit(1 if bad else 0)

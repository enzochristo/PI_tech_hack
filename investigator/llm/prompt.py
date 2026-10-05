"""Prompt e schema da camada LLM. A LLM recebe SÓ os findings já produzidos (formato OCSF + matriz ACH),
nunca os dados crus do sistema."""

from __future__ import annotations

import json

MAX_FINDINGS = 12

SYSTEM = """Você redige a explicação de findings de segurança produzidos por uma ferramenta determinística.
Regras obrigatórias:
1. Use SOMENTE os dados do JSON recebido. Não invente caminhos, IPs, PIDs, usuários, horários nem comandos.
2. Toda afirmação deve citar, no campo "cites", os ids de evidência (ex.: "E1", "E3") do MESMO finding.
3. Não altere classificação, severidade, confiança nem veredito. Se discordar do veredito, diga isso em
   "second_opinion" (agrees=false) e cite as evidências que motivam a discordância.
4. Nunca afirme que houve exploração, comprometimento, C2 ou exfiltração, a menos que o veredito seja H3.
   Prefira "pode", "é compatível com", "não há evidência de".
5. Hipóteses extras ("extra_hypotheses") são possibilidades que as hipóteses H1..H3 não cobrem; cada uma
   deve citar a evidência que a motiva. Se não houver nenhuma, devolva lista vazia.
6. Seja conciso: 2 a 4 afirmações na narrativa de cada finding. Responda em português do Brasil.
7. Se um fato não está nas evidências, não o afirme.
8. Como ler o veredito: a hipótese vencedora é a de MENOR número de inconsistências (I) na matriz ACH.
   H2 significa "má configuração explorável, SEM exploração observada": a ausência de exploração observada
   SUSTENTA H2, não a contradiz. "INCONCLUSIVO" significa empate entre hipóteses.
9. Só use "agrees": false se uma evidência citada contradiz diretamente o veredito, e explique qual. Em caso
   de dúvida, concorde. Se o finding não tem matriz ACH (veredito "(sem matriz ACH)") ou você não tem nada a
   acrescentar, devolva agrees=true, comment="" e cites=[].
10. Cite apenas evidências que sustentam DIRETAMENTE a frase. Um mtime ANTERIOR ao login de um usuário
    enfraquece a hipótese de que esse usuário alterou o recurso (ele não poderia tê-lo alterado antes de entrar)."""

CLAIM = {
    "type": "object",
    "properties": {"text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "string"}}},
    "required": ["text", "cites"],
    "additionalProperties": False,
}

SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "uid": {"type": "string"},
                    "narrative": {"type": "array", "items": CLAIM},
                    "extra_hypotheses": {"type": "array", "items": CLAIM},
                    "second_opinion": {
                        "type": "object",
                        "properties": {
                            "agrees": {"type": "boolean"},
                            "comment": {"type": "string"},
                            "cites": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["agrees", "comment", "cites"],
                        "additionalProperties": False,
                    },
                },
                "required": ["uid", "narrative", "extra_hypotheses", "second_opinion"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}


def finding_view(f: dict) -> dict:
    inv = f["investigation"]
    return {
        "uid": f["finding_info"]["uid"],
        "rule": f["finding_info"]["analytic"]["uid"],
        "title": f["finding_info"]["title"],
        "description": f["finding_info"]["desc"],
        "target": inv["target"],
        "classification": inv["classification"],
        "severity": f["severity"],
        "confidence": f["confidence"],
        "verdict": inv.get("verdict") or "(sem matriz ACH)",
        "hypotheses": inv.get("hypotheses", {}),
        "evidences": [{"id": e["data"]["id"], "source": e["data"]["source"], "fact": e["data"]["fact"]}
                      for e in f["evidences"]],
        "ach_rows": (inv.get("ach_matrix") or {}).get("rows", []),
        "interpretation": inv["interpretation"],
        "missing_evidence": inv["missing_evidence"],
        "not_proven": inv["not_proven"],
        "known_false_positives": inv["known_false_positives"],
    }


def build_payload(report: dict) -> tuple[list[dict], int]:
    """Retorna (findings enviados, quantos ficaram de fora pelo limite)."""
    views = [finding_view(f) for f in report["findings"]]
    return views[:MAX_FINDINGS], max(0, len(views) - MAX_FINDINGS)


def user_message(views: list[dict]) -> str:
    return "Findings (JSON):\n" + json.dumps(views, ensure_ascii=False, indent=1)

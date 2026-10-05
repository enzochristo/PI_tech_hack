"""Verificador pós-geração: descarta toda afirmação da LLM sem base nas evidências do finding.

Uma afirmação é descartada se:
  1. não cita nenhuma evidência;
  2. cita um id que não existe naquele finding;
  3. menciona caminho, IP ou PID que não aparece em nada que a ferramenta produziu para o finding;
  4. afirma exploração/comprometimento sem negação, quando o veredito não é H3.
"""

from __future__ import annotations

import json
import re

PATH_RE = re.compile(r"(?<![\w.])/[\w.\-]+(?:/[\w.\-]+)*")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PID_RE = re.compile(r"\b(?:PID|PPID|processo)\s+(\d+)\b", re.I)
_ASSERT = r"(foi|foram|houve|ocorreu|ocorreram|confirmad\w+|comprovad\w+)"
_THREAT = r"(explora\w*|comprometi\w+|invas\w+|malicios\w+|\bC2\b|exfiltra\w+)"
# afirmação nas duas ordens: "foi explorado" e "a exploração foi confirmada"
OVERCLAIM_RE = re.compile(rf"{_ASSERT}.{{0,50}}{_THREAT}|{_THREAT}.{{0,50}}{_ASSERT}", re.I)
NEGATION_RE = re.compile(r"\b(não|nao|sem|nenhum\w*|nunca|ausên\w+|inexist\w+)\b", re.I)


def _corpus(f: dict) -> str:
    inv = f["investigation"]
    parts = [f["finding_info"]["title"], f["finding_info"]["desc"], inv["target"], inv["interpretation"],
             inv["not_proven"], *inv["missing_evidence"], *inv["known_false_positives"],
             *inv.get("hypotheses", {}).values(), *(e["data"]["fact"] for e in f["evidences"])]
    return "\n".join(parts)


def check_claim(text: str, cites: list[str], ids: set[str], corpus: str, verdict: str) -> str | None:
    """Retorna o motivo do descarte, ou None se a afirmação é aceita."""
    if not cites:
        return "sem citação de evidência"
    bad = [c for c in cites if c not in ids]
    if bad:
        return f"cita evidência inexistente: {', '.join(bad)}"
    for token in PATH_RE.findall(text) + IP_RE.findall(text):
        if token not in corpus:
            return f"menciona '{token}', que não está nas evidências"
    for pid in PID_RE.findall(text):
        if not re.search(rf"\b{pid}\b", corpus):
            return f"menciona o PID {pid}, que não está nas evidências"
    if verdict != "H3" and OVERCLAIM_RE.search(text) and not NEGATION_RE.search(text):
        return "afirma exploração/comprometimento sem base (veredito não é H3)"
    return None


def verify(result: dict, report: dict) -> dict:
    by_uid = {f["finding_info"]["uid"]: f for f in report["findings"]}
    out, total, discarded = {}, 0, 0
    for entry in result.get("findings", []):
        f = by_uid.get(entry.get("uid"))
        claims = [*entry.get("narrative", []), *entry.get("extra_hypotheses", [])]
        so = entry.get("second_opinion")
        if so and not (so.get("comment", "").strip() or so.get("cites")):
            so = None  # segunda opinião em branco = "sem opinião", não conta como afirmação
        n = len(claims) + (1 if so else 0)
        total += n
        if f is None:
            discarded += n
            out[entry.get("uid", "?")] = {"discarded": [{"text": "(finding inexistente)", "reason": "uid desconhecido"}],
                                          "narrative": [], "extra_hypotheses": [], "second_opinion": None}
            continue
        ids = {e["data"]["id"] for e in f["evidences"]}
        corpus, verdict = _corpus(f), f["investigation"].get("verdict", "")
        rec = {"narrative": [], "extra_hypotheses": [], "second_opinion": None, "discarded": []}

        def screen(kind: str, c: dict) -> None:
            nonlocal discarded
            text, cites = c.get("text") or c.get("comment", ""), c.get("cites", [])
            reason = check_claim(text, cites, ids, corpus, verdict)
            if reason:
                discarded += 1
                rec["discarded"].append({"text": text, "reason": reason})
            elif kind == "second_opinion":
                rec["second_opinion"] = {"agrees": c["agrees"], "comment": text, "cites": cites}
            else:
                rec[kind].append({"text": text, "cites": cites})

        for c in entry.get("narrative", []):
            screen("narrative", c)
        for c in entry.get("extra_hypotheses", []):
            screen("extra_hypotheses", c)
        if so:
            screen("second_opinion", so)
        out[entry["uid"]] = rec
    return {"findings": out, "total_claims": total, "discarded_claims": discarded,
            "unsupported_rate": round(discarded / total, 3) if total else 0.0}


def render(v: dict, model: str, skipped: int = 0) -> str:
    lines = ["ANÁLISE ASSISTIDA POR LLM (verificada)",
             f"modelo: {model} · a LLM NÃO altera classificação, severidade, confiança nem veredito", ""]
    for uid, rec in v["findings"].items():
        lines.append(f"[{uid}]")
        for c in rec["narrative"]:
            lines.append(f"  - {c['text']} [{', '.join(c['cites'])}]")
        for c in rec["extra_hypotheses"]:
            lines.append(f"  ? hipótese extra: {c['text']} [{', '.join(c['cites'])}]")
        so = rec["second_opinion"]
        if so:
            lines.append(f"  segunda opinião ({'concorda' if so['agrees'] else 'DISCORDA'} do veredito "
                         f"determinístico): {so['comment']} [{', '.join(so['cites'])}]")
        for d in rec["discarded"]:
            lines.append(f"  x descartada ({d['reason']}): {d['text'][:90]}")
        lines.append("")
    lines.append(f"Afirmações descartadas pelo verificador: {v['discarded_claims']} de {v['total_claims']} "
                 f"(taxa de afirmações sem suporte: {v['unsupported_rate']:.0%})")
    if skipped:
        lines.append(f"Aviso: {skipped} finding(s) não enviados à LLM (limite por requisição).")
    return "\n".join(lines)

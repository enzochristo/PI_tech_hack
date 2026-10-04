from __future__ import annotations

from ..model import Finding
from .ocsf import CONFIDENCE, SEVERITY


def render(findings: list[Finding], artifacts: list[dict]) -> str:
    out = ["Artefatos analisados (SHA-256):"]
    out += [f"  {a['sha256'][:16]}…  {a['name']}" for a in artifacts]
    if not findings:
        out += ["", "Nenhum finding: as evidências coletadas não indicam situação que mereça investigação."]
    for f in findings:
        out += [
            "", f"[{f.uid}] {f.rule_id} · {f.classification} · severidade {SEVERITY[f.severity]} · "
                f"confiança {CONFIDENCE[f.confidence]}",
            f"  {f.title}", f"  alvo: {f.target}", "  EVIDÊNCIAS (observado)",
        ]
        out += [f"    {e.id} [{e.source}] {e.fact}" for e in f.evidences]
        out += ["  INTERPRETAÇÃO", f"    {f.interpretation}"]
        if f.ach:
            a = f.ach
            out += ["  HIPÓTESES / MATRIZ ACH (C consistente, I inconsistente, N neutra)"]
            out += [f"    {h}: {d}  [inconsistências: {a['inconsistencies'][h]}]" for h, d in a["hypotheses"].items()]
            for r in a["rows"]:
                tag = "" if r["diagnostic"] else "  (não diagnóstica)"
                tag += "  (frágil)" if r["fragile"] else ""
                out.append(f"    {r['evidence']:<8} {r['marks']['H1']} {r['marks']['H2']} {r['marks']['H3']}  {r['label']}{tag}")
            out.append(f"    VEREDITO: {f.verdict}" + (f" (empate entre {', '.join(a['tied'])})" if f.verdict == "INCONCLUSIVO" else ""))
            if a["sensitivity"]:
                out.append(f"    SENSIBILIDADE: a conclusão depende de {', '.join(a['sensitivity'])}")
        out += [
                "  NÃO PROVADO", f"    {f.not_proven}", "  EVIDÊNCIA AUSENTE"]
        out += [f"    - {m}" for m in f.missing_evidence]
    return "\n".join(out)

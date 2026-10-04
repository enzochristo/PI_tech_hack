"""Finding no formato OCSF Detection Finding (classe 2004).

O OCSF não tem campos para interpretação/hipótese; esses dados ficam no bloco de extensão `investigation`.
"""

from __future__ import annotations

from datetime import datetime

from .. import scenario
from ..model import Finding, Inventory

SEVERITY = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
CONFIDENCE = {1: "Low", 2: "Medium", 3: "High"}


def _epoch_ms(inv: Inventory) -> int:
    # hora da coleta = menor timestamp de processes.csv (determinístico para o mesmo dataset)
    return int(min(datetime.fromisoformat(p.collected_at) for p in inv.processes).timestamp() * 1000)


def to_ocsf(f: Finding, inv: Inventory) -> dict:
    return {
        "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2,
        "activity_id": 1, "type_uid": 200401,
        "time": _epoch_ms(inv),
        "severity_id": f.severity, "severity": SEVERITY[f.severity],
        "confidence_id": f.confidence, "confidence": CONFIDENCE[f.confidence],
        "status_id": 1,
        "metadata": {"version": "1.4.0", "product": {"name": "endpoint-investigator"}},
        "finding_info": {
            "uid": f.uid, "title": f.title, "desc": f.description,
            "analytic": {"uid": f.rule_id, "type_id": 1, "type": "Rule"},
        },
        "evidences": [{"data": {"id": e.id, "source": e.source, "fact": e.fact, "ecs": e.ecs}}
                      for e in f.evidences],
        "investigation": {
            "target": f.target,
            "classification": f.classification,
            "interpretation": f.interpretation,
            "hypotheses": f.ach["hypotheses"] if f.ach else {},
            "verdict": f.verdict,
            "ach_matrix": f.ach,
            "missing_evidence": f.missing_evidence,
            "not_proven": f.not_proven,
            "known_false_positives": f.false_positives,
        },
    }


def to_report(findings: list[Finding], inv: Inventory) -> dict:
    return {
        "tool": "endpoint-investigator",
        "artifacts": inv.artifacts,
        "scenario_score": scenario.score(findings),
        "findings": [to_ocsf(f, inv) for f in findings],
    }

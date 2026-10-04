"""Uso: python3 -m investigator (--dataset DIR | --live) [--format terminal|json] [--output ARQUIVO]"""

from __future__ import annotations

import argparse
import json
import sys

from . import ach, scenario
from .collectors import dataset, live
from .graph import build_graph
from .normalize import normalize
from .report import ocsf, terminal
from .rules import run_all


def investigate(directory: str | None):
    """directory=None coleta o sistema local (ao vivo)."""
    inv = normalize(dataset.collect(directory) if directory else live.collect())
    findings = scenario.apply_prerequisites(run_all(inv, build_graph(inv)))
    for f in findings:
        ach.analyze(f, inv)
    return inv, findings


def main() -> None:
    ap = argparse.ArgumentParser(prog="investigator", description="Endpoint Investigator")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--dataset", help="diretório gerado por tools/generate_dataset.py")
    src.add_argument("--live", action="store_true", help="coleta o sistema local (rode como root para ver tudo)")
    ap.add_argument("--format", choices=["terminal", "json"], default="terminal")
    ap.add_argument("--output", help="grava a saída neste arquivo em vez de stdout")
    args = ap.parse_args()

    inv, findings = investigate(None if args.live else args.dataset)
    text = (json.dumps(ocsf.to_report(findings, inv), indent=2, ensure_ascii=False)
            if args.format == "json" else terminal.render(findings, inv.artifacts))
    if args.output:
        open(args.output, "w", encoding="utf-8").write(text + "\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    main()

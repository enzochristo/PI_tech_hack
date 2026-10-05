#!/usr/bin/env python3
"""Avaliação: gera lotes com o gerador corrigido, roda a ferramenta e compara com o gabarito.

Mede, por regra, precisão e recall (só regras implementadas) e o acerto do veredito ACH por cenário.
Gabarito de veredito (EXPECTED_VERDICT) é nosso: foi derivado do raciocínio de cada cenário, não do
gerador do professor. Mede coerência do motor com esse raciocínio, não verdade absoluta.

Uso: python3 tools/evaluate.py [--seeds 8] [--keep DIR]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from investigator import progress  # noqa: E402
from investigator.__main__ import investigate  # noqa: E402

progress.enabled = False

IMPLEMENTED = {"R1", "R2", "R3", "R4", "R5", "R6", "R7"}
SCENARIOS = ["normal", "permission", "privileged_service", "correlation", "ambiguous",
             "random", "writable_parent", "user_root_process"]
# (cenário, regra) -> veredito esperado do ACH. R1 sem sessão de usuário no journal => empate H2/H3 (writable_parent).
EXPECTED_VERDICT = {
    ("permission", "R6"): "H2", ("privileged_service", "R7"): "H1", ("ambiguous", "R7"): "H1",
    ("correlation", "R1"): "H2", ("writable_parent", "R1"): "INCONCLUSIVO",
    ("random", "R7"): "H1", ("user_root_process", "R2"): "INCONCLUSIVO",
    ("privileged_service", "R5"): "INCONCLUSIVO", ("ambiguous", "R5"): "INCONCLUSIVO",
    ("correlation", "R5"): "INCONCLUSIVO", ("random", "R1"): "H2",  # random herda a sessão do aluno de normal_parts
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=8, help="datasets por cenário")
    ap.add_argument("--keep", help="mantém os datasets gerados neste diretório")
    args = ap.parse_args()

    tmp = tempfile.TemporaryDirectory()
    base = Path(args.keep or tmp.name)
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    verdicts = defaultdict(lambda: [0, 0])
    misses = []

    for sc in SCENARIOS:
        for seed in range(1, args.seeds + 1):
            d = base / f"{sc}-{seed}"
            subprocess.run([sys.executable, str(ROOT / "tools/generate_dataset.py"), "--scenario", sc,
                            "--seed", str(seed), "--output", str(d)], check=True, capture_output=True)
            meta = json.loads((d / "metadata.json").read_text())
            expected = {(e["rule"], e["target"]) for e in meta["expected_findings"] if e["rule"] in IMPLEMENTED}
            _, findings = investigate(str(d))
            got = {(f.rule_id, f.target): f for f in findings}
            for e in expected:
                (tp if e in got else fn)[e[0]] += 1
                if e not in got:
                    misses.append(f"{d.name}: faltou {e}")
            for e in got.keys() - expected:
                fp[e[0]] += 1
                misses.append(f"{d.name}: extra {e}")
            for (rule, _), f in got.items():
                want = EXPECTED_VERDICT.get((sc, rule))
                if want:
                    verdicts[sc][1] += 1
                    verdicts[sc][0] += f.verdict == want
                    if f.verdict != want:
                        misses.append(f"{d.name}: veredito {f.verdict}, esperado {want}")

    print(f"{len(SCENARIOS) * args.seeds} datasets ({args.seeds} por cenário)\n")
    print(f"{'regra':<6}{'precisão':>10}{'recall':>9}{'TP':>5}{'FP':>5}{'FN':>5}")
    for r in sorted(IMPLEMENTED):
        p = tp[r] / (tp[r] + fp[r]) if tp[r] + fp[r] else float("nan")
        c = tp[r] / (tp[r] + fn[r]) if tp[r] + fn[r] else float("nan")
        print(f"{r:<6}{p:>10.2f}{c:>9.2f}{tp[r]:>5}{fp[r]:>5}{fn[r]:>5}")
    print(f"\n{'cenário':<22}veredito ACH correto")
    for sc in SCENARIOS:
        if sc in verdicts:
            ok, total = verdicts[sc]
            print(f"{sc:<22}{ok}/{total}")
    for m in misses:
        print("  !", m)
    sys.exit(1 if misses else 0)


if __name__ == "__main__":
    main()

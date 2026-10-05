#!/usr/bin/env python3
"""Compara os findings da ferramenta com expected_findings do metadata.json.

Uso: python3 tools/compare_expected.py training/*    (cada argumento é um diretório de dataset)
Regras fora de IMPLEMENTED aparecem como PENDENTE, não como falha.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from investigator import progress  # noqa: E402
from investigator.__main__ import investigate  # noqa: E402

progress.enabled = False

IMPLEMENTED = {"R1", "R2", "R3", "R4", "R5", "R6", "R7"}


def compare(directory: Path) -> tuple[str, int, int, int]:
    meta = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    expected = {(e["rule"], e["target"]) for e in meta["expected_findings"]}
    _, findings = investigate(str(directory))
    got = {(f.rule_id, f.target) for f in findings}
    exp_impl = {e for e in expected if e[0] in IMPLEMENTED}
    pending = expected - exp_impl

    print(f"\n== {directory.name}  (cenário: {meta['scenario']}, seed: {meta['seed']})")
    for e in sorted(exp_impl):
        print(f"  {'OK       ' if e in got else 'FALTOU   '} esperado {e[0]:<3} {e[1]}")
    for e in sorted(got - exp_impl):
        print(f"  EXTRA     tool gerou {e[0]:<3} {e[1]}  (não está no gabarito)")
    for e in sorted(pending):
        print(f"  PENDENTE  esperado {e[0]:<3} {e[1]}  (regra de etapa futura)")
    if not expected and not got:
        print("  OK        nenhum finding esperado, nenhum gerado")
    return meta["scenario"], len(exp_impl & got), len(exp_impl - got), len(got - exp_impl)


def main() -> None:
    dirs = [Path(a) for a in sys.argv[1:]]
    if not dirs:
        sys.exit(__doc__)
    results = [compare(d) for d in dirs]
    tp, fn, fp = (sum(r[i] for r in results) for i in (1, 2, 3))
    print(f"\nTOTAL: acertos={tp} faltaram={fn} extras={fp}")
    sys.exit(1 if fn or fp else 0)


if __name__ == "__main__":
    main()

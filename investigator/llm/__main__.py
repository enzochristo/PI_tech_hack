"""Uso: python3 -m investigator.llm RELATORIO.json   (relatório gerado com --format json)

Permite rodar a LLM sem root: gere o JSON com `sudo ... --live --format json --output x.json` e depois
rode este comando como usuário comum, onde a variável OPENAI_API_KEY está definida."""

from __future__ import annotations

import json
import sys

from .client import LLMError, explain
from .verify import render, verify


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    report = json.load(open(sys.argv[1], encoding="utf-8"))
    try:
        result, model, skipped = explain(report)
    except LLMError as e:
        sys.exit(f"erro: {e}")
    print(render(verify(result, report), model, skipped))


if __name__ == "__main__":
    main()

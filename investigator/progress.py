"""Mensagens de progresso em stderr (stdout fica limpo para o relatório/JSON)."""

from __future__ import annotations

import sys

enabled = True


def say(msg: str) -> None:
    if enabled:
        print(msg, file=sys.stderr, flush=True)


def warn(msg: str) -> None:
    """Avisos importantes: aparecem mesmo com --quiet."""
    print(msg, file=sys.stderr, flush=True)

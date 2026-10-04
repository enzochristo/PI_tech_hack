"""Coletor de dataset: lê a saída do gerador e devolve registros brutos com a origem (arquivo:linha)."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

FILES = ("processes.csv", "permissions.csv", "services.txt", "journal.log", "metadata.json")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(directory: str | Path) -> dict:
    d = Path(directory)
    raw: dict = {"processes": [], "permissions": [], "services": [], "journal": [], "meta": {}}

    for name, key in (("processes.csv", "processes"), ("permissions.csv", "permissions")):
        with (d / name).open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                # header = linha 1, então o primeiro registro é a linha 2
                raw[key].append({**row, "src": f"{name}:{len(raw[key]) + 2}"})

    lines = (d / "services.txt").read_text(encoding="utf-8").splitlines()
    for n, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        unit, active, user, execstart = line.split(None, 3)
        raw["services"].append(
            {"unit": unit, "active": active, "user": user, "execstart": execstart,
             "src": f"services.txt:{n}"})

    for n, line in enumerate((d / "journal.log").read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            raw["journal"].append({"line": line, "src": f"journal.log:{n}"})

    meta_path = d / "metadata.json"
    if meta_path.exists():
        # só fuso e ano: o gabarito (expected_findings) nunca chega ao motor de análise
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        raw["meta"] = {k: meta[k] for k in ("timezone", "year") if k in meta}

    raw["artifacts"] = [{"name": f, "sha256": _sha256(d / f)} for f in FILES if (d / f).exists()]
    return raw

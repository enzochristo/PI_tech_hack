"""R4: permissão + caminho -> binário setuid de root fora dos diretórios do sistema."""

from __future__ import annotations

import posixpath

from ..graph import Graph
from ..model import Finding, Inventory
from .common import Builder, file_fact, make_finding

META = "r4_suid.toml"
NONSTANDARD_DIRS = ("/usr/local", "/opt", "/home", "/tmp")
# subconjunto do GTFOBins: binários que, com setuid, dão shell root ou leitura/escrita arbitrária
GTFOBINS = {"bash", "sh", "dash", "find", "vim", "vi", "nano", "less", "more", "awk", "nmap", "python",
            "python3", "perl", "ruby", "env", "cp", "mv", "tar", "zip", "cat", "tee", "dd", "php", "node"}


def run(inv: Inventory, g: Graph) -> list[Finding]:
    out = []
    for f in inv.files:
        if f.is_dir or not f.flags["setuid"] or f.owner != "root":
            continue
        if not any(f.path == d or f.path.startswith(d + "/") for d in NONSTANDARD_DIRS):
            continue
        gtfo = posixpath.basename(f.path) in GTFOBINS
        b = Builder()
        b.add(f.src, f"{file_fact(f)} -> executa com UID 0 para qualquer usuário", f.to_ecs())
        out.append(make_finding(
            META, f.path, "Binário setuid de root fora do padrão",
            f"{f.path} (modo {f.mode}) é setuid root em diretório não padrão"
            + ("; o nome consta no GTFOBins" if gtfo else "; o nome não consta no GTFOBins") + ".", b,
            severity=4 if gtfo else None))
    return out

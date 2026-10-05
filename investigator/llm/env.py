"""Lê o arquivo .env (se existir) e preenche variáveis de ambiente que ainda não estão definidas.

Procura em: diretório atual e raiz do projeto. Formato: CHAVE=valor (aspas opcionais, # comenta).
Nunca imprime valores. O .env está no .gitignore e não deve ser versionado."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def load_dotenv() -> list[str]:
    """Retorna os caminhos de .env carregados."""
    loaded = []
    for path in dict.fromkeys([Path.cwd() / ".env", ROOT / ".env"]):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip().strip("'\"")
            if key.strip() and value:
                os.environ.setdefault(key.strip(), value)  # variável já exportada tem prioridade
        loaded.append(str(path))
    return loaded


def llm_enabled_by_default() -> bool:
    return os.environ.get("ENDPOINT_LLM", "").strip().lower() in ("on", "1", "true", "yes", "sim")

"""Cliente da API da OpenAI (Chat Completions + saída estruturada), só com a biblioteca padrão.

A chave vem da variável de ambiente OPENAI_API_KEY. Ela nunca é escrita em arquivo nem impressa.
Variáveis opcionais: OPENAI_MODEL (padrão abaixo) e OPENAI_BASE_URL.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .prompt import SCHEMA, SYSTEM, build_payload, user_message

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_BASE_URL = "https://api.openai.com/v1"


class LLMError(RuntimeError):
    pass


def _post(body: dict, api_key: str, timeout: float) -> dict:
    url = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/") + "/chat/completions"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise LLMError(f"A API respondeu HTTP {e.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise LLMError(f"Falha de rede ao chamar a API: {e}") from None


def explain(report: dict, model: str | None = None, post=None, timeout: float = 120.0) -> tuple[dict, str, int]:
    """Retorna (resposta bruta da LLM, modelo usado, findings não enviados). `post` permite injetar um stub."""
    model = model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL)
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key and post is None:
        raise LLMError("OPENAI_API_KEY não encontrada. Coloque-a no arquivo .env (veja .env.example) ou use: export OPENAI_API_KEY='sua-chave'")
    views, skipped = build_payload(report)
    if not views:
        return {"findings": []}, model, 0
    body = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_message(views)}],
        "response_format": {"type": "json_schema",
                            "json_schema": {"name": "finding_explanations", "strict": True, "schema": SCHEMA}},
    }
    resp = (post or _post)(body, key, timeout)
    try:
        msg = resp["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        raise LLMError("Resposta da API em formato inesperado.") from None
    if msg.get("refusal"):
        raise LLMError(f"O modelo recusou a requisição: {msg['refusal'][:200]}")
    try:
        return json.loads(msg["content"]), model, skipped
    except (TypeError, ValueError):
        raise LLMError("A resposta do modelo não é um JSON válido.") from None

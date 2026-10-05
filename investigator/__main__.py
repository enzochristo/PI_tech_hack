"""Uso: python3 -m investigator (--dataset DIR | --live) [--format terminal|json] [--output ARQUIVO]
       [--matrix] [--graph] [--graph-dot ARQ.dot] [--llm [--llm-model MODELO]] [--quiet]"""

from __future__ import annotations

import argparse
import json
import sys

from . import ach, progress, scenario
from .collectors import dataset, live
from .graph import build_graph
from .normalize import normalize
from .report import correlation, ocsf, terminal
from .rules import run_all


def analyze(directory: str | None):
    """directory=None coleta o sistema local (ao vivo). Retorna (inventário, grafo, findings)."""
    progress.say(f"[1/5] Coletando ({'ao vivo' if directory is None else 'dataset ' + directory})...")
    raw = dataset.collect(directory) if directory else live.collect()
    progress.say("[2/5] Normalizando (texto -> fatos)...")
    inv = normalize(raw)
    progress.say(f"      {len(inv.processes)} processos, {len(inv.services)} serviços, "
                 f"{len(inv.files)} arquivos, {len(inv.logs)} linhas de log")
    progress.say("[3/5] Construindo o grafo de proveniência...")
    graph = build_graph(inv)
    progress.say("[4/5] Aplicando as regras R1-R7...")
    findings = scenario.apply_prerequisites(run_all(inv, graph))
    progress.say(f"[5/5] Comparando hipóteses (ACH) para {len(findings)} finding(s)...")
    for f in findings:
        ach.analyze(f, inv)
    return inv, graph, findings


def investigate(directory: str | None):
    inv, _, findings = analyze(directory)
    return inv, findings


def main() -> None:
    from .llm.env import llm_enabled_by_default, load_dotenv
    load_dotenv()  # chave e opções vêm do .env (se existir); variáveis já exportadas têm prioridade
    ap = argparse.ArgumentParser(prog="investigator", description="Endpoint Investigator")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--dataset", help="diretório gerado por tools/generate_dataset.py")
    src.add_argument("--live", action="store_true", help="coleta o sistema local (rode como root para ver tudo)")
    ap.add_argument("--format", choices=["terminal", "json"], default="terminal")
    ap.add_argument("--quiet", action="store_true", help="não imprime as mensagens de progresso")
    ap.add_argument("--matrix", action="store_true", help="imprime a matriz de correlação entre fontes")
    ap.add_argument("--graph", action="store_true", help="imprime as relações do grafo de proveniência")
    ap.add_argument("--graph-dot", metavar="ARQ", help="grava o grafo em formato DOT (graphviz)")
    ap.add_argument("--llm", action="store_true",
                    help="camada opcional: explicação por LLM (OpenAI), verificada; requer OPENAI_API_KEY")
    ap.add_argument("--no-llm", action="store_true", help="não usa a LLM, mesmo com ENDPOINT_LLM=on no .env")
    ap.add_argument("--llm-model", help="modelo da LLM (padrão: variável OPENAI_MODEL ou gpt-4o-mini)")
    ap.add_argument("--output", help="grava a saída neste arquivo em vez de stdout")
    args = ap.parse_args()

    args.llm = (args.llm or llm_enabled_by_default()) and not args.no_llm
    progress.enabled = not args.quiet
    progress.say(">>> Endpoint Investigator iniciado")
    inv, graph, findings = analyze(None if args.live else args.dataset)
    report = ocsf.to_report(findings, inv)
    llm_text = ""
    if args.llm:
        from .llm.client import LLMError, explain
        from .llm.verify import render as llm_render, verify
        progress.say("[LLM] Enviando os findings (não os dados crus) para a API...")
        try:
            result, model, skipped = explain(report, args.llm_model)
            verified = verify(result, report)
            report["llm"] = {"model": model, "verified": verified}
            llm_text = llm_render(verified, model, skipped)
        except LLMError as e:
            progress.warn(f"[LLM] indisponível, seguindo só com a análise determinística: {e}")
    if args.format == "json":
        text = json.dumps(report, indent=2, ensure_ascii=False)
    else:
        text = terminal.render(findings, inv.artifacts)
        if args.matrix:
            text += "\n\n" + correlation.render(findings)
        if args.graph:
            text += "\n\n" + graph.to_text()
        if llm_text:
            text += "\n\n" + llm_text
    if args.graph_dot:
        open(args.graph_dot, "w", encoding="utf-8").write(graph.to_dot())
        progress.say(f">>> Grafo gravado em {args.graph_dot} (dot -Tpng {args.graph_dot} -o grafo.png)")
    progress.say(f">>> Análise concluída: {len(findings)} finding(s)\n")
    if args.output:
        open(args.output, "w", encoding="utf-8").write(text + "\n")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    main()

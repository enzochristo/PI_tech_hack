"""Desenha o fluxo do Endpoint Investigator (abstrato, com exemplo do cenário correlation)."""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = sys.argv[1]

# (etapa, arquivo, o que faz, exemplo, cor, enunciado)
STAGES = [
    ("FONTES", "dataset  ou  --live",
     "4 visões independentes do sistema\n(ps · systemctl · ls -l · journal)",
     "processes.csv  services.txt\npermissions.csv  journal.log",
     "#e8e8e8", None),
    ("1. COLETA", "collectors/dataset.py · live.py",
     "lê os artefatos sem interpretar;\nguarda SHA-256 (cadeia de custódia)",
     "linha 'backup-agent.service  running  root\n/bin/bash /opt/backup/backup.sh'",
     "#dbe9f6", "COLETA"),
    ("2. NORMALIZAÇÃO", "normalize.py",
     "texto vira FATO estruturado,\ncada fato lembra a origem\n(arquivo:linha)",
     "ExecStart → binário=/bin/bash, script=/opt/backup/backup.sh\nmodo 0777 → world_writable=True",
     "#dbe9f6", "NORMALIZAÇÃO"),
    ("3. GRAFO DE PROVENIÊNCIA", "graph.py",
     "fatos viram NÓS e RELAÇÕES\n(arestas); as 4 fontes deixam de ser\nlistas separadas",
     "service:backup-agent ─uses_script→ file:backup.sh\nservice:backup-agent ─has_process→ process:2417",
     "#fde2c8", "CORRELAÇÃO"),
    ("4. REGRAS R1–R7", "rules/r*.py + r*.toml",
     "cada regra CAMINHA no grafo\nprocurando um padrão que\ncruza fontes",
     "R1: serviço root → usa script → algum não-root\npode escrever no script ou num diretório pai? → SIM",
     "#fde2c8", "CORRELAÇÃO\n+ EVIDÊNCIAS"),
    ("5. PRÉ-REQUISITOS", "scenario.py",
     "descarta finding que só faz sentido\nse outra regra também disparou",
     "R3 (linha do tempo) só fica se R1 existe",
     "#fde2c8", None),
    ("6. HIPÓTESES (ACH)", "ach.py",
     "cada evidência é C / I / N\npara H1, H2, H3; vence quem\ntem MENOS inconsistências",
     "H1 legítimo = 1 I · H2 má config = 0 I · H3 explorado = 1 I\n→ H2  (empate → INCONCLUSIVO)",
     "#e3f1dc", "HIPÓTESES"),
    ("7. RELATÓRIO", "report/terminal.py · ocsf.py",
     "Evidência · Interpretação · Hipótese ·\nNão provado · Evidência ausente",
     "[F-001] R1 · RISCO · High · confiança Medium\nfalta: hash vs baseline, auditd",
     "#e3f1dc", "RESULTADO"),
]

fig, ax = plt.subplots(figsize=(18, 17))
ax.set_xlim(0, 18)
ax.set_ylim(0, 17)
ax.axis("off")

ax.text(9, 16.55, "Endpoint Investigator — como funciona", ha="center", fontsize=20, weight="bold")
ax.text(9, 16.1, "cada etapa: o que faz (meio) e um exemplo real do cenário training/correlation (direita)",
        ha="center", fontsize=11, color="#555")
for x, t in ((3.6, "ETAPA / ARQUIVO"), (7.6, "O QUE FAZ"), (13.6, "EXEMPLO (cenário correlation)")):
    ax.text(x, 15.55, t, ha="center", fontsize=10, weight="bold", color="#777")

top, step, h = 15.2, 1.85, 1.45
centers = []
for i, (name, src, what, ex, color, enun) in enumerate(STAGES):
    y = top - i * step - h
    centers.append(y + h / 2)
    ax.add_patch(FancyBboxPatch((1.9, y), 3.4, h, boxstyle="round,pad=0.02,rounding_size=0.15",
                                fc=color, ec="#333", lw=1.4))
    ax.text(3.6, y + h * 0.62, name, ha="center", va="center", fontsize=12.5, weight="bold")
    ax.text(3.6, y + h * 0.28, src, ha="center", va="center", fontsize=9, family="DejaVu Sans Mono", color="#333")
    ax.text(5.55, y + h / 2, what, ha="left", va="center", fontsize=10.3)
    ax.add_patch(FancyBboxPatch((10.3, y + 0.12), 7.5, h - 0.24, boxstyle="round,pad=0.02,rounding_size=0.1",
                                fc="#fafafa", ec="#bbb", lw=1, ls="--"))
    ax.text(10.45, y + h / 2, ex, ha="left", va="center", fontsize=9.2, family="DejaVu Sans Mono")
    if enun:
        ax.text(0.95, y + h / 2, enun, ha="center", va="center", fontsize=9, weight="bold", color="#8a5a00",
                bbox=dict(boxstyle="round,pad=0.3", fc="#fff6d6", ec="#d9b25a"))
    if i:
        ax.add_patch(FancyArrowPatch((3.6, y + h + step - h), (3.6, y + h + 0.02),
                                     arrowstyle="-|>", mutation_scale=18, lw=1.8, color="#333"))

ax.text(0.95, top + 0.15, "fluxo do\nenunciado", ha="center", fontsize=9, color="#8a5a00", weight="bold")

# camada LLM opcional
yl = top - len(STAGES) * step - 0.35
ax.add_patch(FancyBboxPatch((1.9, yl - 0.85), 3.4, 0.95, boxstyle="round,pad=0.02,rounding_size=0.15",
                            fc="white", ec="#888", lw=1.4, ls="--"))
ax.text(3.6, yl - 0.25, "LLM (opcional)", ha="center", va="center", fontsize=11.5, weight="bold", color="#555")
ax.text(3.6, yl - 0.62, "llm/  ·  --llm", ha="center", va="center", fontsize=9, family="DejaVu Sans Mono", color="#555")
ax.add_patch(FancyArrowPatch((3.6, centers[-1] - h / 2), (3.6, yl + 0.12), arrowstyle="-|>",
                             mutation_scale=16, lw=1.4, color="#888", ls="--"))
ax.text(5.6, yl - 0.38, "recebe só os findings prontos e redige a explicação;\num verificador apaga frase que cita evidência inexistente.\nNÃO altera veredito.",
        ha="left", va="center", fontsize=9.5, color="#555")

# chave das cores
ax.text(13.2, yl - 0.2, "laranja = onde a correlação acontece", fontsize=9.5, color="#b0610f", weight="bold")
ax.text(13.2, yl - 0.55, "verde = conclusão e apresentação", fontsize=9.5, color="#3d7a28", weight="bold")
ax.text(13.2, yl - 0.9, "azul = preparar os dados", fontsize=9.5, color="#2c6aa0", weight="bold")

fig.savefig(OUT, dpi=150, bbox_inches="tight", facecolor="white")
print(OUT)

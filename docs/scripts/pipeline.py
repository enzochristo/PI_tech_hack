"""Figura: pipeline do Endpoint Investigator, da extração ao relatório, com as duas entradas.

Uso: python3 docs/scripts/pipeline.py docs/pipeline.png
Mostra que dataset e Kali (--live) só diferem na coleta: do grafo em diante o código é o mesmo.
"""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = sys.argv[1]
INK, QUIET = "#222", "#666"

fig, ax = plt.subplots(figsize=(25, 9))
ax.set_xlim(0, 25)
ax.set_ylim(0, 9)
ax.axis("off")
ax.text(12.2, 8.55, "Endpoint Investigator: da extração ao relatório", ha="center", fontsize=21,
        weight="bold", color=INK)
ax.text(12.2, 8.05, "dataset e Kali entram por portas diferentes; do grafo em diante o código é exatamente o mesmo",
        ha="center", fontsize=12.5, color=QUIET)

W, H, Y = 2.35, 1.5, 4.0           # caixas da linha principal (centro vertical em Y + H/2)
STEPS = [  # (x, título, arquivo, exemplo, cor, etapa do enunciado)
    (4.45, "1. EXTRAÇÃO", "collectors/", "lê os dados crus\n+ SHA-256", "#dbe9f6", "COLETA"),
    (7.35, "2. NORMALIZAÇÃO", "normalize.py", "texto → fato\n0777 → world_writable", "#dbe9f6", "NORMALIZAÇÃO"),
    (10.25, "3. GRAFO", "graph.py", "liga as fontes por\ncaminho, comando, PID", "#fde2c8", "CORRELAÇÃO"),
    (13.15, "4. REGRAS R1–R7", "rules/", "seguem as setas\nprocurando padrões", "#fde2c8", "EVIDÊNCIAS"),
    (16.05, "5. PRÉ-REQUISITOS", "scenario.py", "R3 só vale\nse R1 disparou", "#fde2c8", None),
    (18.95, "6. HIPÓTESES (ACH)", "ach.py", "H1 / H2 / H3\nou INCONCLUSIVO", "#e3f1dc", "HIPÓTESES"),
    (21.5, "7. RELATÓRIO", "report/", "terminal ou\nJSON (OCSF)", "#e3f1dc", "RESULTADO"),
]
W_LAST = 2.05

for i, (x, t, f, ex, fc, enun) in enumerate(STEPS):
    w = W_LAST if i == len(STEPS) - 1 else W
    ax.add_patch(FancyBboxPatch((x - w / 2, Y), w, H, boxstyle="round,pad=0.02,rounding_size=0.15",
                                fc=fc, ec="#d62728" if i == 2 else "#333", lw=3 if i == 2 else 1.4, zorder=3))
    ax.text(x, Y + H - 0.38, t, ha="center", va="center", fontsize=11.5, weight="bold", color=INK, zorder=4)
    ax.text(x, Y + 0.68, ex, ha="center", va="center", fontsize=9.6, color=INK, zorder=4, linespacing=1.2)
    ax.text(x, Y + 0.17, f, ha="center", va="center", fontsize=9, family="DejaVu Sans Mono", color=QUIET, zorder=4)
    if enun:
        ax.text(x, Y + H + 0.38, enun, ha="center", va="center", fontsize=9.5, weight="bold", color="#8a5a00",
                bbox=dict(boxstyle="round,pad=0.3", fc="#fff6d6", ec="#d9b25a"))
    if i:
        px = STEPS[i - 1][0] + W / 2
        ax.add_patch(FancyArrowPatch((px + 0.04, Y + H / 2), (x - w / 2 - 0.04, Y + H / 2), arrowstyle="-|>",
                                     mutation_scale=20, lw=2, color="#333", zorder=2))



# ---- as duas entradas, convergindo na extração ----
IN = [(6.2, "DATASET", "--dataset", "processes.csv  services.txt\npermissions.csv  journal.log", "#f3f3f3"),
      (0.95, "KALI AO VIVO", "--live", "/proc  systemctl show\nos.stat  journalctl", "#f3f3f3")]
for y, t, flag, d, fc in IN:
    ax.add_patch(FancyBboxPatch((0.15, y), 3.4, 1.45, boxstyle="round,pad=0.02,rounding_size=0.15",
                                fc=fc, ec="#555", lw=1.4, zorder=3))
    ax.text(1.85, y + 1.15, t, ha="center", va="center", fontsize=11, weight="bold", color=INK, zorder=4)
    ax.text(1.85, y + 0.82, flag, ha="center", va="center", fontsize=9, family="DejaVu Sans Mono", color=QUIET, zorder=4)
    ax.text(1.85, y + 0.36, d, ha="center", va="center", fontsize=8.6, family="DejaVu Sans Mono", color=INK,
            zorder=4, linespacing=1.25)
x0 = STEPS[0][0]
ax.add_patch(FancyArrowPatch((1.85, 6.15), (x0 - W / 2 - 0.05, Y + H * 0.72), arrowstyle="-|>", mutation_scale=20,
                             lw=2, color="#555", connectionstyle="arc3,rad=0.3", zorder=2))
ax.add_patch(FancyArrowPatch((1.85, 2.45), (x0 - W / 2 - 0.05, Y + H * 0.28), arrowstyle="-|>", mutation_scale=20,
                             lw=2, color="#555", connectionstyle="arc3,rad=-0.3", zorder=2))
ax.text(1.85, 7.85, "testes e demo", ha="center", fontsize=10, color=QUIET, style="italic")
ax.text(1.85, 0.6, "máquina real", ha="center", fontsize=10, color=QUIET, style="italic")

# ---- chave: o mesmo código para as duas entradas ----
bx0, bx1, by = STEPS[1][0] - W / 2, STEPS[-1][0] + W_LAST / 2, Y - 0.45
ax.plot([bx0, bx0, bx1, bx1], [by + 0.2, by, by, by + 0.2], color="#d62728", lw=2)
ax.text((bx0 + bx1) / 2, by - 0.42, "MESMO CÓDIGO para dataset e Kali: o grafo, as regras e o ACH rodam igual nos dois",
        ha="center", va="center", fontsize=12.5, weight="bold", color="#d62728")
ax.text((bx0 + bx1) / 2, by - 0.88,
        "o que muda entre os dois é só a extração (etapa 1): de onde vêm os processos, serviços, permissões e logs",
        ha="center", va="center", fontsize=11, color=QUIET)

# ---- LLM opcional, à direita do relatório ----
lx = 23.95
ax.add_patch(FancyBboxPatch((lx - 0.9, Y + 0.1), 1.8, H - 0.2, boxstyle="round,pad=0.02,rounding_size=0.15",
                            fc="white", ec="#888", lw=1.4, ls="--", zorder=3))
ax.text(lx, Y + H - 0.42, "LLM", ha="center", va="center", fontsize=11, weight="bold", color="#555")
ax.text(lx, Y + H - 0.72, "(opcional)", ha="center", va="center", fontsize=9, color="#555")
ax.text(lx, Y + 0.45, "só explica;\nnão muda\no veredito", ha="center", va="center", fontsize=8.6, color="#555",
        linespacing=1.1)
ax.add_patch(FancyArrowPatch((STEPS[-1][0] + W_LAST / 2 + 0.04, Y + H / 2), (lx - 0.94, Y + H / 2),
                             arrowstyle="-|>", mutation_scale=16, lw=1.4, color="#888", ls="--"))

fig.savefig(OUT, dpi=130, bbox_inches="tight", facecolor="white")
print(OUT)

"""Desenho conceitual: como 4 listas independentes viram UMA relação (R1) pelas chaves de ligação."""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

fig, ax = plt.subplots(figsize=(18, 10.5))
ax.set_xlim(0, 18); ax.set_ylim(0, 10.5); ax.axis("off")
ax.text(9, 10.05, "Correlação = ligar linhas de arquivos DIFERENTES por uma chave em comum", ha="center", fontsize=19, weight="bold")
ax.text(9, 9.6, "cenário training/correlation · regra R1", ha="center", fontsize=12, color="#555")

def box(x, y, w, h, fc, ec="#333", lw=1.4, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", fc=fc, ec=ec, lw=lw, ls=ls))

SRC = [  # (arquivo, linha, cor)
    ("services.txt  linha 4", "backup-agent.service  running  root\n/bin/bash /opt/backup/backup.sh", "#dbe9f6"),
    ("processes.csv  linha 5", "pid=2417  ppid=1  user=root\ncmd=/bin/bash /opt/backup/backup.sh", "#e3f1dc"),
    ("permissions.csv  linha 3", "/opt/backup/backup.sh  root:root\nmode=0777", "#fff1cc"),
    ("journal.log  linha 5", "backup-agent[2417]:\nbackup completed with status=OK", "#fde2c8"),
]
ys = [7.6, 5.6, 3.6, 1.6]
for (t, body, c), y in zip(SRC, ys):
    box(0.3, y, 5.0, 1.45, c)
    ax.text(0.5, y + 1.18, t, fontsize=11, weight="bold", va="center")
    ax.text(0.5, y + 0.55, body, fontsize=9.8, family="DejaVu Sans Mono", va="center")
ax.text(2.8, 9.25, "4 LISTAS SEPARADAS", ha="center", fontsize=12, weight="bold", color="#777")

# nós do grafo
N = {"svc": (9.3, 7.9, "serviço backup-agent\nroda como root", "#dbe9f6"),
     "proc": (9.3, 5.6, "processo 2417\n(root)", "#e3f1dc"),
     "file": (13.6, 6.75, "/opt/backup/backup.sh\n0777 → qualquer um escreve", "#ffd6d6"),
     "log": (9.3, 2.3, "evento de log\n'status=OK'", "#fde2c8")}
for k, (x, y, t, c) in N.items():
    box(x - 1.7, y - 0.55, 3.4, 1.1, c, ec="#d62728" if k in ("svc", "file") else "#333", lw=2.6 if k in ("svc", "file") else 1.4)
    ax.text(x, y, t, ha="center", va="center", fontsize=10.5)
ax.text(11.5, 9.25, "1 GRAFO LIGADO", ha="center", fontsize=12, weight="bold", color="#777")

def arrow(a, b, txt, color="#333", lw=2, rad=0.0, tx=None, ty=None):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=18, lw=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}"))
    if txt:
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        ax.text(tx or mx, ty or my, txt, ha="center", va="center", fontsize=9.3, color=color,
                bbox=dict(boxstyle="round,pad=0.25", fc="white", ec=color, lw=1))

# fontes -> nós (dashed)
for (y, node) in ((7.6, "svc"), (5.6, "proc"), (3.6, "file"), (1.6, "log")):
    x, ny = N[node][0], N[node][1]
    arrow((5.35, y + 0.72), (x - 1.75 if node != "file" else x - 1.75, ny), "", color="#999", lw=1.2)

# chaves de ligação
arrow((9.3, 7.33), (9.3, 6.17), "has_process\nChave: ExecStart == cmd", "#8e44ad", tx=7.2, ty=6.75)
arrow((11.0, 7.9), (13.0, 7.3), "uses_script\nChave: caminho do script", "#d62728", lw=3, tx=12.0, ty=8.35)
arrow((9.3, 2.85), (9.3, 5.05), "logged_by\nChave: PID 2417", "#d9822b", tx=7.4, ty=3.9)
ax.text(13.6, 5.65, "↑ modo vem de permissions.csv\nChave: o mesmo caminho", ha="center", fontsize=9.3, color="#b8860b")

# conclusão
box(12.1, 0.55, 5.6, 4.0, "#fff", ec="#d62728", lw=2)
ax.text(14.9, 4.15, "R1 dispara quando o caminho existe:", ha="center", fontsize=11.5, weight="bold", color="#d62728")
ax.text(12.35, 2.55,
        "serviço (root)\n   └─uses_script→ arquivo\n          └─ alguém não-root escreve\n             nele ou num diretório pai\n\n"
        "→ EVIDÊNCIAS E1..E6 (cada uma com\n   arquivo:linha de origem)\n→ HIPÓTESES H1/H2/H3 no ACH",
        fontsize=9.6, family="DejaVu Sans Mono", va="center")
ax.text(9, 0.15, "Nenhuma fonte sozinha mostra o risco: root é normal, 0777 sozinho é só má configuração. O risco aparece no CRUZAMENTO.",
        ha="center", fontsize=11.5, style="italic", color="#333")
fig.savefig(sys.argv[1], dpi=130, bbox_inches="tight", facecolor="white")

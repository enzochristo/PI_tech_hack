"""Figura didática: como 4 listas viram um grafo (nós redondos, arestas sem cruzamento).

Uso: python3 docs/scripts/juncao.py docs/juncao_grafo.png
Exemplo fixo do cenário training/correlation. A cor de cada chave (caminho, comando, PID) é a
mesma na lista e na aresta que ela cria: é assim que se vê qual valor repetido liga o quê.
"""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch

OUT = sys.argv[1]
PATH, CMD, PID = "#e67e22", "#8e44ad", "#27ae60"   # cor de cada chave de ligação
INK, QUIET = "#222", "#666"

fig, ax = plt.subplots(figsize=(20, 10.5))
ax.set_xlim(0, 20)
ax.set_ylim(0, 10.5)
ax.set_aspect("equal")
ax.axis("off")

ax.text(10, 10.05, "Como 4 listas viram um grafo: valores repetidos viram ligações", ha="center",
        fontsize=20, weight="bold", color=INK)

# ---------------- PAINEL A: as 4 listas ----------------
ax.text(3.9, 9.3, "ANTES: 4 listas separadas", ha="center", fontsize=14, weight="bold", color=QUIET)


def lista(y, titulo, partes, fc):
    ax.add_patch(FancyBboxPatch((0.3, y), 7.2, 1.55, boxstyle="round,pad=0.02,rounding_size=0.12",
                                fc=fc, ec="#999", lw=1.2))
    ax.text(0.5, y + 1.22, titulo, fontsize=12, weight="bold", color=INK, va="center")
    x = 0.5
    for txt, cor in partes:          # escreve a linha em pedaços, colorindo a chave
        t = ax.text(x, y + 0.5, txt, fontsize=11, family="DejaVu Sans Mono", va="center",
                    color=cor or INK, weight="bold" if cor else "normal")
        fig.canvas.draw()
        bb = t.get_window_extent().transformed(ax.transData.inverted())
        x = bb.x1


lista(7.45, "services.txt  (systemctl)",
      [("backup-agent  root  ", None), ("/bin/bash /opt/backup/backup.sh", CMD)], "#e8f1fa")
lista(5.55, "processes.csv  (ps)",
      [("pid=", None), ("2417", PID), ("  root  ", None), ("/bin/bash /opt/backup/backup.sh", CMD)], "#eaf6e6")
lista(3.65, "permissions.csv  (ls -l)",
      [("/opt/backup/backup.sh", PATH), ("  modo 0777", None)], "#fff6dc")
lista(1.75, "journal.log  (journalctl)",
      [("backup-agent[", None), ("2417", PID), ("]: status=OK", None)], "#fdebdc")

ax.text(3.9, 1.1, "o caminho do script também está dentro do comando (em roxo)", ha="center",
        fontsize=10.5, color=QUIET, style="italic")
ax.text(3.9, 0.7, "→ é a normalização que o separa: binário /bin/bash + script /opt/backup/backup.sh",
        ha="center", fontsize=10.5, color=QUIET, style="italic")

# seta grande entre os painéis
ax.add_patch(FancyArrowPatch((7.9, 5.3), (9.1, 5.3), arrowstyle="simple,head_width=1.2,head_length=0.8",
                             mutation_scale=22, color="#bbb"))
ax.text(8.5, 5.95, "build_graph()", ha="center", fontsize=10.5, family="DejaVu Sans Mono", color=QUIET)

# ---------------- PAINEL B: o grafo ----------------
ax.text(14.6, 9.3, "DEPOIS: 1 grafo ligado", ha="center", fontsize=14, weight="bold", color=QUIET)

R = 1.08
N = {  # posição, título, detalhe, arquivo de origem, cor de fundo
    "svc":  ((11.2, 7.2), "SERVIÇO", "backup-agent\nroot", "services.txt", "#dbe9f6"),
    "file": ((16.6, 7.2), "ARQUIVO", "backup.sh\n0777", "permissions.csv", "#ffd6d6"),
    "proc": ((11.2, 4.2), "PROCESSO", "2417\nroot", "processes.csv", "#e3f1dc"),
    "log":  ((11.2, 1.3), "LOG", "status=OK", "journal.log", "#fde2c8"),
    "dir":  ((16.6, 4.2), "PASTA", "/opt/backup\n0755", "permissions.csv", "#eeeeee"),
}
for k, ((x, y), t, d, src, fc) in N.items():
    ax.add_patch(Circle((x, y), R, fc=fc, ec="#d62728" if k == "file" else "#333",
                        lw=3 if k == "file" else 1.5, zorder=3))
    ax.text(x, y + 0.5, t, ha="center", va="center", fontsize=11, weight="bold", color=INK, zorder=4)
    ax.text(x, y - 0.05, d, ha="center", va="center", fontsize=9.6, color=INK, zorder=4,
            family="DejaVu Sans Mono", linespacing=1.15)
    ax.text(x, y - 0.6, src, ha="center", va="center", fontsize=8.6, color=QUIET, style="italic", zorder=4)


def edge(a, b, cor, nome, chave, lado):
    (x1, y1), (x2, y2) = N[a][0], N[b][0]
    dist = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
    ux, uy = (x2 - x1) / dist, (y2 - y1) / dist          # a seta começa e termina na borda do círculo
    ax.add_patch(FancyArrowPatch((x1 + ux * (R + 0.05), y1 + uy * (R + 0.05)),
                                 (x2 - ux * (R + 0.05), y2 - uy * (R + 0.05)), arrowstyle="-|>",
                                 mutation_scale=26, shrinkA=0, shrinkB=0, lw=3, color=cor, zorder=5))
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    if lado == "cima":
        ax.text(mx, my + 0.62, nome, ha="center", fontsize=12, weight="bold", color=cor)
        ax.text(mx, my + 0.3, chave, ha="center", fontsize=10.5, color=QUIET)
    elif lado == "dir":
        ax.text(mx + 0.25, my + 0.15, nome, ha="left", fontsize=12, weight="bold", color=cor)
        ax.text(mx + 0.25, my - 0.2, chave, ha="left", fontsize=10.5, color=QUIET)
    else:  # diagonal: rótulo abaixo da linha
        ax.text(mx - 0.75, my + 0.75, nome, ha="center", fontsize=12, weight="bold", color=cor)
        ax.text(mx - 0.75, my + 0.43, chave, ha="center", fontsize=10.5, color=QUIET)


edge("svc", "file", PATH, "usa_script", "chave: o mesmo caminho", "cima")
edge("svc", "proc", CMD, "tem_processo", "chave: o comando", "dir")
edge("proc", "file", PATH, "usa_script", "chave: o mesmo caminho", "diag")
edge("log", "proc", PID, "registrado_por", "chave: o PID 2417", "dir")
edge("file", "dir", "#999", "dentro_de", "chave: o caminho", "dir")

# conclusão
ax.add_patch(FancyBboxPatch((13.3, 0.35), 6.4, 1.75, boxstyle="round,pad=0.02,rounding_size=0.12",
                            fc="#fff", ec="#d62728", lw=2))
ax.text(16.5, 1.72, "Regra R1 = seguir as setas", ha="center", fontsize=12.5, weight="bold", color="#d62728")
ax.text(16.5, 1.2, "serviço root → usa_script → arquivo 0777", ha="center", fontsize=11,
        family="DejaVu Sans Mono", color=INK)
ax.text(16.5, 0.75, "= o root executa algo que qualquer um altera", ha="center", fontsize=11, color=INK)

fig.savefig(OUT, dpi=130, bbox_inches="tight", facecolor="white")
print(OUT)

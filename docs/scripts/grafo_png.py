"""Desenha um RECORTE do grafo de proveniência real: o serviço backup-agent e tudo ligado a ele.

Uso (na raiz do projeto): python3 docs/scripts/grafo_png.py training/correlation docs/grafo_correlation.png
As posições são fixas (sem cruzamento de setas); as arestas e suas origens vêm do grafo que o
investigator monta. Se uma aresta desenhada não existir no grafo, o script falha.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

from investigator import progress
from investigator.__main__ import analyze

progress.enabled = False
inv, g, findings = analyze(sys.argv[1])

SVC = ("service", "backup-agent.service")
P1, P2 = ("process", 2417), ("process", 2421)
F = ("file", "/opt/backup/backup.sh")
D1, D2, D3 = ("dir", "/opt/backup"), ("dir", "/opt"), ("dir", "/")
R = ("remote", "updates.example.invalid")
LOG = ("journal", 2417)

# posição (x, y) de cada nó — escolhida à mão para nenhuma seta cruzar outra
POS = {SVC: (1.5, 7.0), P1: (1.5, 3.6), LOG: (1.5, 0.6), F: (8.6, 5.3),
       D1: (12.6, 5.3), D2: (15.9, 5.3), D3: (19.0, 5.3), P2: (8.6, 1.6), R: (14.2, 1.6)}

def width(n):
    return 2.5 if n[0] == "dir" else 3.3


SRC_COLOR = {"services.txt": "#2c6aa0", "processes.csv": "#3d8b37", "journal.log": "#d9822b"}


def find_edge(etype, a, b):
    es = [e for e in g.out(a, etype) if e.dst == b]
    assert es, f"aresta {etype} {a} -> {b} não existe no grafo"
    return es[0]


def text_of(n):
    obj = g.attr(n, "obj")
    kind, key = n
    if kind == "service":
        return f"SERVIÇO\n{key}", f"User={obj.user}"
    if kind == "process":
        exe, _, rest = obj.cmd.partition(" ")
        rest = rest if len(rest) <= 26 else rest[:25] + "…"
        return f"PROCESSO {key}  (user={obj.user})", f"{exe}\n{rest}"
    if kind in ("file", "dir"):
        return key, (f"modo {obj.mode}  {obj.owner}:{obj.group}" if obj else "(permissão não coletada)")
    if kind == "remote":
        return "DESTINO REMOTO", key
    if kind == "journal":
        n_lines = len(g.into(P1, "logged_by"))
        return "LOG (journal.log)", f"{n_lines} linhas 'backup-agent[2417]'"


def danger(n):
    obj = g.attr(n, "obj")
    return n[0] in ("file", "dir") and obj is not None and obj.flags.get("world_writable")


# (tipo, origem, destino, rótulo, destacado em R1)
logged = g.into(P1, "logged_by")
EDGES = [
    (find_edge("has_process", SVC, P1), "has_process", False),
    (find_edge("uses_script", SVC, F), "uses_script", True),
    (find_edge("uses_script", P1, F), "uses_script", False),
    (find_edge("parent_of", P1, P2), "parent_of", False),
    (find_edge("connects_to", P2, R), "connects_to", False),
    (find_edge("inside_dir", F, D1), "inside_dir", True),
    (find_edge("inside_dir", D1, D2), "inside_dir", True),
    (find_edge("inside_dir", D2, D3), "inside_dir", True),
]
assert logged, "nenhum evento de log ligado ao PID 2417"


def compact(sources):
    by_file = {}
    for s in sources:
        f, line = s.split(":")
        by_file.setdefault(f, []).append(line)
    return "\n".join(f"{f}:{','.join(dict.fromkeys(ls))}" for f, ls in by_file.items())


def color_of(e):
    files = sorted({s.split(":")[0] for s in e.sources})
    if len(files) > 1:
        return "#8e44ad", compact(e.sources)
    if not files:
        return "#999999", "deduzido do caminho"
    return SRC_COLOR[files[0]], compact(e.sources)


fig, ax = plt.subplots(figsize=(20, 10))
ax.set_xlim(-0.6, 20.8)
ax.set_ylim(-1.2, 9.4)
ax.axis("off")
ax.text(10, 9.0, "Grafo de proveniência (recorte) — o que o código monta para backup-agent.service",
        ha="center", fontsize=18, weight="bold")
ax.text(10, 8.5, "cada seta é uma RELAÇÃO; o texto embaixo dela diz de qual arquivo:linha ela veio",
        ha="center", fontsize=12, color="#555")

H = 1.15
for n, (x, y) in POS.items():
    hl = n in (SVC, F, D1, D2, D3)
    W = width(n)
    fc = "#ffd6d6" if danger(n) else {"service": "#dbe9f6", "process": "#e3f1dc", "file": "#fff1cc",
                                       "dir": "#f1f1f1", "remote": "#f8d7da", "journal": "#fde2c8"}[n[0]]
    ax.add_patch(FancyBboxPatch((x - W / 2, y - H / 2), W, H, boxstyle="round,pad=0.03,rounding_size=0.15",
                                fc=fc, ec="#d62728" if hl else "#333", lw=3 if hl else 1.3, zorder=3))
    title, sub = text_of(n)
    ax.text(x, y + 0.22, title, ha="center", va="center", fontsize=10.5, weight="bold", zorder=4)
    ax.text(x, y - 0.3, sub, ha="center", va="center", fontsize=8.8, zorder=4,
            family="DejaVu Sans Mono" if n[0] in ("file", "dir", "process") else None)


def border(n, toward):
    """Ponto onde a reta centro(n) -> toward sai da caixa de n (a seta começa/termina na borda)."""
    (x, y), (tx, ty) = POS[n], toward
    dx, dy = tx - x, ty - y
    pad = 0.12
    t = min((width(n) / 2 + pad) / abs(dx) if dx else 1e9, (H / 2 + pad) / abs(dy) if dy else 1e9)
    return x + dx * t, y + dy * t


def draw(a, b, label, src_text, color, hl):
    (x1, y1), (x2, y2) = POS[a], POS[b]
    ax.add_patch(FancyArrowPatch(border(a, POS[b]), border(b, POS[a]), arrowstyle="-|>", mutation_scale=22,
                                 shrinkA=0, shrinkB=0, lw=4 if hl else 2.2,
                                 color="#d62728" if hl else color, zorder=2))
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    dx = 0.45 if x1 == x2 else 0
    dy = 0 if x1 == x2 else (0.95 if y1 == y2 else 0.32)
    if label == "inside_dir":
        ax.text(mx, my + 0.9, label, ha="center", va="center", fontsize=10, weight="bold", color=color, zorder=5)
        return
    ax.text(mx + dx, my + dy, label, ha="left" if dx else "center", va="center", fontsize=10.5, weight="bold",
            color=color, zorder=5, bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))
    n_lines = src_text.count("\n") + 1
    ax.text(mx + dx, my + dy - 0.2 - 0.17 * n_lines, src_text, ha="left" if dx else "center", va="center", fontsize=8.5,
            color="#555", zorder=5, family="DejaVu Sans Mono",
            bbox=dict(boxstyle="round,pad=0.1", fc="white", ec="none"))


for e, label, hl in EDGES:
    c, s = color_of(e)
    draw(e.src, e.dst, label, s, c, hl)
draw(LOG, P1, "logged_by", compact([e.sources[0] for e in logged]), SRC_COLOR["journal.log"], False)

# legenda
items = [("#2c6aa0", "veio de services.txt"), ("#3d8b37", "veio de processes.csv"),
         ("#d9822b", "veio de journal.log"), ("#8e44ad", "CRUZA mais de um arquivo"),
         ("#999999", "deduzido do caminho"), ("#d62728", "caminho percorrido pela R1")]
for i, (c, t) in enumerate(items):
    x = 0.2 + i * 3.5
    ax.plot([x, x + 0.6], [-0.85, -0.85], color=c, lw=5 if c == "#d62728" else 3.5)
    ax.text(x + 0.75, -0.85, t, va="center", fontsize=10.5)
ax.text(20.2, 3.6, "fundo vermelho =\nqualquer um escreve\n(0777, de permissions.csv)", ha="right", fontsize=10,
        color="#b03030")
fig.savefig(sys.argv[2], dpi=120, bbox_inches="tight", facecolor="white")
print(sys.argv[2])

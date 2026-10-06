"""Duas matrizes das regras R1–R7: a técnica (o que o código testa) e a implicação (o que o resultado significa).

Uso: python3 docs/scripts/regras.py docs/
Gera docs/regras_tecnica.png e docs/regras_implicacao.png. Conteúdo tirado de investigator/rules/r*.py e r*.toml.
"""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, Rectangle

OUT = Path(sys.argv[1])
INK, QUIET, GRID = "#222", "#666", "#cfcfcf"
CLASS_COLOR = {"RISCO": "#c0392b", "CONTEXTO": "#2c6aa0", "INCONCLUSIVO": "#8e6e00",
               "CONFIG. INADEQUADA": "#b9770e", "LEGÍTIMO": "#2e7d32"}

RULES = ["R1", "R2", "R3", "R4", "R5", "R6", "R7"]
NAMES = {"R1": "Privilégio\ninseguro", "R2": "Contexto de\nexecução", "R3": "Linha do\ntempo",
         "R4": "SUID fora\ndo padrão", "R5": "Saída de rede\nprivilegiada", "R6": "Configuração\ninadequada",
         "R7": "Uso legítimo\nde privilégio"}
CLASS = {"R1": "RISCO", "R2": "CONTEXTO", "R3": "CONTEXTO", "R4": "RISCO", "R5": "INCONCLUSIVO",
         "R6": "CONFIG. INADEQUADA", "R7": "LEGÍTIMO"}

# fontes cruzadas (processos, serviços, permissões, logs) — de "correlates" nos .toml + o que o código lê
SOURCES = {"R1": "PSP-", "R2": "P--L", "R3": "-SPL", "R4": "--P-", "R5": "PSPL", "R6": "PSP-", "R7": "PSP-"}

TECH = {  # (condição testada pelo código, caminho no grafo / dado usado, cenário que testa)
    "R1": ("serviço com User=root  E\nalgum item de [script, pasta, …, /] tem\no+w (sem sticky) OU g+w de grupo ≠ root\nOU dono ≠ root",
           "serviço ─usa_script→ arquivo\narquivo ─dentro_de→ … → /",
           "correlation\nwritable_parent"),
    "R2": ("processo com user=root  E\npai com user ≠ root  E\npai não é sudo/su  E\nnenhum log sudo/su do usuário do pai",
           "processo ─filho_de→ processo\n+ journal (ausência de sudo/su)",
           "user_root_process"),
    "R3": ("PRÉ-REQUISITO: R1 disparou  E\nlog 'Accepted … for <usuário ≠ root>'\n→ compara mtime do script × hora do login",
           "finding R1 + journal (sessão SSH)\n+ mtime de permissions",
           "correlation"),
    "R4": ("arquivo com setuid  E  dono=root  E\ncaminho em /usr/local, /opt, /home, /tmp\n(High se o nome está no GTFOBins)",
           "só o nó do arquivo\n(modo + caminho)",
           "correlation"),
    "R5": ("processo root com URL no comando\n(curl/wget)  E  o pai pertence a um serviço\n(sobe para Medium se R1 marcou o script)",
           "processo ─conecta_a→ destino\npai ←tem_processo─ serviço",
           "correlation, ambiguous\nprivileged_service"),
    "R6": ("arquivo (não pasta) com o+w  E\nnenhuma seta executa/usa_script\nchegando nele",
           "nó do arquivo SEM\narestas de entrada",
           "permission"),
    "R7": ("serviço root com script  E\npermissões do script coletadas  E\nnenhum item da cadeia alterável por não-root",
           "mesma cadeia da R1,\ncom resposta NÃO",
           "privileged_service\nambiguous"),
}

IMPL = {  # (severidade base, confiança, hipóteses ACH, o que significa, próximo passo do analista)
    "R1": ("High", "pelo ACH", "H1 legítimo\nH2 má config. explorável\nH3 já explorado",
           "quem escreve no script vira root na\npróxima execução do serviço:\nescalada de privilégio POSSÍVEL",
           "corrigir dono/modo do script e das\npastas; coletar auditd e hash\ncontra baseline"),
    "R2": ("Medium", "pelo ACH", "H1 sudo sem log\nH2 setuid não registrado\nH3 escalada indevida",
           "um usuário comum originou um\nprocesso root sem elevação\nregistrada",
           "conferir auth.log/sudo, setuid na\ncadeia de pais e histórico\ndo shell"),
    "R3": ("Low", "Medium", "— (sem matriz ACH)",
           "havia OPORTUNIDADE: usuário presente\n+ recurso alterável; a ordem\nmtime × login pesa a favor ou contra",
           "auditd de escrita, histórico do\nshell, hash do script"),
    "R4": ("Medium\n(High se GTFOBins)", "Medium", "— (sem matriz ACH)",
           "qualquer usuário executa o binário\ncomo root; se ele tiver falha\nou der shell, é escalada",
           "dpkg -S (quem instalou), hash\ncontra a fonte, auditd de\nexecuções"),
    "R5": ("Low\n(Medium se R1)", "pelo ACH", "H1 uso legítimo\nH2 uso inesperado\nH3 C2 / exfiltração",
           "o root fala com a internet; sozinho\nNÃO é C2. Com R1, quem altera o\nscript controla o que sai",
           "ss/netstat, conteúdo enviado,\nreputação do destino"),
    "R6": ("Low", "pelo ACH", "H1 legítimo\nH2 má config.\nH3 já explorado",
           "desleixo sem impacto direto; vira\nR1 se algo passar a usar o arquivo\n(ex.: cron, fora do snapshot)",
           "corrigir o modo; conferir\ncron e timers"),
    "R7": ("Informational", "pelo ACH", "H1 legítimo\nH2 má config.\nH3 já explorado",
           "root usado do jeito certo: prova que\na ferramenta NÃO trata root\ncomo vulnerabilidade",
           "nada a corrigir; limite: o\nconteúdo do script não é\nanalisado"),
}


def table(path, title, subtitle, headers, widths, cells, row_h=1.55, note=""):
    total_w = sum(widths)
    n = len(RULES)
    fig_h = 1.9 + 0.75 + n * row_h + (0.6 if note else 0.2)
    fig, ax = plt.subplots(figsize=(total_w, fig_h))
    ax.set_xlim(0, total_w)
    ax.set_ylim(0, fig_h)
    ax.axis("off")
    ax.text(total_w / 2, fig_h - 0.55, title, ha="center", fontsize=20, weight="bold", color=INK)
    ax.text(total_w / 2, fig_h - 1.05, subtitle, ha="center", fontsize=12, color=QUIET)
    top = fig_h - 1.5
    xs = [sum(widths[:i]) for i in range(len(widths))]
    ax.add_patch(Rectangle((0, top - 0.75), total_w, 0.75, fc="#ececec", ec="none"))
    for x, w, h in zip(xs, widths, headers):
        ax.text(x + w / 2, top - 0.375, h, ha="center", va="center", fontsize=11.5, weight="bold", color=INK)
    for i, r in enumerate(RULES):
        y = top - 0.75 - (i + 1) * row_h
        if i % 2:
            ax.add_patch(Rectangle((0, y), total_w, row_h, fc="#f8f8f8", ec="none", zorder=0))
        ax.plot([0, total_w], [y, y], color=GRID, lw=1)
        for j, (x, w) in enumerate(zip(xs, widths)):
            cells(ax, r, j, x, w, y, row_h)
    ax.plot([0, total_w], [top - 0.75, top - 0.75], color="#999", lw=1.4)
    if note:
        ax.text(total_w / 2, 0.3, note, ha="center", fontsize=11, color=QUIET, style="italic")
    fig.savefig(path, dpi=120, bbox_inches="tight", facecolor="white")
    print(path)


def rule_cell(ax, r, x, w, y, h):
    c = CLASS_COLOR[CLASS[r]]
    ax.text(x + 0.2, y + h / 2, r, ha="left", va="center", fontsize=17, weight="bold", color=c)
    ax.text(x + 0.95, y + h / 2, NAMES[r], ha="left", va="center", fontsize=10.5, color=INK, linespacing=1.15)


def txt(ax, x, y, h, s, size=10.3, mono=False, color=INK, center=False):
    ax.text(x + (0 if center else 0.15), y + h / 2, s, ha="center" if center else "left", va="center",
            fontsize=size, color=color, family="DejaVu Sans Mono" if mono else None, linespacing=1.25)


# ---------------- 1. matriz técnica ----------------
def tech_cells(ax, r, j, x, w, y, h):
    if j == 0:
        rule_cell(ax, r, x, w, y, h)
    elif 1 <= j <= 4:
        used = SOURCES[r][j - 1] != "-"
        ax.add_patch(Circle((x + w / 2, y + h / 2), 0.2, fc="#333" if used else "none",
                            ec="#333" if used else "#ccc", lw=1.3))
    elif j == 5:
        txt(ax, x, y, h, TECH[r][0], size=10, mono=True)
    elif j == 6:
        txt(ax, x, y, h, TECH[r][1], size=10)
    else:
        txt(ax, x, y, h, TECH[r][2], size=10, mono=True, color=QUIET)


table(OUT / "regras_tecnica.png", "Regras R1–R7: o que o código testa",
      "● = fonte que a regra cruza   ·   condição = o teste exato feito em investigator/rules/r*.py",
      ["Regra", "Proc.", "Serv.", "Perm.", "Logs", "Condição para disparar", "No grafo / dado usado", "Cenário que testa"],
      [2.9, 0.9, 0.9, 0.9, 0.9, 6.6, 4.1, 2.9], tech_cells,
      note="R1 e R7 fazem o MESMO teste (a cadeia do script até /): alterável → R1, protegido → R7.  "
           "R6 é o complemento: arquivo 0777 que NINGUÉM usa.")


# ---------------- 2. matriz de implicação ----------------
def impl_cells(ax, r, j, x, w, y, h):
    sev, conf, hyp, mean, nxt = IMPL[r]
    if j == 0:
        rule_cell(ax, r, x, w, y, h)
    elif j == 1:
        c = CLASS_COLOR[CLASS[r]]
        ax.text(x + w / 2, y + h / 2, CLASS[r], ha="center", va="center", fontsize=9.6, weight="bold",
                color="white", bbox=dict(boxstyle="round,pad=0.35", fc=c, ec="none"))
    elif j == 2:
        txt(ax, x, y, h, sev, size=10.3, center=True)
        ax.texts[-1].set_x(x + w / 2)
    elif j == 3:
        txt(ax, x, y, h, conf, size=10.3, center=True)
        ax.texts[-1].set_x(x + w / 2)
    elif j == 4:
        txt(ax, x, y, h, hyp, size=9.8, color=QUIET if hyp.startswith("—") else INK)
    elif j == 5:
        txt(ax, x, y, h, mean, size=10.3)
    else:
        txt(ax, x, y, h, nxt, size=10, color=QUIET)


table(OUT / "regras_implicacao.png", "Regras R1–R7: o que cada resultado significa",
      "severidade = estrago SE for verdade   ·   confiança = força da evidência (com ACH: empate → Low, margem 1 → Medium, ≥ 2 → High)",
      ["Regra", "Classe", "Severidade", "Confiança", "Hipóteses (ACH)", "Implicação para o analista", "Próximo passo (evidência ausente)"],
      [2.9, 2.6, 1.9, 1.5, 3.4, 5.1, 4.6], impl_cells,
      note="Nenhuma regra afirma que houve ataque: o finding diz o que é POSSÍVEL e o que falta para confirmar.")

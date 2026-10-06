# Endpoint Investigator

Ferramenta de investigação de segurança para endpoints GNU/Linux, desenvolvida para a Avaliação
Intermediária de Tecnologias Hackers (Insper, Prof. Rodolfo Avelino).

Ela coleta um snapshot do estado da máquina (**processos, permissões e serviços**, mais o journal),
**relaciona** essas fontes entre si e produz *findings* que separam, em cada caso:

| Elemento | Significado |
|---|---|
| **Evidência** | O que foi efetivamente observado, com a origem (`arquivo:linha` ou comando) |
| **Interpretação** | O significado técnico dessa evidência |
| **Hipótese** | Explicações concorrentes, comparadas por uma matriz ACH |
| **Evidência ausente** | O que falta para confirmar ou rejeitar a hipótese |

> **Ideia central:** uma evidência isolada raramente caracteriza um incidente. "Serviço rodando como
> root" não é vulnerabilidade. O risco está na **combinação** entre identidade privilegiada, recurso
> usado e capacidade de alterar esse recurso. Quando as evidências não bastam, a ferramenta diz
> **INCONCLUSIVO** em vez de adivinhar.

A análise é **100% determinística**: o mesmo snapshot sempre gera o mesmo resultado. Existe uma camada de
LLM **opcional** (`--llm`, ver [§ 10.1](#101-camada-llm-opcional-openai)) que apenas explica os findings já
prontos; sem a flag, a ferramenta não usa modelo de linguagem.

---

## Sumário

1. [Escopo](#1-escopo)
2. [Instalação e dependências](#2-instalação-e-dependências)
3. [Execução](#3-execução)
4. [Arquitetura](#4-arquitetura)
5. [Fontes de informação](#5-fontes-de-informação)
6. [Normalização e grafo de proveniência](#6-normalização-e-grafo-de-proveniência)
7. [Regras de correlação](#7-regras-de-correlação)
8. [Matriz ACH](#8-matriz-ach-evidência--hipótese)
9. [Grafo de cenário](#9-grafo-de-cenário)
10. [Formato de saída (OCSF)](#10-formato-de-saída-ocsf)
11. [Gerador de datasets e avaliação](#11-gerador-de-datasets-e-avaliação)
12. [Testes ao vivo na Kali](#12-testes-ao-vivo-na-kali)
13. [Decisões de projeto](#13-decisões-de-projeto)
14. [Limitações](#14-limitações)
15. [Estrutura do repositório](#15-estrutura-do-repositório)
16. [Uso de IA](#16-uso-de-ia)

---

## 1. Escopo

**O que a ferramenta faz**

- Executa **sob demanda** (snapshot), sem agente permanente.
- Analisa as três dimensões obrigatórias: **processos**, **permissões** e **serviços**; usa também o
  **journal** para reconstrução temporal.
- Implementa sete regras (R1 a R7) que cruzam as fontes entre si.
- Para cada finding, entrega evidência, interpretação, hipóteses, veredito, sensibilidade e evidência ausente.
- Registra o SHA-256 dos artefatos de entrada (cadeia de custódia).

**O que a ferramenta não pretende fazer**

- Não é antivírus nem EDR; não monitora continuamente.
- Não procura todas as vulnerabilidades de um endpoint. O objetivo é demonstrar capacidade de observar,
  relacionar evidências, formular hipóteses e justificar conclusões.
- Não analisa o **conteúdo** dos arquivos (scripts, binários), apenas metadados e relações.
- Não coleta conexões de rede nem portas em escuta (ver [Limitações](#14-limitações)).

---

## 2. Instalação e dependências

- **Python 3.10 ou superior.** Apenas biblioteca padrão; **nenhum `pip install`**.
- Em Python 3.11+ os metadados das regras são lidos com `tomllib`. Em 3.10 (sem `tomllib`) é usado um
  leitor mínimo do subconjunto de TOML que os arquivos das regras usam.
- Modo ao vivo: Linux com **systemd** (`systemctl`, `journalctl`) e, de preferência, **root**.
- Opcional: `jq`, apenas para formatar a saída JSON nos roteiros de teste.

```bash
git clone <repositório> && cd PI_tech_hack      # ou copie a pasta
python3 --version                                # 3.10+
```

---

## 3. Execução

### 3.1 Modo dataset (analisa arquivos gerados)

```bash
python3 tools/generate_dataset.py --scenario correlation --seed 1 --output training/correlation
python3 -m investigator --dataset training/correlation
python3 -m investigator --dataset training/correlation --format json --output saida.json
```

### 3.2 Modo ao vivo (analisa a máquina local)

```bash
sudo python3 -m investigator --live
sudo python3 -m investigator --live --format json --output /tmp/live.json
```

Sem root, a coleta enxerga menos processos, serviços e journal. A coleta pode levar de 30 s a alguns
minutos por causa da busca de arquivos setuid.

### 3.3 Opções

| Opção | Efeito |
|---|---|
| `--dataset DIR` | Analisa um dataset gerado por `tools/generate_dataset.py` |
| `--live` | Coleta e analisa o sistema local (exclusivo com `--dataset`) |
| `--format terminal\|json` | Relatório legível (padrão) ou JSON em OCSF |
| `--matrix` | Imprime a matriz de correlação entre fontes (capacidade e neste snapshot) |
| `--graph` / `--graph-dot ARQ` | Imprime as relações do grafo / grava o grafo em DOT (graphviz) |
| `--llm` / `--llm-model M` | Camada opcional de explicação por LLM (OpenAI), verificada |
| `--no-llm` | Desliga a LLM mesmo com `ENDPOINT_LLM=on` no `.env` (use nas demos sem rede) |
| `--quiet` | Não imprime as mensagens de progresso (que vão para o stderr) |
| `--output ARQ` | Grava a saída em arquivo |

### 3.4 Como ler o relatório de terminal

```
[F-001] R1 · RISCO · severidade High · confiança Medium
  <título>                       alvo: <recurso>
  EVIDÊNCIAS (observado)         E1 [origem] fato ...
  INTERPRETAÇÃO                  significado técnico
  HIPÓTESES / MATRIZ ACH         C/I/N por hipótese e evidência; (não diagnóstica) / (frágil)
  VEREDITO / SENSIBILIDADE       H1, H2, H3 ou INCONCLUSIVO; de qual evidência depende
  NÃO PROVADO                    o que o achado não permite afirmar
  EVIDÊNCIA AUSENTE              o que desempataria
```

**Severidade** responde "qual o impacto se a hipótese for verdadeira?". **Confiança** responde "quanta
evidência sustenta a hipótese?". São eixos separados: um finding pode ter severidade alta e confiança baixa.

---

## 4. Arquitetura

O fluxo segue o de referência do enunciado
(`COLETA → NORMALIZAÇÃO → CORRELAÇÃO → EVIDÊNCIAS → HIPÓTESES → RESULTADO`):

```
┌─────────┐  ┌────────────┐  ┌───────────┐  ┌────────┐  ┌──────────┐  ┌─────┐  ┌────────┐
│ COLETA  │─►│NORMALIZAÇÃO│─►│  GRAFO DE │─►│ REGRAS │─►│ GRAFO DE │─►│ ACH │─►│ SAÍDA  │
│         │  │            │  │PROVENIÊNC.│  │R1 … R7 │  │ CENÁRIO  │  │     │  │ OCSF + │
│dataset/ │  │ campos ECS │  │ entidades │  │TOML +  │  │pré-requi-│  │C/I/N│  │terminal│
│  live   │  │+ origem    │  │ e relações│  │ Python │  │sitos     │  │     │  │        │
└─────────┘  └────────────┘  └───────────┘  └────────┘  └──────────┘  └─────┘  └────────┘
```

Os dois coletores produzem **a mesma estrutura bruta**. A partir da normalização o motor é um só, então o
que é testado nos datasets é exatamente o que roda ao vivo.

| Módulo | Responsabilidade |
|---|---|
| `investigator/collectors/dataset.py` | Lê `processes.csv`, `permissions.csv`, `services.txt`, `journal.log`; registra `arquivo:linha` e SHA-256 |
| `investigator/collectors/live.py` | Lê `/proc`, `systemctl show`, `os.stat`, `journalctl -o json` |
| `investigator/normalize.py` | Comando → interpretador + script; modo → flags; linha de log → identificador + PID; URL → destino |
| `investigator/model.py` | Entidades normalizadas com nomes de campo ECS (`to_ecs()`) |
| `investigator/graph.py` | Grafo de proveniência (1ª camada) |
| `investigator/rules/` | Uma regra = metadados `.toml` + matcher `.py` que consulta o grafo |
| `investigator/scenario.py` | Grafo de cenário (2ª camada): pré-requisitos e pontuação |
| `investigator/ach.py` | Matriz ACH, veredito, confiança e sensibilidade |
| `investigator/report/` | Saída em terminal, em OCSF (JSON) e matriz de correlação entre fontes |
| `investigator/llm/` | Camada opcional: prompt, cliente OpenAI e verificador pós-geração |
| `tools/` | Gerador de datasets, comparação com gabarito e avaliação com métricas |

O gabarito do gerador (`expected_findings`) **nunca chega ao motor**: o coletor descarta esse campo e
repassa apenas fuso e ano.

---

## 5. Fontes de informação

### 5.1 Dataset

| Arquivo | Conteúdo |
|---|---|
| `processes.csv` | Snapshot de processos (`pid, ppid, user, stat, cmd`). O `timestamp` é a **hora da coleta**, não o início do processo |
| `permissions.csv` | Metadados de arquivos e diretórios (`path, type, owner, group, mode, mtime`) |
| `services.txt` | Serviços (`UNIT, ACTIVE, USER, EXECSTART`) |
| `journal.log` | Eventos de sistema (horário local, sem ano; ano e fuso vêm do `metadata.json`) |

### 5.2 Ao vivo

| Dado | Fonte |
|---|---|
| Processos | `/proc/<pid>/status`, `cmdline`, `exe` (threads de kernel são ignoradas) |
| Serviços em execução | `systemctl list-units --state=running` + `systemctl show -p User,ExecStart,MainPID` |
| Permissões | `os.stat` (segue symlinks), **orientado por contexto**: executáveis e scripts de processos e serviços, todos os diretórios pai, mais busca restrita (ver abaixo) |
| Journal | `journalctl -o json -n 1000` |

**Busca restrita (não é varredura do filesystem):** arquivos **setuid** em `/usr/local`, `/opt`, `/home` e
`/tmp`; e arquivos regulares **gravíveis por todos** apenas em `/opt` e `/usr/local`.

### 5.3 Cadeia de custódia

O relatório lista o SHA-256 de cada artefato. No modo ao vivo, o hash é da coleta serializada de cada seção
(`live:processes`, `live:permissions`, `live:services`, `live:journal`).

---

## 6. Normalização e grafo de proveniência

### 6.1 O que a normalização faz

| Entrada bruta | Vira |
|---|---|
| `/bin/bash /opt/backup/backup.sh` | interpretador `/bin/bash` + script `/opt/backup/backup.sh` (é isso que liga serviço a arquivo) |
| modo `0777` / `4755` | flags `world_writable`, `group_writable`, `setuid`, `setgid`, `sticky` |
| `backup-agent[2417]: backup job started` | identificador `backup-agent` + PID `2417` (liga a linha de log ao processo) |
| `curl -fsS https://updates.example.invalid/status` | destino remoto `updates.example.invalid` |
| `sshd[2630]: Accepted publickey for aluno from 10.20.30.44` | sessão SSH: usuário, IP de origem, PID |

Cada fato guarda sua **origem** (`permissions.csv:3`, `journal.log:6`, `stat /opt/x`, `/proc/123`). Os nomes
de campo seguem o **ECS** (`process.pid`, `process.parent.pid`, `process.executable`, `user.name`,
`file.path`, `file.mode`, `service.name`...).

### 6.2 Grafo de proveniência (1ª camada do HOLMES)

- **Nós:** processo, serviço, arquivo, diretório, usuário, evento de log, destino remoto.
- **Arestas:** `parent_of`, `runs_as`, `executes`, `uses_script`, `has_process`, `inside_dir`,
  `logged_by`, `connects_to`. Cada aresta guarda as origens que a sustentam.

**Ligação serviço → processo** (`has_process`), por três critérios, todos registrados como evidência:
mesmo comando do `ExecStart`; `MainPID` (modo ao vivo); ou PID citado no journal sob o nome do serviço.
Um serviço sem processo associado (ex.: `apache2.service` com `apachectl` e processo `apache2`) é
tratado como tal, sem forçar a ligação. O **log é ligado ao processo pelo PID**, nunca pelo nome do
executável.

Esse grafo é o que faz processos, permissões e serviços deixarem de ser "listas independentes".

---

## 7. Regras de correlação

Cada regra tem **metadados declarativos em TOML** (id, título, severidade, confiança padrão, interpretação,
o que não foi provado, evidências ausentes e **falsos positivos conhecidos**) e um **matcher em Python**
que consulta o grafo. Os falsos positivos de cada regra alimentam a seção de limitações.

| Regra | Cruza | Dispara quando | Classificação | Severidade |
|---|---|---|---|---|
| **R1** Relação de privilégio insegura | serviço + processo + permissão | serviço root usa um recurso (binário ou script) que não-root consegue alterar ou substituir | RISCO | High |
| **R2** Contexto de execução | processo + cadeia de PPID + usuário + journal | processo root é filho de processo de usuário comum, sem registro de sudo/su | CONTEXTO | Medium |
| **R3** Linha do tempo | serviço + log + sessão + mtime | usuário comum presente enquanto um recurso alterável é usado por root. **Pré-requisito: R1** | CONTEXTO | Low |
| **R4** SUID fora do padrão | permissão + caminho | binário setuid de root em `/usr/local`, `/opt`, `/home` ou `/tmp` | RISCO | Medium (High se o nome consta no GTFOBins) |
| **R5** Saída de rede privilegiada | processo filho + serviço root + URL | `curl`/`wget` root, filho de serviço | INCONCLUSIVO | Low (Medium se o script do serviço foi marcado por R1) |
| **R6** Configuração inadequada isolada | permissão sem consumidor | arquivo gravável por todos que nenhum processo ou serviço usa | CONFIGURAÇÃO INADEQUADA | Low |
| **R7** Uso legítimo de privilégio | serviço root + script protegido | script e diretórios coletados só alteráveis por root | LEGÍTIMO | Informational |

**Correlações pedidas no enunciado:**

| Correlação | Regra |
|---|---|
| Processo + serviço + permissão → hipótese de risco | R1 |
| Processo + PPID + usuário → contexto de execução | R2 |
| Serviço + arquivo + usuário → relação de privilégio | R1 |
| Processo + serviço + log → reconstrução temporal | R3 (e linhas de log em R1, R5) |

### 7.1 R1: o que verifica

A checagem ingênua olha só o modo do script. R1 verifica **o recurso e todos os diretórios até a raiz**, porque
um script `0700` de root dentro de um diretório que qualquer um pode gravar pode ser **apagado e recriado**
(checagem equivalente à do PEASS-ng). Para cada entrada da cadeia, considera alterável por:

- qualquer usuário (`o+w`);
- grupo não privilegiado (`g+w` com grupo diferente de `root`);
- dono não-root.

**Descartes (falsos positivos tratados):** diretório com **sticky bit** (impede apagar arquivo de outro dono).
`DynamicUser=` e `RootImage=` são listados como falsos positivos conhecidos, mas **não são coletados**
hoje. Permissões de diretórios acima do coletado (ex.: `/opt`, `/`) aparecem como evidência ausente.

### 7.2 R7: por que existe

Registrar "verifiquei e está correto" prova que a ferramenta **não** aplica a regra ingênua "serviço root =
vulnerável", exigência explícita do enunciado.

### 7.3 Reclassificação por R1 (R5)

Se o script do serviço que dispara o `curl` foi marcado por R1, a severidade de R5 sobe: quem altera o script
controla o que o root envia para fora. O veredito continua INCONCLUSIVO: a ferramenta não chama isso de C2.

---

## 8. Matriz ACH: evidência × hipótese

**ACH (Analysis of Competing Hypotheses, Heuer)** compara hipóteses por **refutação**: hipóteses nas
colunas, evidências nas linhas, cada célula **C** (consistente), **I** (inconsistente) ou **N** (neutra).

- **Vence a hipótese com menos inconsistências**, e não a que tem mais evidências a favor.
- **Empate no topo → INCONCLUSIVO.** É assim que a ferramenta reconhece "não há evidência suficiente".
- **Confiança = margem** para a segunda colocada: inconclusivo = Low; margem 1 = Medium; margem ≥ 2 = High.
- **Diagnosticidade:** evidência com a mesma marca em todas as hipóteses é marcada `(não diagnóstica)` e não pesa.
- **Sensibilidade:** cada evidência não essencial é retirada e o veredito recalculado; se muda, o relatório diz
  `a conclusão depende de E#`. Evidências `(frágil)` são as que dependem de contexto (relógio, ausência de log,
  permissões não coletadas).
- **Evidência ausente:** em caso de empate, o relatório indica entre quais hipóteses não há como distinguir.

### 8.1 Hipóteses

| Regras | H1 | H2 | H3 |
|---|---|---|---|
| R1, R6, R7 | configuração legítima, sem risco | má configuração explorável, sem exploração observada | a exploração já ocorreu |
| R2 | elevação legítima (sudo/su) sem log coletado | elevação por mecanismo não registrado (ex.: setuid), sem abuso comprovado | escalada de privilégio indevida |
| R5 | uso legítimo do serviço | destino ou uso inesperado, sem evidência de exfiltração | canal de comando/exfiltração (C2) ativo |

### 8.2 Marcações codificadas (H1 / H2 / H3)

| Regra | Evidência | Marca | Observação |
|---|---|---|---|
| R1 | serviço executa como root | C C C | não diagnóstica |
| R1 | recurso alterável por não-privilegiado | **I** C C | evidência central do finding |
| R1 | execução terminou com `status=OK` | C C N | |
| R1 | usuário comum presente no journal | N C C | |
| R1 | mtime do recurso **anterior** ao login | N C **I** | frágil |
| R1 | mtime **posterior** ao login | N C C | frágil |
| R6 | arquivo gravável por todos | **I** C C | central |
| R6 | nenhum processo/serviço o usa | C C **I** | frágil: o snapshot não enxerga cron/timers |
| R7 | recurso e diretórios só alteráveis por root | C **I I** | frágil se há ancestrais não coletados |
| R2 | processo root filho de processo de usuário | C C C | não diagnóstica |
| R2 | nenhum sudo/su no journal | **I** C C | frágil: journal pode estar incompleto |
| R2 | sessão de login do usuário registrada | N C C | |
| R5 | processo root, filho de serviço, conecta ao exterior | C C C | não diagnóstica |
| R5 | o serviço registra a atividade no log | C N N | |
| R5 | script do serviço só alterável por root | C N **I** | frágil |
| R5 | script do serviço alterável por não-root | N C C | |

R3 e R4 não têm matriz: não modelamos hipóteses concorrentes para elas.

### 8.3 Exemplo (cenário `correlation`, R1)

| Evidência | H1 | H2 | H3 |
|---|---|---|---|
| E1 `backup-agent` roda como root | C | C | C (não diagnóstica) |
| E3 `backup.sh` com modo `0777` | **I** | C | C |
| E4 backup terminou com `status=OK` | C | C | N |
| E5 sessão SSH do `aluno` ativa | N | C | C |
| E6 mtime do script anterior ao login | N | C | **I** (frágil) |
| **Inconsistências** | **1** | **0** | **1** |

**Veredito H2**, confiança Medium (margem 1). Sensibilidade: depende de E6; sem ele H2 e H3 empatam. Não há
evidência de exploração; faltam hash contra baseline e auditd.

> **Limitação assumida:** no ACH original quem preenche a matriz é um analista. Aqui as marcações são
> codificadas por regra, de forma determinística. A qualidade da matriz depende dessas marcações.

---

## 9. Grafo de cenário

Segunda camada inspirada no HOLMES: cada nó é um finding e as arestas são **pré-requisitos** entre regras.

- **R3 só existe se R1 disparou** (a linha do tempo só importa se há algo alterável); a regra recebe os findings
  de R1 e referencia o `F-xxx` correspondente.
- **R5 é reclassificada** se o script do serviço foi marcado por R1.
- **Pontuação do cenário:** produto ponderado sobre os findings de RISCO,
  `score = Π (1 − severidade/5 × confiança/3)`, onde 1,0 = nenhum risco e valores menores indicam maior
  ameaça combinada. Sai no JSON como `scenario_score`. É uma adaptação nossa da ideia do HOLMES, não a
  fórmula do artigo.

---

## 10. Formato de saída (OCSF)

Cada finding sai como **OCSF Detection Finding (classe 2004)**:

| Campo | Origem |
|---|---|
| `severity_id` (1 a 5) | severidade da regra (em TOML) |
| `confidence_id` (1 a 3) | margem do ACH |
| `status_id` | 1 (New): snapshot |
| `finding_info` | uid, título, descrição, regra (`analytic.uid`) |
| `evidences[].data` | `id`, `source`, `fact` e campos `ecs` |
| `time` | menor timestamp de `processes.csv` (determinístico) |

O OCSF não tem campos para interpretação e hipóteses; eles vão no bloco de extensão **`investigation`**:
`target`, `classification`, `interpretation`, `hypotheses`, `verdict`, `ach_matrix`, `missing_evidence`,
`not_proven`, `known_false_positives`. O relatório JSON traz também `artifacts` (SHA-256) e `scenario_score`.

---

### 10.1 Camada LLM opcional (OpenAI)

Ligada por `--llm` ou por `ENDPOINT_LLM=on` no `.env`; `--no-llm` desliga nos dois casos. Ideia: **dados → evidências estruturadas → (só então) LLM**, como o
enunciado exige.

- **Entrada:** a LLM recebe **apenas os findings já produzidos** (evidências com id e origem, matriz ACH,
  veredito), nunca os dados crus do sistema. No máximo 12 findings por requisição.
- **Saída com schema fixo (JSON):** narrativa, hipóteses extras e segunda opinião, cada afirmação com
  `cites` (ids de evidência do mesmo finding).
- **Verificador pós-geração** (`investigator/llm/verify.py`): descarta a afirmação que (1) não cita
  evidência, (2) cita um id inexistente, (3) menciona caminho, IP ou PID que não está nas evidências do
  finding, ou (4) afirma exploração/comprometimento sem negação quando o veredito não é H3.
- **A LLM não altera** classificação, severidade, confiança nem veredito; se discordar, a discordância sai
  como segunda opinião ao lado do veredito determinístico.
- **Métrica:** o relatório mostra a **taxa de afirmações sem suporte** (descartadas ÷ total).
- **Falha segura:** sem chave, sem rede ou com recusa do modelo, a ferramenta avisa e entrega o relatório
  determinístico normalmente.

```bash
cp .env.example .env                         # preencha OPENAI_API_KEY; o .env está no .gitignore
# ou, sem arquivo: export OPENAI_API_KEY='sua-chave'
python3 -m investigator --dataset training/correlation --llm
# ao vivo: gere o JSON com sudo e rode a LLM como usuário comum (a chave não passa pelo sudo)
sudo python3 -m investigator --live --format json --output /tmp/live.json
python3 -m investigator.llm /tmp/live.json
```

Variáveis opcionais: `OPENAI_MODEL` (padrão `gpt-4o-mini`) e `OPENAI_BASE_URL`. O cliente usa só a
biblioteca padrão (HTTP direto para a API de Chat Completions com saída estruturada).

**Privacidade:** o modo `--llm` envia os findings (caminhos, nomes de usuário e serviços, destinos) a um
serviço externo. Use em datasets de teste; no modo ao vivo, só se estiver de acordo com isso.

**Teste offline:** `python3 tools/test_llm_verify.py` usa uma API falsa e confere que o verificador aceita
afirmações com base e descarta as inventadas (sem rede e sem chave).

## 11. Gerador de datasets e avaliação

### 11.1 Gerador (`tools/generate_dataset.py`)

Versão corrigida e ampliada do gerador fornecido:

1. `random_noise` funciona (a versão original quebrava sempre que era sorteado).
2. `scenario_permission` grava `permission` no metadata (e não `normal`).
3. Horários com fuso real (`-03:00`).
4. Cenários novos: `writable_parent` (script `0700` em diretório `0777`) e `user_root_process`.
5. `metadata.json` traz `expected_findings`, o gabarito usado nas avaliações.
6. `--scenario` força um cenário; `--batch` e `--seed` geram lotes reprodutíveis.
7. No cenário `random` com `0777`, o gabarito inclui também R3 (o `aluno` logado já existe no cenário base).

Cenários: `normal`, `permission`, `privileged_service`, `correlation`, `ambiguous`, `random`,
`writable_parent`, `user_root_process`.

### 11.2 Avaliação

```bash
python3 tools/compare_expected.py training/*      # esperado × gerado, cenário a cenário
python3 tools/evaluate.py --seeds 12              # lote + métricas
```

`evaluate.py` gera lotes (8 cenários × N seeds), roda a ferramenta e mede **precisão e recall por regra** e
o **acerto do veredito ACH por cenário**. Com 96 datasets (12 por cenário), R1 a R7 obtiveram precisão e recall
1,00 e todos os vereditos esperados foram atingidos.

**Como interpretar esses números:** o gabarito de findings vem do gerador; o gabarito de **vereditos** foi
derivado por nós do raciocínio de cada cenário. A avaliação mede coerência do motor com esse raciocínio, não
verdade absoluta, e não prova generalização para dados de outras fontes.

---

## 12. Testes ao vivo na Kali

O roteiro completo está em [`TESTES_KALI.md`](TESTES_KALI.md). Ele monta um laboratório controlado em
`/opt/lab` (script root gravável por todos, setuid inofensivo, arquivo `0777` órfão, serviço chamando
`curl` para um IP que não responde) e verifica o comportamento da ferramenta variando as permissões.

Verificado na Kali (VM do curso):

| Situação | Resultado observado |
|---|---|
| Linha de base | Apenas R4 em `/opt/google/chrome/chrome-sandbox` (falso positivo conhecido: sandbox do Chrome) |
| Script `0777` | R1, R4, R5 (Medium) e R6 |
| Script `0700` | R1 some; R7 (H1, Informational); R5 cai para Low |
| Script `0700` em diretório `0777` | R1 volta, pelo diretório pai; R7 some |
| Diretório com sticky bit (`1777`) | R1 some, R7 volta (falso positivo descartado) |
| Retirada do setuid | R4 do laboratório some; o do Chrome permanece |

---

## 13. Decisões de projeto

| Decisão | Motivo |
|---|---|
| Só biblioteca padrão, Python 3.10+ | Roda na Kali sem instalar nada |
| Mesmo motor para dataset e ao vivo | O que se testa é o que se demonstra |
| Regras como dados (TOML) + matcher | Cada regra declara os próprios falsos positivos, que viram a seção de limitações |
| Permissões orientadas por contexto | Exigência do enunciado; evita varredura indiscriminada |
| Verificar todos os diretórios até a raiz | Pega o caso de substituição via diretório gravável, que a checagem ingênua perde |
| ACH em vez de pontuação aditiva | Define de forma objetiva quando algo é inconclusivo e qual é a evidência ausente |
| Severidade e confiança em eixos separados | Impacto potencial e força da evidência são perguntas diferentes |
| Saída OCSF e campos ECS | Evita inventar nomenclatura de entrada e de saída |
| LLM opcional, só sobre findings prontos | O enunciado desconfia de "dados → LLM → analise esta máquina"; a análise é determinística e a LLM só explica, com verificação |

---

## 14. Limitações

**Escopo e método**

- **Snapshot, não monitoramento:** não vemos o que aconteceu entre duas coletas.
- **ACH automatizado:** as marcações C/I/N são codificadas por nós, por regra.
- **HOLMES adaptado:** usamos só as ideias estruturais (duas camadas, pré-requisitos, produto ponderado); o
  artigo trabalha com logs de auditoria em tempo real.
- **Sem baseline de hash:** não sabemos se um arquivo foi alterado em relação ao original; isso aparece como
  evidência ausente. Também não analisamos o conteúdo de scripts e binários.
- **Horários aproximados:** o journal do dataset não tem ano nem fuso; tratamos tudo como horário local
  (ano e fuso vêm do `metadata.json`). O mtime pode ser forjado.
- **R3 e R4 sem matriz ACH.**

**Fontes não cobertas**

- **Conexões de rede e portas em escuta** (o exemplo "processo gerenciando uma porta" do enunciado), arquivos
  abertos, usuários e grupos, mecanismos de persistência (cron, timers, `rc.local`) e hash dos arquivos analisados.
- **Consumidores fora do snapshot:** o R6 não enxerga cron nem timers; por isso "arquivo sem consumidor" é
  evidência frágil.

**Tratamentos ainda ausentes**

- **Evidência conflitante entre fontes:** no cenário `privileged_service`, o journal registra "Deactivated" mas
  o serviço aparece como `running` e o processo continua listado. A ferramenta ainda não aponta essa
  contradição.
- **`DynamicUser=` e `RootImage=`** não são coletados.
- **Serviço sem processo associado** (ex.: `apache2`) é tratado só como evidência ausente dentro de R1, não como achado próprio.

**Modo ao vivo**

- Coleta serviços **em execução** apenas; journal limitado às últimas 1000 linhas.
- Busca de setuid restrita a `/usr/local`, `/opt`, `/home` e `/tmp`; arquivos gravíveis por todos apenas em
  `/opt` e `/usr/local` (`/tmp` e `/home` geram muito ruído legítimo).
- Sem root, a visão é parcial.
- Pode demorar de 30 s a alguns minutos (varredura de setuid).

**Falsos positivos conhecidos** (declarados nos TOML)

| Regra | Falso positivo |
|---|---|
| R1 | Diretório com sticky bit; permissões acima do coletado; `DynamicUser=`/`RootImage=` |
| R2 | sudo/su com log não coletado; sessão administrativa legítima; binário setuid padrão |
| R3 | Usuário legítimo que administra a máquina; horário sem fuso confiável |
| R4 | Setuid legítimo de software de terceiros (ex.: `chrome-sandbox` em `/opt`) |
| R5 | Checagem de status, atualização ou métricas legítimas do serviço |
| R6 | Consumidor fora do snapshot; arquivo gravável por design |
| R7 | Conteúdo malicioso apesar de permissões corretas |

---

## 15. Estrutura do repositório

```
PI_tech_hack/
  investigator/
    collectors/        dataset.py · live.py
    model.py           entidades normalizadas (campos ECS)
    normalize.py       comando → interpretador+script, modo → flags, log → PID
    graph.py           grafo de proveniência
    rules/
      *.toml           metadados declarativos de cada regra (R1 a R7)
      common.py        análise de alteração (arquivo + diretórios pai), evidências, findings
      r1_privilege.py  r2_context.py  r3_timeline.py  r4_suid.py
      r5_outbound.py   r6_misconfig.py  r7_legit.py
    scenario.py        grafo de cenário (pré-requisitos + pontuação)
    ach.py             matriz ACH, veredito, confiança e sensibilidade
    report/            ocsf.py · terminal.py
    __main__.py        CLI
  tools/
    generate_dataset.py   gerador de datasets (corrigido e ampliado)
    compare_expected.py   esperado × gerado
    evaluate.py           avaliação com métricas
  TESTES_KALI.md          roteiro de testes na Kali
  README.md  DOCUMENTO_TECNICO.md
```

---

## 16. Uso de IA

Ferramentas de IA (Claude) foram usadas **no desenvolvimento**: apoio à programação, à documentação, à
revisão do desenho e à explicação dos resultados, conforme permitido no enunciado. **Em tempo de execução**,
coleta, normalização, correlação, hipóteses e veredito são produzidos por código determinístico; a camada de
LLM (`--llm`) é opcional e só redige a explicação de findings já prontos (§ 10.1). A IA não é a camada de
análise da solução.

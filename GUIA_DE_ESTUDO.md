# Guia de estudo — como o Endpoint Investigator funciona

Este guia é para **entender e conseguir explicar** o projeto ao professor. Leia na ordem. Cada parte
assume só o que foi explicado antes. No fim há perguntas que o professor pode fazer, com respostas, e
exercícios para você testar se entendeu.

**Regra de ouro para a apresentação:** você não precisa decorar código. Precisa explicar **o problema, a
ideia, o caminho dos dados e por que as decisões foram tomadas**. Se souber o exemplo da Parte 3 de cabeça,
você explica 80% do projeto.

---

## Parte 1 — O problema, em palavras simples

Imagine que você é um analista de segurança e recebe um computador Linux para investigar. Você pode listar
os processos (`ps`), os serviços (`systemctl`), as permissões dos arquivos (`ls -l`). Cada comando dá uma
**lista**. O problema: **o perigo quase nunca está em um item isolado, está na combinação entre eles.**

Três fatos soltos:

1. "O serviço `backup-agent` roda como **root**." → normal, muitos serviços rodam como root.
2. "O arquivo `backup.sh` tem permissão **0777**, qualquer um pode editar." → ruim, mas é só um arquivo.
3. "O `backup-agent` **executa** o `backup.sh`." → normal.

Juntando os três: **qualquer usuário pode editar um script que o root executa.** Então qualquer usuário pode
fazer o root executar o que ele quiser. Isso se chama **escalada de privilégio**. O risco só aparece ao
**relacionar** as três informações.

O professor pediu exatamente isto: uma ferramenta que **coleta, relaciona e interpreta**, e que diga o que
**foi observado**, o que é **interpretação**, o que é **hipótese** e o que **ainda falta** para concluir.

E há um cuidado: a ferramenta **não pode acusar sem prova**. "Pode ser explorado" não é "foi explorado". Se não
há evidência suficiente, ela precisa dizer **"inconclusivo"**.

---

## Parte 2 — O que você precisa saber de Linux (glossário)

| Termo | O que é | Por que importa aqui |
|---|---|---|
| **Processo** | Um programa em execução | É o que está rodando agora |
| **PID** | Número do processo | Identifica o processo |
| **PPID** | PID do processo **pai** (quem o criou) | Dá a árvore: de onde veio cada processo |
| **Usuário / UID** | Dono do processo. **root = UID 0**, o administrador | Root pode tudo; por isso é o alvo |
| **Serviço** | Programa que o sistema (systemd) mantém rodando em segundo plano | Ex.: ssh, backup-agent |
| **ExecStart** | O comando que o serviço executa | Liga o serviço a um arquivo/script |
| **Journal** | O log do sistema (`journalctl`) | Mostra o que aconteceu e quando |
| **Permissão (modo)** | Quem pode ler, escrever e executar um arquivo | Base da análise |
| **mtime** | Data da última modificação do arquivo | Mostra quando foi alterado |
| **SUID (setuid)** | Bit especial: o programa roda com os poderes do **dono** (root), mesmo se um usuário comum o executar | Perigoso se estiver fora do lugar |
| **Sticky bit** | Em um diretório, impede apagar arquivos de outros donos (ex.: `/tmp`) | Evita falso positivo |

### Como ler um modo como `0777` ou `4755`

O modo tem dígitos em octal: **dono, grupo, outros**. Cada dígito soma: `4`=ler, `2`=escrever, `1`=executar.

- `0777` → dono 7 (rwx), grupo 7 (rwx), outros 7 (rwx). **Qualquer um escreve.** É o "o+w" (others write).
- `0755` → dono rwx, grupo e outros só leem/executam. Normal.
- `0700` → só o dono. Protegido.
- `4755` → o `4` na frente é o **setuid**.
- `1777` → o `1` na frente é o **sticky bit**.

**Detalhe importante:** em um **diretório**, "escrever" significa **criar e apagar arquivos dentro dele**. Então
um script `0700` dentro de um diretório `0777` pode ser **apagado e recriado** por qualquer um. Isso o
`writable_parent` testa.

---

## Parte 3 — Um exemplo completo, passo a passo

Esse é o exemplo que você deve saber de cabeça. É o cenário `correlation`.

### 3.1 Os dados de entrada (arquivos do dataset)

```
services.txt:4   backup-agent.service  running  root  /bin/bash /opt/backup/backup.sh
processes.csv:5  2417  PPID 1  root  /bin/bash /opt/backup/backup.sh
permissions.csv:3 /opt/backup/backup.sh  file  root:root  modo 0777  mtime 2026-09-13 08:59
journal.log:6    Sep 14 09:25:00 ... sshd[2630]: Accepted publickey for aluno from 10.20.30.44
```

### 3.2 Etapa 1 — Coleta
Os arquivos são lidos, e cada linha guarda de **onde veio** (`permissions.csv:3`). Isso permite dizer depois
"esta evidência veio da linha 3 do arquivo X".

### 3.3 Etapa 2 — Normalização (texto vira fato)
Texto bruto não serve para raciocinar. A normalização extrai o que importa:

- `/bin/bash /opt/backup/backup.sh` → **interpretador** = `/bin/bash`, **script** = `/opt/backup/backup.sh`.
  É isso que **liga o serviço ao arquivo**.
- `0777` → flags: `world_writable = verdadeiro`.
- `sshd[2630]: Accepted ... for aluno` → sessão SSH do usuário `aluno`, às 09:25.

### 3.4 Etapa 3 — Grafo (as relações)
Um **grafo** é um conjunto de **nós** (coisas) e **arestas** (ligações). Aqui:

```
serviço backup-agent ──has_process──► processo 2417 (root)
serviço backup-agent ──uses_script──► arquivo backup.sh (0777)
arquivo backup.sh ──inside_dir──► diretório /opt/backup ──inside_dir──► /opt ──► /
processo 2417 ──runs_as──► usuário root
```

O grafo é a resposta à exigência do professor: processos, serviços e permissões deixam de ser listas
separadas e passam a ser **ligados**.

### 3.5 Etapa 4 — Regras (a lógica que procura problemas)
A regra **R1** percorre o grafo e pergunta, para cada serviço que roda como root:

> "O script que ele executa, ou algum diretório acima dele, pode ser alterado por alguém que **não** é root?"

Aqui: o `backup.sh` é `0777` → **sim**. R1 dispara e junta as evidências: o serviço (linha 4), o processo
(linha 5), a permissão (linha 3).

### 3.6 Etapa 5 — Matriz ACH (hipóteses)
Agora a ferramenta precisa dizer **o que isso significa**, sem exagerar. Ela compara **três explicações**:

- **H1:** é uma configuração legítima, sem risco.
- **H2:** é uma má configuração que **poderia** ser explorada, mas **não há exploração observada**.
- **H3:** a exploração **já aconteceu**.

Para cada evidência, ela marca se a evidência é **C** (consistente), **I** (inconsistente) ou **N** (neutra)
com cada hipótese:

| Evidência | H1 | H2 | H3 |
|---|---|---|---|
| Serviço roda como root | C | C | C |
| backup.sh é 0777 | **I** | C | C |
| Backup terminou com status=OK | C | C | N |
| Usuário `aluno` está logado | N | C | C |
| O arquivo foi modificado **antes** do login do aluno | N | C | **I** |
| **Total de I** | **1** | **0** | **1** |

**A regra do método:** vence a hipótese com **menos inconsistências** (menos "I"). O ACH funciona por
**refutação**: não ganha quem tem mais evidências a favor, ganha quem tem menos contra.

- H1 tem 1 "I": `0777` contradiz "legítimo sem risco".
- H3 tem 1 "I": o arquivo foi modificado **antes** do login do `aluno`, então não foi ele quem o alterou.
- **H2 tem 0 → vence.** Conclusão: *"relação de privilégio insegura, sem evidência de exploração."*

**Confiança:** é a diferença entre a vencedora e a segunda (aqui, 1 → **Medium**).

**Sensibilidade:** a ferramenta tira cada evidência e vê se a conclusão muda. Se tirar a evidência do mtime,
H2 e H3 **empatam**. Então ela avisa: *"a conclusão depende do mtime"*. É honestidade: o mtime pode ser
forjado.

### 3.7 Etapa 6 — Saída
O relatório mostra, nesta ordem: **evidências** (o que foi observado), **interpretação**, **hipóteses e
matriz**, **veredito**, **não provado** e **evidência ausente** (o que desempataria: hash do script, log de
auditoria...). Também sai em JSON no formato OCSF, um padrão do mercado.

### 3.8 O que acontece quando NÃO há evidência suficiente?
No cenário `writable_parent`, não há nenhum usuário logado no journal. Sem login, não existe comparação de
mtime. H2 e H3 ficam **empatadas com 0**. A regra diz: **empate = INCONCLUSIVO**. A ferramenta recusa
concluir. **Isso é exatamente o que o enunciado pede:** "uma boa ferramenta reconhece quando não há
evidências suficientes".

---

## Parte 4 — Cada peça, explicada

### 4.1 Os dois coletores (modo dataset e modo ao vivo)
- **Dataset:** lê arquivos de teste fictícios gerados pelo script do professor. É o modo de **desenvolvimento
  e avaliação**.
- **Ao vivo:** lê a máquina de verdade: `/proc` (processos), `systemctl` (serviços), `os.stat` (permissões),
  `journalctl` (logs).

**Os dois produzem a mesma estrutura.** A partir daí o resto do código é **idêntico**. Vantagem: o que foi
testado nos datasets é o mesmo código que roda na demonstração.

### 4.2 Normalização (`normalize.py`)
Transforma texto em dados estruturados: separa interpretador e script, transforma o modo em flags, extrai
PID do log, extrai o destino de um `curl`. Os nomes dos campos seguem o **ECS** (padrão da Elastic), para não
inventar nomenclatura.

### 4.3 Grafo (`graph.py`)
Guarda nós e arestas e sabe **ligar um serviço ao seu processo** por três critérios: mesmo comando do
`ExecStart`; PID principal do serviço (ao vivo); ou PID citado no journal. Cada aresta lembra a origem.

### 4.4 As sete regras

| Regra | Em uma frase | Exemplo |
|---|---|---|
| **R1** | Serviço root usa um recurso que não-root consegue alterar | root executa script `0777` |
| **R2** | Processo root nasceu de um processo de usuário comum, sem sudo/su | shell root filho do bash do aluno |
| **R3** | Linha do tempo: usuário comum presente enquanto há recurso alterável | login do aluno às 09:25 vs. mtime do script |
| **R4** | Programa setuid de root em lugar fora do padrão | `/usr/local/bin/report-sync` com `4755` |
| **R5** | Serviço root fazendo `curl` para fora | **inconclusivo**: não é C2 por si só |
| **R6** | Arquivo `0777` que ninguém usa | configuração ruim, sem risco imediato |
| **R7** | Serviço root usando script **protegido** | "verifiquei e está correto" |

**Por que R7 existe?** O enunciado diz: *"um serviço executado como root não deverá ser automaticamente
classificado como vulnerável"*. O R7 prova que a ferramenta **não faz** essa conta simplista. Ela olha o
contexto.

**R3 só funciona se R1 disparou** (pré-requisito). Faz sentido: a linha do tempo só importa se existe algo
alterável. Pré-requisitos reduzem falsos positivos.

**R5 sobe de severidade se R1 marcou o script do serviço:** quem altera o script controla o que o root envia
para fora. Mesmo assim ela continua "inconclusiva", porque não há prova de ação maliciosa.

### 4.5 O que R1 verifica de especial
Não olha só o modo do script. Olha o **arquivo e todos os diretórios até a raiz**. Um script `0700` dentro
de um diretório `0777` é **substituível**: apaga e recria. A checagem simples perderia isso. Mas ela
**descarta** diretórios com **sticky bit**, porque nesses só o dono apaga o arquivo (é o caso do `/tmp`).

### 4.6 Grafo de cenário (`scenario.py`)
Uma segunda camada: cada **finding** é um nó e há **pré-requisitos** entre regras (ex.: R3 depende de R1).
Também calcula uma **pontuação** do cenário (produto ponderado), adaptada da ideia do artigo HOLMES.

### 4.7 ACH (`ach.py`)
Já explicado na Parte 3.6. Pontos que o professor pode cobrar:
- **Por que ACH e não só uma soma de pontos?** Porque ACH define de forma objetiva *quando* é inconclusivo
  (empate), *qual* a confiança (margem) e *qual* a evidência ausente (a que desempataria).
- **Diagnosticidade:** evidência com a mesma marca em todas as hipóteses não ajuda a escolher, então "não
  pesa" (aparece como `não diagnóstica`).
- **Quem preenche a matriz?** No método original, um analista humano. **Aqui, as marcações são codificadas por
  nós, por regra.** Isso é uma **limitação que assumimos**.

### 4.8 Severidade vs. confiança
São duas perguntas diferentes:
- **Severidade:** *se a hipótese for verdadeira, qual o impacto?*
- **Confiança:** *quanta evidência sustenta a hipótese?*

Pode haver severidade **alta** com confiança **baixa**: "seria grave se fosse verdade, mas não temos como
saber". Isso é informação útil para o analista.

### 4.9 Saída OCSF
OCSF é um formato aberto para achados de segurança, usado por empresas como AWS e Splunk. Usá-lo é uma
decisão técnica: a saída pode ser lida por outras ferramentas. O OCSF não tem campo para hipóteses, então
elas vão num bloco extra chamado `investigation`.

### 4.10 O gerador de datasets e a avaliação
- O professor deu um gerador de cenários fictícios. Nós o **corrigimos e ampliamos**: consertamos o cenário
  `random` (quebrava), corrigimos o nome do cenário de permissão e o fuso, e criamos dois cenários novos.
  Também fizemos o `metadata.json` trazer o **gabarito** (`expected_findings`).
- `evaluate.py` gera 96 datasets, roda a ferramenta e compara com o gabarito. Mede **precisão** (dos que ela
  achou, quantos estavam certos) e **recall** (dos que existiam, quantos ela achou). Deu 1,00 em tudo.

---

## Parte 5 — Mapa do código (onde olhar quando o professor pedir)

| Se ele perguntar… | Abra… |
|---|---|
| "Como você lê o sistema ao vivo?" | `investigator/collectors/live.py` |
| "Como transforma texto em fatos?" | `investigator/normalize.py` |
| "Onde estão as relações entre processo, serviço e arquivo?" | `investigator/graph.py` |
| "Como R1 decide se um arquivo é alterável?" | `investigator/rules/common.py` (`alter_reasons`, `chain_for`) e `r1_privilege.py` |
| "Onde ficam os falsos positivos de cada regra?" | `investigator/rules/*.toml` |
| "Como você decide entre as hipóteses?" | `investigator/ach.py` (`decide`, `analyze`) |
| "Como o pré-requisito de R3 funciona?" | `investigator/scenario.py` e `rules/r3_timeline.py` |
| "Como você mediu se funciona?" | `tools/evaluate.py` |

### O coração de R1, em linguagem simples
O arquivo `rules/common.py` tem a função `alter_reasons`. Ela faz, para cada arquivo/diretório da cadeia:

```
se "outros" podem escrever (o+w):
    se é diretório com sticky bit  → descarta (falso positivo)
    senão                          → alterável por "qualquer usuário"
se "grupo" pode escrever e o grupo NÃO é root → alterável por esse grupo
se o dono NÃO é root                          → alterável pelo dono
```

E `chain_for` monta a lista: o arquivo, depois o diretório pai, o pai do pai, até `/`. R1 dispara se **qualquer**
item da lista tiver algum "alterável por".

### O coração do ACH, em linguagem simples
A função `decide` em `ach.py`:

```
para cada hipótese: conta quantos "I" ela recebeu
pega a(s) com menor contagem
se mais de uma empata no topo → "INCONCLUSIVO"
senão → essa é o veredito; confiança = diferença para a segunda colocada
```

Só isso. A parte difícil foi decidir **as marcações** de cada regra, e isso está documentado no README (§8).

---

## Parte 6 — Perguntas que o professor pode fazer (com respostas)

**1. "Resuma o que sua ferramenta faz."**
Coleta processos, permissões, serviços e journal de um Linux, liga tudo num grafo, aplica sete regras de
correlação e, para cada achado, separa evidência, interpretação, hipóteses e evidência ausente. Quando não há
evidência suficiente, diz INCONCLUSIVO.

**2. "Por que um serviço root não é automaticamente uma vulnerabilidade?"**
Porque o risco está na combinação: identidade privilegiada + recurso usado + capacidade de alterar o recurso.
Root executando um script que só root altera é uso legítimo. A regra R7 registra esse caso como "verificado".

**3. "O que prova que sua análise não é só um monte de `if`?"**
Há três diferenças: as regras cruzam fontes por meio de um grafo; as hipóteses concorrentes são comparadas
formalmente (ACH), com empate gerando INCONCLUSIVO; e cada finding traz evidência com origem, o que não
provamos e o que falta. Mas é honesto dizer: as regras e as marcações do ACH são codificadas por nós.

**4. "O que é ACH e por que usou?"**
Analysis of Competing Hypotheses, de Richards Heuer (CIA). Compara explicações concorrentes por refutação:
vence a que tem menos evidências contra. Usei porque dá uma definição objetiva de "inconclusivo" (empate),
de confiança (margem) e de evidência ausente (a que desempataria).

**5. "Quando a ferramenta diz 'inconclusivo'?"**
Quando as duas melhores hipóteses empatam em número de inconsistências. Exemplo: script `0700` em diretório
`0777` e nenhum usuário comum no journal: H2 ("explorável, sem exploração") e H3 ("explorado") ficam ambas com
zero, e não há como distinguir.

**6. "Isso está fixo no código? Funciona para outros casos?"**
As regras não usam nomes, caminhos ou PIDs dos cenários. O coletor ainda descarta o gabarito antes da análise.
Na Kali montamos um laboratório com nomes que o código nunca viu, e os resultados mudaram só com as
permissões. O que está definido no código são as políticas (diretórios considerados fora do padrão, lista de
binários do GTFOBins) e as marcações do ACH. Não garantimos generalização para qualquer sistema.

**7. "Por que não usou LLM?"**
O enunciado diz que a IA não pode ser a única camada. Optamos por zero LLM em tempo de execução: o resultado é
determinístico e reproduzível, não depende de internet e não corre o risco de afirmar algo sem evidência.
Usamos IA no desenvolvimento, e isso está declarado.

**8. "Qual a diferença entre evidência, interpretação e hipótese no seu relatório?"**
Evidência: fato observado com origem (`permissions.csv:3`). Interpretação: o significado técnico ("qualquer
usuário pode alterar um script executado por UID 0"). Hipótese: explicação possível (H1, H2, H3). Evidência
ausente: o que confirmaria ou rejeitaria (hash contra baseline, auditd).

**9. "Como você liga um serviço ao processo?"**
Por três critérios: o comando do processo é igual ao `ExecStart` do serviço; o `MainPID` do systemd (ao
vivo); ou o PID citado no journal sob o nome do serviço. Cada critério fica registrado como evidência.

**10. "Por que olha os diretórios pai?"**
Porque um script `0700` dentro de um diretório que qualquer um escreve pode ser apagado e recriado. Se
olhássemos só o modo do arquivo, perderíamos esse caso. Descartamos diretórios com sticky bit, porque neles
só o dono apaga o arquivo.

**11. "O que é um falso positivo na sua ferramenta? Dê um exemplo."**
O R4 disparou na Kali para `/opt/google/chrome/chrome-sandbox`: é um setuid root em `/opt`, mas é parte normal
do Chrome. A ferramenta já declara isso como falso positivo conhecido e indica o que faltaria para decidir
(`dpkg -S` para ver o pacote).

**12. "Como você sabe que a ferramenta funciona?"**
Três formas: 96 datasets gerados pelo gerador corrigido (precisão e recall 1,00); comparação cenário a cenário
com o gabarito; e testes na Kali com um laboratório controlado, variando permissões e vendo as regras
reagirem. Limitação honesta: o gabarito dos vereditos é nosso, então mede coerência e não prova
generalização.

**13. "Qual a limitação mais importante?"**
(a) Não coletamos conexões de rede nem portas em escuta, que é o exemplo dado no enunciado. (b) As marcações do
ACH são codificadas por nós. (c) É um snapshot, não monitora o que ocorreu entre coletas. (d) Não analisamos
o conteúdo dos scripts.

**14. "O que você faria com mais tempo?"**
Ler `/proc/net/tcp` para ligar processos a portas em escuta; detectar evidência conflitante entre fontes (o
journal diz que o serviço parou, mas ele aparece rodando); coletar `DynamicUser` e `RootImage`; avaliar contra
datasets de outras fontes.

**15. "Por que severidade e confiança são separadas?"**
Severidade é o impacto se for verdade; confiança é quanta evidência temos. Algo pode ser grave e incerto. Misturar
os dois esconderia essa informação do analista.

**16. "O mtime não pode ser forjado?"**
Pode, e a ferramenta declara isso. Por isso a evidência é marcada como **frágil** e a análise de sensibilidade
mostra que o veredito depende dela. Sem ela, H2 e H3 empatam.

**17. "O que é o grafo de cenário?"**
Uma segunda camada em que cada finding é um nó e há pré-requisitos entre regras (R3 só existe se R1 disparou).
Reduz falsos positivos. Veio do artigo HOLMES (IEEE S&P 2019); usamos só as ideias estruturais, não o
processamento em tempo real.

**18. "Por que Python, só biblioteca padrão?"**
Roda na Kali sem instalar nada e é fácil de ler e demonstrar.

**19. "A ferramenta altera algo no sistema?"**
Não. Só lê (`/proc`, `systemctl show`, `os.stat`, `journalctl`). A única escrita é o relatório, quando se usa
`--output`.

**20. "Usou IA para fazer isso?"**
Sim, no desenvolvimento (código e documentação), como o enunciado permite, e está declarado no documento. A
ferramenta em si não usa IA ao rodar. **Prepare-se para explicar qualquer parte do código**: o professor pode
pedir.

---

## Parte 7 — Exercícios (teste se entendeu)

Faça no terminal, **preveja o resultado antes de rodar**.

1. Gere `writable_parent`. Por que o R1 dispara se o script é `0700`? *(Resposta: o diretório pai é `0777`.)*
2. Mude o diretório para `1777` (sticky). O que acontece? *(R1 some; o sticky bit descarta.)*
3. No `correlation`, por que a confiança do R1 é Medium e não High? *(Margem de 1 entre H2 e as outras.)*
4. Por que o R7 diz "legítimo" e não "vulnerável"? *(Script protegido de ponta a ponta.)*
5. Por que o `normal` não gera nenhum finding? *(Nada sugere risco: `/etc/shadow` `0640` está correto.)*
6. O que acontece com o R5 quando o script passa de `0777` para `0700`? *(Severidade cai de Medium para Low.)*
7. Explique em voz alta, em 1 minuto, o exemplo da Parte 3. Se travar, releia.

### Experimento que fixa o ACH
```bash
python3 tools/generate_dataset.py --scenario correlation --seed 1 --output /tmp/c
python3 -m investigator --dataset /tmp/c | grep -A12 "MATRIZ ACH"
```
Leia linha por linha a tabela de C/I/N e confira as contagens de "I" com o que você calcularia à mão.

---

## Parte 8 — Roteiro de apresentação sugerido (5 a 7 minutos)

1. **(30 s) O problema:** "Uma evidência isolada não prova nada. O risco está na combinação."
2. **(1 min) O fluxo:** coleta → normalização → grafo → regras → hipóteses (ACH) → resultado.
3. **(2 min) Demo no dataset:** rode `correlation`. Mostre evidência, matriz, veredito, sensibilidade e
   evidência ausente.
4. **(1 min) O caso inconclusivo:** rode `writable_parent`. "Aqui ela se recusa a concluir."
5. **(1 min) Métricas:** `evaluate.py` (96 datasets, 1,00), citando a limitação do gabarito.
6. **(1 min) Ao vivo na Kali** (se der): mude `0777` → `0700` e mostre R1 virar R7.
7. **(30 s) Limitações:** rede e portas não cobertas, marcações do ACH codificadas por nós.

**Dica:** antes da demo, deixe os comandos prontos num arquivo, para não digitar nada na hora.

---

## Parte 9 — O que dizer se você não souber

É melhor dizer "essa parte foi apoiada por IA; o que eu entendo é X, e o código está em Y" do que inventar.
O enunciado permite o uso de IA e pede que o grupo tenha **domínio técnico**: isso vale 0,5 ponto da
demonstração. Estude as Partes 1 a 4 e as perguntas 1 a 12. Com isso você cobre quase tudo.

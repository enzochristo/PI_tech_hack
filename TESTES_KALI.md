# Roteiro de testes na Kali — Endpoint Investigator

Rode tudo a partir da pasta do projeto. A Parte A não precisa de root; a Parte B precisa de `sudo`.
Os testes da Parte B criam situações controladas para validar a lógica da ferramenta; não geram incidente real.

---

## Parte A — Datasets

### A1. Versão do Python e avaliação em lote

```bash
python3 --version          # precisa de 3.10+
python3 tools/evaluate.py --seeds 12
```

**Interpretar:** a tabela deve mostrar `1.00` de precisão e recall para R1 a R7 e todos os cenários com
vereditos `n/n`. Qualquer linha começando com `!` é um desvio (falso positivo, falso negativo ou veredito
diferente do esperado).

### A2. Um dataset por cenário contra o gabarito

```bash
for s in normal permission privileged_service correlation ambiguous random writable_parent user_root_process; do
  python3 tools/generate_dataset.py --scenario $s --seed 1 --output training/$s
done
python3 tools/compare_expected.py training/*
```

**Interpretar:**

| Marca | Significado |
|---|---|
| `OK` | finding esperado que a ferramenta achou |
| `FALTOU` | falso negativo |
| `EXTRA` | falso positivo (a ferramenta gerou algo fora do gabarito) |

O final deve ser `acertos=12 faltaram=0 extras=0`. No cenário `normal` o correto é **nenhum finding**:
`/etc/shadow` com `0640 root:shadow` e a sessão do `aluno` não são suspeitos.

### A3. Relatórios completos

```bash
python3 -m investigator --dataset training/correlation
python3 -m investigator --dataset training/writable_parent
python3 -m investigator --dataset training/user_root_process
```

**Como ler cada finding:**

| Seção | O que é |
|---|---|
| EVIDÊNCIAS | o que foi observado, com `arquivo:linha` |
| INTERPRETAÇÃO | significado técnico da evidência |
| MATRIZ ACH | C (consistente), I (inconsistente), N (neutra) por hipótese; vence quem tem menos I |
| `(não diagnóstica)` | evidência igual para todas as hipóteses; não pesa |
| `(frágil)` | evidência que depende de contexto (mtime, ausência de log, permissões não coletadas) |
| VEREDITO | H1, H2, H3 ou **INCONCLUSIVO** (empate: a ferramenta recusa concluir) |
| SENSIBILIDADE | de qual evidência a conclusão depende |
| NÃO PROVADO | o que o achado não permite afirmar |
| EVIDÊNCIA AUSENTE | o que desempataria |

**Esperado por cenário:**

| Cenário | Findings | Observação |
|---|---|---|
| `correlation` | R1, R4, R3, R5 | R1 → H2 (confiança Medium); R5 com severidade Medium por causa do R1 |
| `writable_parent` | R1 | via diretório pai (`/opt/sync` 0777); veredito INCONCLUSIVO |
| `user_root_process` | R2 | processo root filho de shell de usuário, sem sudo/su; INCONCLUSIVO |

### A4. Determinismo e cadeia de custódia

```bash
diff <(python3 -m investigator --dataset training/correlation --format json) \
     <(python3 -m investigator --dataset training/correlation --format json) && echo "determinístico"
sha256sum training/correlation/*.csv training/correlation/*.txt training/correlation/*.log
python3 -m investigator --dataset training/correlation | head -7
```

**Interpretar:** `diff` vazio = o mesmo dataset gera sempre o mesmo resultado. Os hashes do `sha256sum`
devem coincidir com o início dos hashes em "Artefatos analisados".

---

## Parte B — Coleta ao vivo

### B0. Linha de base (antes do laboratório)

```bash
sudo apt install -y jq
sudo python3 -m investigator --live --format json --output /tmp/base.json
jq '.findings[] | {regra: .finding_info.analytic.uid, alvo: .investigation.target, veredito: .investigation.verdict, severidade}' /tmp/base.json
```

**Interpretar:** a coleta pode levar de 30 s a alguns minutos (varredura de setuid). Em uma Kali limpa espere
poucos findings. Um R4 em setuid de software de terceiros em `/opt` ou `/usr/local` é um falso positivo
conhecido, listado nos falsos positivos da regra.

### B1. Montar o laboratório

```bash
sudo mkdir -p /opt/lab
printf '#!/bin/bash\nwhile true; do curl -s --max-time 50 http://10.255.255.1/ ; sleep 1; done\n' | sudo tee /opt/lab/backup.sh >/dev/null
sudo chmod 0777 /opt/lab/backup.sh
sudo cp /usr/bin/true /opt/lab/report-sync && sudo chmod 4755 /opt/lab/report-sync
sudo touch /opt/lab/orphan.sh && sudo chmod 0777 /opt/lab/orphan.sh
sudo tee /etc/systemd/system/lab-backup.service >/dev/null <<'EOF'
[Service]
ExecStart=/bin/bash /opt/lab/backup.sh
EOF
sudo systemctl daemon-reload && sudo systemctl start lab-backup.service
systemctl status lab-backup.service --no-pager | head -5
```

Atalho de leitura usado nos testes seguintes:

```bash
lab() { sudo python3 -m investigator --live --format json --output /tmp/lab.json && jq -r '.findings[] | "\(.finding_info.analytic.uid)  \(.investigation.target)  veredito=\(.investigation.verdict)  sev=\(.severity)  conf=\(.confidence)"' /tmp/lab.json; }
```

### Teste 1 — tudo ligado

```bash
lab
```

**Esperado** (além da linha de base): R1 em `/opt/lab/backup.sh`; R4 em `/opt/lab/report-sync`; R6 em
`/opt/lab/orphan.sh`; R5 em `10.255.255.1` com severidade Medium (reclassificada pelo R1).

**Interpretar:** R1 é a relação de privilégio (root + script gravável por todos). R5 continua inconclusivo:
a ferramenta não chama de C2 sem evidência.

### Teste 2 — R1 vira R7

```bash
sudo chmod 0700 /opt/lab/backup.sh; lab
```

**Esperado:** R1 some; aparece R7 (legítimo) em `backup.sh`; R4, R6 e R5 continuam, e o R5 perde o aumento de
severidade.

**Interpretar:** root usando um script protegido **não** é vulnerabilidade. É o argumento central do enunciado.

### Teste 3 — diretório pai gravável

```bash
sudo chmod 0777 /opt/lab; lab
jq '.findings[] | select(.finding_info.analytic.uid=="R1") | .evidences[].data.fact' /tmp/lab.json
```

**Esperado:** R1 volta em `backup.sh` (que continua `0700`); R7 some. O `jq` mostra a evidência do diretório.

**Interpretar:** o arquivo está protegido, mas quem grava no diretório pode apagá-lo e recriá-lo.

### Teste 4 — sticky bit descarta o falso positivo

```bash
sudo chmod 1777 /opt/lab; lab
```

**Esperado:** R1 some; R7 volta.

**Interpretar:** com sticky bit só o dono apaga o arquivo; a checagem descarta o caso.

### Teste 5 — R4 depende do bit setuid

```bash
sudo chmod 0755 /opt/lab/report-sync; lab
```

**Esperado:** R4 some.

**Interpretar:** a regra olha o bit setuid, não o nome do arquivo.

### Teste 6 — linha do tempo (R3) e sensibilidade do ACH

```bash
sudo chmod 0777 /opt/lab; sudo chmod 0777 /opt/lab/backup.sh
sudo useradd -m labuser && echo 'labuser:lab123' | sudo chpasswd
sudo systemctl start ssh
ssh -o StrictHostKeyChecking=no labuser@localhost 'exit'
lab
```

**Esperado:** R3 com alvo `labuser`; R1 com veredito **H2**, confiança Medium (mtime do script anterior ao
login contradiz H3).

Depois simule uma alteração posterior ao login:

```bash
sudo touch /opt/lab/backup.sh; lab
sudo python3 -m investigator --live | grep -A25 "R1 ·"
```

**Esperado:** R1 volta a **INCONCLUSIVO**; R3 passa a dizer mtime "POSTERIOR".

**Interpretar:** a mesma evidência frágil mudou o veredito, e a ferramenta mostra essa dependência em
SENSIBILIDADE. O `labuser` pode ter alterado o script, então a conclusão correta é "não dá para afirmar".

### Teste 7 — falso positivo que não deve disparar (R2)

Em outro terminal rode `sudo -s` e deixe aberto. No terminal original:

```bash
lab
```

**Esperado:** sem R2.

**Interpretar:** o sudo está registrado no journal, então a elevação é explicada. Se aparecer R2 no processo
`sudo`, o journal estava vazio ou ilegível. É um falso positivo documentado ("sudo/su cujo log não foi
coletado").

---

## Limpeza

```bash
sudo systemctl stop lab-backup.service
sudo rm -rf /opt/lab /etc/systemd/system/lab-backup.service /tmp/lab.json /tmp/base.json
sudo systemctl daemon-reload
sudo userdel -r labuser; sudo systemctl stop ssh
```

---

## Se algo fugir do esperado

Anote: o comando executado e a saída do `lab`. Pontos mais prováveis de problema:

- `aviso: systemctl indisponível` ou `journalctl indisponível` (sem systemd ou sem permissão);
- coleta muito demorada (varredura de setuid em `/home`);
- R3 ausente: o journal pode não estar persistente ou não ter a linha `Accepted ... for labuser`
  (confira com `journalctl -t sshd -n 5`).

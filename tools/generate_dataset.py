#!/usr/bin/env python3
"""
Endpoint Investigator - Training Dataset Generator (versão corrigida e ampliada)

Baseado no gerador original do professor. Mudanças:
  1. random_noise funciona (o original quebrava sempre que era sorteado).
  2. scenario_permission grava "permission" no metadata (o original gravava "normal").
  3. Horários com fuso real (-03:00); o original rotulava um horário UTC como -03:00.
  4. Cenários novos: writable_parent e user_root_process.
  5. metadata.json traz expected_findings, o gabarito usado pelo evaluate.py.
  6. --scenario força um cenário específico.

Uso:
  python3 generate_dataset.py --level basic --output training/basic-001
  python3 generate_dataset.py --scenario correlation --output training/correlation
  python3 generate_dataset.py --batch 10 --level intermediate --output training/ --seed 1
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


LOCAL_TZ = timezone(timedelta(hours=-3))


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build(start, processes, permissions, services, logs, kind, expected, readme_extra=""):
    return {
        "kind": kind,
        "processes": [
            {"timestamp": iso(start + timedelta(seconds=i * 2)), "pid": str(pid), "ppid": str(ppid),
             "user": user, "stat": stat, "cmd": cmd}
            for i, (pid, ppid, user, stat, cmd) in enumerate(processes)
        ],
        "permissions": [
            {"path": path, "type": typ, "owner": owner, "group": group, "mode": mode,
             "mtime": iso(start - timedelta(days=(i % 12), minutes=i))}
            for i, (path, typ, owner, group, mode) in enumerate(permissions)
        ],
        "services": services,
        "logs": [(start + timedelta(seconds=offset), message) for offset, message in logs],
        "expected_findings": expected,
        "readme_extra": readme_extra,
    }


def normal_parts() -> tuple[list, list, list, list]:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (701, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (733, 1, "www-data", "S", "/usr/sbin/apache2 -k start"),
        (744, 733, "www-data", "S", "/usr/sbin/apache2 -k start"),
        (1204, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (1212, 1204, "aluno", "S", "/bin/bash"),
        (1234, 1212, "aluno", "S", "/usr/bin/python3 /home/aluno/check.py"),
    ]
    permissions = [
        ("/opt/app", "directory", "root", "root", "0755"),
        ("/opt/app/check.py", "file", "root", "root", "0755"),
        ("/etc/shadow", "file", "root", "shadow", "0640"),
        ("/usr/local/bin/report-sync", "file", "root", "root", "0755"),
        ("/home/aluno/check.py", "file", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("apache2.service", "running", "root", "/usr/sbin/apachectl start"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (2, "systemd[1]: Started apache2.service - The Apache HTTP Server."),
        (8, "sshd[1204]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (10, "systemd-logind[640]: New session 7 of user aluno."),
        (15, "python3[1234]: routine check completed status=OK"),
    ]
    return processes, permissions, services, logs


def scenario_normal(start: datetime) -> dict:
    processes, permissions, services, logs = normal_parts()
    return build(start, processes, permissions, services, logs, "normal", [])


def scenario_permission(start: datetime) -> dict:
    processes, permissions, services, logs = normal_parts()
    permissions.append(("/opt/reports", "directory", "root", "root", "0755"))
    permissions.append(("/opt/reports/report.sh", "file", "root", "root", "0777"))
    return build(
        start, processes, permissions, services, logs, "permission",
        [{"rule": "R6", "target": "/opt/reports/report.sh"}],
        "Há uma permissão excessivamente ampla em um arquivo, mas o dataset não "
        "estabelece que ele seja executado por um serviço privilegiado. O aluno "
        "deve diferenciar configuração inadequada de evidência de exploração.",
    )


def scenario_privileged_service(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2421, 2417, "root", "S", "/usr/bin/curl -fsS https://updates.example.invalid/status"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0700"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (60, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (63, "backup-agent[2417]: backup job started"),
        (64, "backup-agent[2417]: checking remote status endpoint"),
        (65, "backup-agent[2417]: backup completed with status=OK"),
        (66, "systemd[1]: backup-agent.service: Deactivated successfully."),
    ]
    return build(
        start, processes, permissions, services, logs, "privileged_service",
        [
            {"rule": "R7", "target": "/opt/backup/backup.sh"},
            {"rule": "R5", "target": "updates.example.invalid"},
        ],
        "O serviço executa como root, mas o script está restrito a root. O objetivo "
        "é evitar a regra simplista 'serviço root = vulnerabilidade'.",
    )


def scenario_correlation(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2421, 2417, "root", "S", "/usr/bin/curl -fsS https://updates.example.invalid/status"),
        (2630, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (2638, 2630, "aluno", "S", "/bin/bash"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0777"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
        ("/usr/local/bin/report-sync", "file", "root", "root", "4755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (120, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (123, "backup-agent[2417]: backup job started"),
        (124, "backup-agent[2417]: checking remote status endpoint"),
        (125, "backup-agent[2417]: backup completed with status=OK"),
        (1500, "sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (1502, "systemd-logind[640]: New session 9 of user aluno."),
    ]
    return build(
        start, processes, permissions, services, logs, "correlation",
        [
            {"rule": "R1", "target": "/opt/backup/backup.sh"},
            {"rule": "R3", "target": "aluno"},
            {"rule": "R4", "target": "/usr/local/bin/report-sync"},
            {"rule": "R5", "target": "updates.example.invalid"},
        ],
        "Este é um cenário de correlação. A combinação serviço privilegiado + script "
        "world-writable deve gerar um finding de risco. O dataset não prova que houve exploração.",
    )


def scenario_ambiguous(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (901, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (1500, 1, "root", "S", "/usr/bin/python3 /opt/monitor/agent.py"),
        (1510, 1500, "root", "S", "/usr/bin/curl -fsS https://metrics.example.invalid/v1/push"),
        (1632, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (1640, 1632, "aluno", "S", "/bin/bash"),
        (1645, 1640, "aluno", "S", "/usr/bin/python3 /home/aluno/check.py"),
    ]
    permissions = [
        ("/opt/monitor", "directory", "root", "root", "0755"),
        ("/opt/monitor/agent.py", "file", "root", "root", "0755"),
        ("/home/aluno/check.py", "file", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("monitor-agent.service", "running", "root", "/usr/bin/python3 /opt/monitor/agent.py"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (20, "systemd[1]: Started monitor-agent.service - Monitoring Agent."),
        (22, "monitor-agent[1500]: sending metrics batch=12"),
        (25, "monitor-agent[1510]: remote status=200"),
        (1600, "sshd[1632]: Accepted publickey for aluno from 10.20.30.44 port 51590 ssh2"),
        (1615, "python3[1645]: check completed status=OK"),
    ]
    return build(
        start, processes, permissions, services, logs, "ambiguous",
        [
            {"rule": "R7", "target": "/opt/monitor/agent.py"},
            {"rule": "R5", "target": "metrics.example.invalid"},
        ],
        "Há uma conexão externa iniciada por um serviço root. Sem outras evidências, "
        "isso não deve ser tratado automaticamente como C2 ou malware. O aluno deve investigar contexto.",
    )


def scenario_random(start: datetime) -> dict:
    processes, permissions, services, logs = normal_parts()
    pid = random.randint(2000, 6000)
    service_name = random.choice(["backup-agent", "report-sync", "inventory-agent"])
    script = f"/opt/{service_name}/run.sh"
    mode = random.choice(["0750", "0700", "0770", "0777"])
    processes.append((pid, 1, "root", "Ss", f"/bin/bash {script}"))
    permissions.append((f"/opt/{service_name}", "directory", "root", "root", "0755"))
    permissions.append((script, "file", "root", "root", mode))
    services.append((f"{service_name}.service", "running", "root", f"/bin/bash {script}"))
    logs.append((random.randint(100, 300), f"systemd[1]: Started {service_name}.service - {service_name} service."))
    expected = [{"rule": "R1" if mode == "0777" else "R7", "target": script}]
    if mode == "0777":  # normal_parts já traz o aluno logado: R3 (linha do tempo) também se aplica
        expected.append({"rule": "R3", "target": "aluno"})
    return build(
        start, processes, permissions, services, logs, "random",
        expected,
        f"Serviço root executa {script} com modo {mode}.",
    )


def scenario_writable_parent(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (3105, 1, "root", "Ss", "/bin/bash /opt/sync/sync.sh"),
    ]
    permissions = [
        ("/opt/sync", "directory", "root", "root", "0777"),
        ("/opt/sync/sync.sh", "file", "root", "root", "0700"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("sync-agent.service", "running", "root", "/bin/bash /opt/sync/sync.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (40, "systemd[1]: Starting sync-agent.service - Sync Agent..."),
        (42, "sync-agent[3105]: sync job started"),
    ]
    return build(
        start, processes, permissions, services, logs, "writable_parent",
        [{"rule": "R1", "target": "/opt/sync/sync.sh"}],
        "O script está restrito a root (0700), mas o diretório que o contém é gravável por "
        "qualquer usuário e não tem sticky bit: o arquivo pode ser apagado e recriado.",
    )


def scenario_user_root_process(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2630, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (2638, 2630, "aluno", "S", "/bin/bash"),
        (2701, 2638, "root", "S", "/bin/sh -i"),
    ]
    permissions = [
        ("/home/aluno", "directory", "aluno", "aluno", "0750"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (900, "sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (902, "systemd-logind[640]: New session 11 of user aluno."),
    ]
    return build(
        start, processes, permissions, services, logs, "user_root_process",
        [{"rule": "R2", "target": "2701"}],
        "Um processo root é filho direto do shell de um usuário comum, sem registro de sudo ou su "
        "no journal. O dataset não mostra como a elevação ocorreu.",
    )


SCENARIOS = {
    "normal": scenario_normal,
    "permission": scenario_permission,
    "privileged_service": scenario_privileged_service,
    "correlation": scenario_correlation,
    "ambiguous": scenario_ambiguous,
    "random": scenario_random,
    "writable_parent": scenario_writable_parent,
    "user_root_process": scenario_user_root_process,
}

LEVELS = {
    "basic": ["normal", "permission", "privileged_service"],
    "intermediate": ["permission", "privileged_service", "correlation", "random", "writable_parent"],
    "challenge": ["correlation", "ambiguous", "random", "writable_parent", "user_root_process"],
}


def make_dataset(level: str, scenario_name: str | None, seed: int | None, out_dir: Path) -> None:
    if seed is not None:
        random.seed(seed)
    start = datetime(2026, 9, 14, 9, 0, tzinfo=LOCAL_TZ)

    if scenario_name is None:
        scenario_name = random.choice(LEVELS[level])
    data = SCENARIOS[scenario_name](start)

    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(out_dir / "processes.csv", ["timestamp", "pid", "ppid", "user", "stat", "cmd"], data["processes"])
    write_csv(out_dir / "permissions.csv", ["path", "type", "owner", "group", "mode", "mtime"], data["permissions"])

    with (out_dir / "services.txt").open("w", encoding="utf-8") as fh:
        fh.write("UNIT                         ACTIVE   USER      EXECSTART\n")
        for unit, active, user, execstart in data["services"]:
            fh.write(f"{unit:<28}{active:<9}{user:<10}{execstart}\n")

    with (out_dir / "journal.log").open("w", encoding="utf-8") as fh:
        for dt, message in sorted(data["logs"], key=lambda x: x[0]):
            fh.write(f"{dt.strftime('%b %d %H:%M:%S')} srv-app-01 {message}\n")

    metadata = {
        "dataset_type": "synthetic_training",
        "level": level,
        "scenario": data["kind"],
        "seed": seed,
        "timezone": "-03:00",
        "year": start.year,
        "generated_at": datetime.now().astimezone().isoformat(),
        "expected_findings": data["expected_findings"],
        "warning": "Dados fictícios para uso acadêmico; não representam um incidente real.",
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    readme = [
        "ENDPOINT INVESTIGATOR - DATASET DE TREINAMENTO",
        "",
        "Este dataset é sintético e foi criado para testar ferramentas de investigação de endpoints Linux.",
        "Não representa um incidente real.",
        "",
        f"Nível: {level}",
        f"Cenário: {data['kind']}",
        "",
        "Arquivos:",
        "- processes.csv: snapshot de processos (timestamp = hora da coleta, não do início do processo).",
        "- permissions.csv: metadados de arquivos e diretórios.",
        "- services.txt: serviços em execução.",
        "- journal.log: eventos de sistema (horário local -03:00, sem ano).",
        "- metadata.json: metadados de geração e gabarito (expected_findings).",
        "",
        "Orientação: não assuma que um único indicador é suficiente para concluir que houve comprometimento.",
        "Procure correlações e diferencie evidência, interpretação e hipótese.",
    ]
    if data["readme_extra"]:
        readme.extend(["", "Nota didática do cenário:", data["readme_extra"]])
    (out_dir / "README.txt").write_text("\n".join(readme) + "\n", encoding="utf-8")

    print(f"Dataset criado em: {out_dir} ({data['kind']})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera datasets sintéticos para Endpoint Investigator.")
    parser.add_argument("--level", choices=list(LEVELS), default="basic")
    parser.add_argument("--scenario", choices=list(SCENARIOS), default=None, help="Força um cenário específico.")
    parser.add_argument("--output", default="./dataset", help="Diretório de saída.")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--batch", type=int, default=1, help="Quantidade de datasets a gerar.")
    args = parser.parse_args()

    root = Path(args.output)
    if args.batch <= 1:
        make_dataset(args.level, args.scenario, args.seed, root)
        return

    root.mkdir(parents=True, exist_ok=True)
    for i in range(1, args.batch + 1):
        seed = (args.seed + i - 1) if args.seed is not None else random.randint(1, 10_000_000)
        make_dataset(args.level, args.scenario, seed, root / f"dataset-{i:03d}")


if __name__ == "__main__":
    main()

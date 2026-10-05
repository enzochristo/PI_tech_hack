"""Entidades normalizadas. Nomes de campo seguem o ECS (ver to_ecs)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Process:
    pid: int
    ppid: int
    user: str
    stat: str
    cmd: str
    collected_at: str
    executable: str | None
    args: list[str]
    interpreter: str | None
    script: str | None
    src: str

    def to_ecs(self) -> dict:
        return {
            "process.pid": self.pid,
            "process.parent.pid": self.ppid,
            "process.executable": self.executable,
            "process.args": self.args,
            "process.command_line": self.cmd,
            "user.name": self.user,
        }


@dataclass
class FileEntry:
    path: str
    type: str  # file | directory
    owner: str
    group: str
    mode: str
    mtime: str
    flags: dict[str, bool]
    src: str

    @property
    def is_dir(self) -> bool:
        return self.type == "directory"

    def to_ecs(self) -> dict:
        return {
            "file.path": self.path,
            "file.type": self.type,
            "file.owner": self.owner,
            "file.group": self.group,
            "file.mode": self.mode,
            "file.mtime": self.mtime,
        }


@dataclass
class Service:
    unit: str
    active: str
    user: str
    execstart: str
    executable: str | None
    args: list[str]
    interpreter: str | None
    script: str | None
    src: str
    main_pid: int | None = None

    @property
    def name(self) -> str:
        return self.unit.removesuffix(".service")

    def to_ecs(self) -> dict:
        return {
            "service.name": self.name,
            "service.state": self.active,
            "user.name": self.user,
            "process.command_line": self.execstart,
        }


@dataclass
class LogEvent:
    timestamp: str  # ISO com fuso
    host: str
    ident: str
    pid: int | None
    message: str
    src: str


@dataclass
class Inventory:
    processes: list[Process]
    files: list[FileEntry]
    services: list[Service]
    logs: list[LogEvent]
    artifacts: list[dict]  # {"name", "sha256"}: cadeia de custódia
    meta: dict = field(default_factory=dict)


@dataclass
class Evidence:
    id: str
    source: str
    fact: str
    ecs: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    target: str
    title: str
    description: str
    severity: int  # OCSF severity_id
    confidence: int  # OCSF confidence_id
    classification: str
    evidences: list[Evidence]
    interpretation: str
    missing_evidence: list[str]
    not_proven: str
    false_positives: list[str]
    uid: str = ""
    verdict: str = ""  # H1 | H2 | H3 | INCONCLUSIVO (preenchido pelo ACH)
    ach: dict | None = None
    correlates: list[str] = field(default_factory=list)  # fontes cruzadas pela regra

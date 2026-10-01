from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Project:
    technologies: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    has_source: bool = False
    has_files: bool = False

    def report(self) -> dict[str, Any]:
        return {"technologies": self.technologies, "artifacts": self.artifacts}


@dataclass
class ScannerContext:
    workspace: Path
    output: Path
    raw_dir: Path
    project: Project
    timeout_seconds: int
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class ScannerResult:
    name: str
    version: str
    status: str
    started_at: str
    finished_at: str
    duration_ms: int
    raw_output: str
    error: str | None = None
    reason: str | None = None
    finding_count: int = 0

    def report(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "durationMs": self.duration_ms,
            "rawOutput": self.raw_output,
            "error": self.error,
            "reason": self.reason,
            "findingCount": self.finding_count,
        }


def dataclass_dict(value: Any) -> dict[str, Any]:
    return asdict(value)
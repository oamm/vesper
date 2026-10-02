from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Project:
    technologies: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    dependency_manifests: list[str] = field(default_factory=list)
    covered_dependency_manifests: list[str] = field(default_factory=list)
    unsupported_dependency_manifests: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    artifact_summary: dict[str, int] = field(default_factory=dict)
    exclusions: list[dict[str, str]] = field(default_factory=list)
    file_count: int = 0
    has_source: bool = False
    has_files: bool = False

    def report(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "technologies": self.technologies,
            "artifacts": self.artifacts,
            "artifactSummary": self.artifact_summary,
            "artifactCount": len(self.artifacts),
            "fileCount": self.file_count,
            "sourceFileCount": len(self.source_files),
            "dependencyManifests": self.dependency_manifests,
            "supportedDependencyManifests": self.lockfiles,
            "coveredDependencyManifests": self.covered_dependency_manifests,
            "unsupportedDependencyManifests": self.unsupported_dependency_manifests,
            "exclusions": self.exclusions,
        }


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
    schema_version: str | None = None
    reason_code: str | None = None
    coverage: dict[str, Any] = field(default_factory=dict)

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
            "schemaVersion": self.schema_version,
            "reasonCode": self.reason_code,
            "coverage": self.coverage,
        }


def dataclass_dict(value: Any) -> dict[str, Any]:
    return asdict(value)
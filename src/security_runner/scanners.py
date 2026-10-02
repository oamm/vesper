import json
import os
import re
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_runner.models import ScannerContext, ScannerResult
from security_runner.normalization import normalize


class ScanTimeout(Exception):
    pass


class Scanner(ABC):
    name: str
    output_name: str | None = None
    version_command: list[str]

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    @abstractmethod
    def can_run(self, context: ScannerContext) -> bool:
        raise NotImplementedError

    @abstractmethod
    def command(self, context: ScannerContext) -> list[str]:
        raise NotImplementedError

    def validate_schema(self, raw: dict[str, Any]) -> str | None:
        raise ValueError("scanner has no supported output schema validator")

    def not_applicable_result(
        self, context: ScannerContext
    ) -> tuple[str, str, str, dict[str, Any]]:
        return (
            "not_applicable",
            "prerequisite_not_detected",
            f"{self.name} prerequisites were not detected; project technologies: "
            f"{', '.join(context.project.technologies) or 'none'}; detected artifacts: "
            f"{', '.join(context.project.artifacts) or 'none'}.",
            {"assessment": "not_applicable", "candidateArtifacts": context.project.artifacts},
        )

    def coverage_from_output(self, raw: dict[str, Any], context: ScannerContext) -> dict[str, Any]:
        return {"assessment": "unknown"}

    def initial_coverage(self, context: ScannerContext) -> dict[str, Any]:
        return {}

    def finalize_coverage(self, coverage: dict[str, Any], status: str) -> dict[str, Any]:
        return coverage

    def execute(self, context: ScannerContext) -> tuple[ScannerResult, list[dict[str, Any]]]:
        output_name = self.output_name or self.name
        raw_path = context.raw_dir / f"{output_name}.json"
        raw_relative = f"raw/{output_name}.json"
        started = datetime.now(timezone.utc)
        started_clock = time.monotonic()
        print(f"[{self.name}] Starting...", flush=True)
        status = "completed"
        error = None
        reason = None
        reason_code = None
        coverage = self.initial_coverage(context)
        raw: Any = {}
        version = self._version()
        process_returncode: int | None = None
        parsed_successfully = False
        schema_version = None

        if not self.enabled:
            status = "skipped"
            reason_code = "disabled_by_configuration"
            reason = "disabled by configuration"
            coverage = {"assessment": "not_applicable"}
        elif not self.can_run(context):
            status, reason_code, reason, coverage = self.not_applicable_result(context)
        else:
            try:
                output, stderr, process_returncode = _run_process(
                    self.command(context), context.workspace, context.timeout_seconds
                )
                try:
                    if not output.strip():
                        raise json.JSONDecodeError("empty scanner output", output, 0)
                    raw = json.loads(output)
                except json.JSONDecodeError:
                    status = "failed"
                    error = "scanner emitted empty or invalid JSON"
                    raw = {"_runner": {"message": error, "returnCode": process_returncode}}
                else:
                    if not isinstance(raw, dict):
                        status = "failed"
                        error = "scanner JSON root must be an object"
                        raw = {"_runner": {"message": error, "rootType": type(raw).__name__}}
                    else:
                        try:
                            schema_version = self.validate_schema(raw)
                            parsed_successfully = True
                        except ValueError as exc:
                            status = "failed"
                            error = str(exc)
            except ScanTimeout:
                status = "timeout"
                error = f"scanner exceeded {context.timeout_seconds}s timeout"
                raw = {"_runner": {"message": "Scanner timed out"}}
            except (OSError, subprocess.SubprocessError) as exc:
                status = "failed"
                error = _safe_text(str(exc))
                raw = {"_runner": {"message": "Scanner could not be executed"}}

        safe_raw = sanitize_data(raw)
        if parsed_successfully:
            try:
                coverage.update(self.coverage_from_output(safe_raw, context))
            except Exception:
                coverage["assessment"] = "unknown"
        elif not coverage:
            coverage = {
                "assessment": "not_applicable" if status in {"skipped", "not_applicable"} else "unknown",
            }
        raw_path.write_text(json.dumps(safe_raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        findings: list[dict[str, Any]] = []
        if parsed_successfully:
            try:
                findings = normalize(self.name, safe_raw)
            except Exception as exc:
                status = "failed"
                error = f"scanner result normalization failed ({type(exc).__name__})"

        if parsed_successfully and status != "failed":
            if process_returncode == 0:
                status = "completed_with_findings" if findings else "clean"
            elif process_returncode == 1 and findings:
                status = "completed_with_findings"
            else:
                status = "failed"
                error = f"scanner exited with code {process_returncode}"

        if status == "failed" and process_returncode not in (None, 0) and error:
            error = f"{error} (exit code {process_returncode})"
        if status == "failed" and 'stderr' in locals() and stderr:
            error = f"{error}: {_safe_text(stderr[-500:]).strip()}"
        coverage = self.finalize_coverage(coverage, status)
        finished = datetime.now(timezone.utc)
        duration = int((time.monotonic() - started_clock) * 1000)
        result = ScannerResult(
            name=self.name, version=version, status=status, started_at=started.isoformat(),
            finished_at=finished.isoformat(), duration_ms=duration, raw_output=raw_relative, error=error,
            reason=reason, reason_code=reason_code, coverage=coverage, finding_count=len(findings),
            schema_version=schema_version,
        )
        if status in {"clean", "completed_with_findings"}:
            print(f"[{self.name}] Completed in {duration / 1000:.1f}s", flush=True)
        elif status in {"skipped", "not_applicable", "unsupported_manifest"}:
            print(f"[{self.name}] {status.replace('_', ' ').title()} ({reason})", flush=True)
        else:
            print(f"[{self.name}] {status}: {error}", flush=True)
        return result, findings

    def _version(self) -> str:
        try:
            completed = subprocess.run(self.version_command, capture_output=True, text=True, timeout=10, check=False)
            output = (completed.stdout or completed.stderr).strip().splitlines()
            return output[0][:160] if output else "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unavailable"


class TrivyScanner(Scanner):
    name = "trivy"
    version_command = ["trivy", "--version"]

    def can_run(self, context: ScannerContext) -> bool:
        return context.project.has_files

    def not_applicable_result(self, context: ScannerContext) -> tuple[str, str, str, dict[str, Any]]:
        return (
            "not_applicable",
            "empty_workspace",
            "Trivy requires repository files; project inventory found 0 files and no artifacts.",
            {"assessment": "not_applicable", "filesDiscovered": 0, "candidateArtifacts": []},
        )

    def coverage_from_output(self, raw: dict[str, Any], context: ScannerContext) -> dict[str, Any]:
        results = raw.get("Results")
        requested = {
            "dependency": True,
            "secret": True,
            "container": True,
            "iac": True,
        }
        coverage: dict[str, Any] = {
            "assessment": "unknown",
            "filesDiscovered": context.project.file_count,
            "candidateArtifacts": context.project.artifacts,
            "capabilities": {
                capability: {
                    "assessment": "unknown",
                    "requested": requested[capability],
                    "resultEntries": None,
                }
                for capability in requested
            },
        }
        if isinstance(results, list):
            coverage["resultEntryCount"] = len(results)
            for capability in coverage["capabilities"].values():
                capability["resultEntries"] = len(results)
        return coverage

    def validate_schema(self, raw: dict[str, Any]) -> str:
        results = raw.get("Results")
        if (
            raw.get("SchemaVersion") != 2
            or not isinstance(raw.get("ArtifactName"), str)
            or not isinstance(raw.get("ArtifactType"), str)
            or not isinstance(raw.get("CreatedAt"), str)
            or not isinstance(raw.get("Metadata"), dict)
            or ("Results" in raw and results is not None and not isinstance(results, list))
        ):
            raise ValueError("scanner output schema is unsupported (expected Trivy v2 artifact metadata and optional Results array)")
        if any(not isinstance(result, dict) or not isinstance(result.get("Target"), str) for result in results or []):
            raise ValueError("scanner output schema is unsupported (Trivy Results entries must contain a Target string)")
        return str(raw["SchemaVersion"])

    def command(self, context: ScannerContext) -> list[str]:
        skipped_dirs = [".git", "node_modules", "bin", "obj", "dist", "build", "artifacts", "coverage", "target", "security-results"]
        skipped_dirs.extend(path for path in context.exclude_paths if path not in skipped_dirs)
        command = [
            "trivy", "fs", "--quiet", "--no-progress", "--format", "json",
            "--scanners", "vuln,misconfig,secret",
            "--skip-dirs", ",".join(skipped_dirs),
            "--timeout", f"{context.timeout_seconds}s", str(context.workspace),
        ]
        if context.exclude_files:
            command.extend(["--skip-files", ",".join(context.exclude_files)])
        return command


class OsvScanner(Scanner):
    name = "osv-scanner"
    output_name = "osv"
    version_command = ["osv-scanner", "--version"]

    def can_run(self, context: ScannerContext) -> bool:
        return bool(context.project.lockfiles)

    def initial_coverage(self, context: ScannerContext) -> dict[str, Any]:
        targets = list(context.project.lockfiles)
        unsupported_count = len(context.project.unsupported_dependency_manifests) + len(context.project.unsupported_dependency_projects)
        return {
            "assessment": "unknown",
            "targetCounts": {
                "attempted": len(targets), "completed": 0, "failed": 0,
                "unsupported": unsupported_count,
            },
            "targets": [{"path": path, "state": "attempted", "findingCount": None} for path in targets],
        }

    def finalize_coverage(self, coverage: dict[str, Any], status: str) -> dict[str, Any]:
        targets = coverage.get("targets")
        if not isinstance(targets, list):
            return coverage
        completed = status in {"clean", "completed_with_findings"}
        state = "completed" if completed else "failed" if status in {"failed", "timeout"} else "not_applicable"
        for target in targets:
            target["state"] = state
        counts = coverage.setdefault("targetCounts", {})
        counts["completed"] = len(targets) if completed else 0
        counts["failed"] = len(targets) if state == "failed" else 0
        coverage["assessment"] = "partial" if counts.get("unsupported", 0) else "complete" if completed else "unknown"
        return coverage

    def not_applicable_result(self, context: ScannerContext) -> tuple[str, str, str, dict[str, Any]]:
        unsupported_manifests = context.project.unsupported_dependency_manifests
        unsupported_projects = context.project.unsupported_dependency_projects
        unsupported_count = len(unsupported_manifests) + len(unsupported_projects)
        if unsupported_count:
            return (
                "unsupported_manifest",
                "unsupported_dependency_input",
                f"OSV-Scanner 2.3.3 cannot directly analyze {unsupported_count} detected dependency project/manifest(s); "
                "see project.json for the inventory.",
                {
                    "assessment": "limited",
                    "unsupportedManifestCount": len(unsupported_manifests),
                    "unsupportedProjectCount": len(unsupported_projects),
                    "targetCounts": {"attempted": 0, "completed": 0, "failed": 0, "unsupported": unsupported_count},
                },
            )
        return (
            "not_applicable",
            "no_dependency_manifest",
            f"No dependency manifest candidate was detected among {len(context.project.artifacts)} project artifacts. "
            f"Detected technologies: {', '.join(context.project.technologies) or 'none'}. OSV-Scanner requires a supported lockfile or pinned manifest.",
            {
                "assessment": "not_applicable",
                "targetCounts": {"attempted": 0, "completed": 0, "failed": 0, "unsupported": 0},
                "candidateManifestCount": 0,
            },
        )

    def coverage_from_output(self, raw: dict[str, Any], context: ScannerContext) -> dict[str, Any]:
        unsupported_manifests = context.project.unsupported_dependency_manifests
        unsupported_projects = context.project.unsupported_dependency_projects
        results = raw.get("results")
        findings_by_target: dict[str, int] = {}
        for result in results if isinstance(results, list) else []:
            source = result.get("source") if isinstance(result, dict) else None
            source_path = _workspace_relative(source.get("path")) if isinstance(source, dict) else ""
            package_results = result.get("packages") or [] if isinstance(result, dict) else []
            finding_count = sum(
                len(package_result.get("vulnerabilities") or [])
                for package_result in package_results
                if isinstance(package_result, dict)
            )
            if source_path:
                findings_by_target[source_path] = findings_by_target.get(source_path, 0) + finding_count
        targets = [
            {"path": path, "state": "attempted", "findingCount": findings_by_target.get(path, 0)}
            for path in context.project.lockfiles
        ]
        return {
            "assessment": "unknown",
            "unsupportedManifestCount": len(unsupported_manifests),
            "unsupportedProjectCount": len(unsupported_projects),
            "unsupportedInputCount": len(unsupported_manifests) + len(unsupported_projects),
            "targets": targets,
            "resultSourcesWithFindings": len(findings_by_target),
        }

    def validate_schema(self, raw: dict[str, Any]) -> str | None:
        results = raw.get("results")
        if not isinstance(results, list):
            raise ValueError("scanner output schema is unsupported (expected OSV results array)")
        if any(
            not isinstance(result, dict)
            or not isinstance(result.get("source"), dict)
            or not isinstance(result.get("packages"), list)
            for result in results
        ):
            raise ValueError("scanner output schema is unsupported (OSV results require source and packages)")
        metadata = raw.get("metadata")
        if isinstance(metadata, dict):
            version = metadata.get("schemaVersion") or metadata.get("schema_version")
            if isinstance(version, (str, int)) and not isinstance(version, bool):
                return str(version)
        return None

    def command(self, context: ScannerContext) -> list[str]:
        command = ["osv-scanner", "scan", "source", "--format", "json"]
        for target in context.project.lockfiles:
            command.extend(["--lockfile", str(context.workspace / target)])
        return command


class SastScanner(Scanner):
    name = "semgrep"
    version_command = ["semgrep", "--version"]

    def can_run(self, context: ScannerContext) -> bool:
        return context.project.has_source

    def not_applicable_result(self, context: ScannerContext) -> tuple[str, str, str, dict[str, Any]]:
        return (
            "not_applicable",
            "no_supported_source_files",
            "Semgrep requires supported source files; project technologies: "
            f"{', '.join(context.project.technologies) or 'none'}; detected source-file count: 0; "
            f"inventory artifacts: {', '.join(context.project.artifacts) or 'none'}.",
            {
                "assessment": "not_applicable",
                "filesDiscovered": 0,
                "filesAnalyzed": 0,
                "rulesetsConfigured": ["p/security-audit"],
                "rulesLoaded": None,
                "parseErrors": 0,
                "candidateArtifacts": context.project.artifacts,
                "candidateFiles": context.project.source_files,
                "supportedArtifacts": [],
            },
        )

    def validate_schema(self, raw: dict[str, Any]) -> str:
        if not isinstance(raw.get("version"), str) or not raw["version"]:
            raise ValueError("scanner output schema is unsupported (expected Semgrep version string)")
        if not isinstance(raw.get("results"), list) or not isinstance(raw.get("errors"), list):
            raise ValueError("scanner output schema is unsupported (expected Semgrep results and errors arrays)")
        if any(not isinstance(result, dict) for result in raw["results"]):
            raise ValueError("scanner output schema is unsupported (Semgrep results entries must be objects)")
        return raw["version"]

    def coverage_from_output(self, raw: dict[str, Any], context: ScannerContext) -> dict[str, Any]:
        paths = raw.get("paths")
        errors = raw.get("errors")
        skipped_rules = raw.get("skipped_rules")
        scanned = paths.get("scanned") if isinstance(paths, dict) else None
        skipped = paths.get("skipped") if isinstance(paths, dict) else None
        stats = raw.get("stats")
        rules_loaded = stats.get("rulesLoaded") if isinstance(stats, dict) else None
        if not isinstance(rules_loaded, int) or isinstance(rules_loaded, bool):
            rules_loaded = None
        if isinstance(skipped, dict):
            skipped_paths = skipped.get("paths")
        else:
            skipped_paths = skipped
        scanned_paths = [_workspace_relative(path) for path in scanned] if isinstance(scanned, list) else []
        normalized_skipped = [
            _workspace_relative(item.get("path") if isinstance(item, dict) else item)
            for item in skipped_paths
        ] if isinstance(skipped_paths, list) else []
        source_files = set(context.project.source_files)
        scanned_sources = source_files.intersection(scanned_paths)
        skipped_sources = source_files.intersection(normalized_skipped)
        parse_error_entries = [error for error in errors or [] if _is_parse_error(error)] if isinstance(errors, list) else []
        parse_error_paths: set[str] = set()
        parse_error_files = []
        for error in parse_error_entries:
            error_paths = error.get("paths") or [error.get("path")]
            if isinstance(error_paths, str):
                error_paths = [error_paths]
            normalized_paths = sorted({_workspace_relative(path) for path in error_paths if path})
            parse_error_paths.update(normalized_paths)
            message = error.get("message") or error.get("shortMessage") or error.get("longMessage")
            for error_path in normalized_paths:
                parse_error_files.append({
                    "path": error_path,
                    "type": _semgrep_error_type(error),
                    **({"message": _safe_text(str(message))[:300]} if message else {}),
                })
        successfully_parsed = scanned_sources - parse_error_paths
        parse_errors = len(parse_error_entries) if isinstance(errors, list) else None
        observed_errors = len(errors) if isinstance(errors, list) else None
        skipped_count = len(skipped_paths) if isinstance(skipped_paths, list) else None
        rules_skipped = len(skipped_rules) if isinstance(skipped_rules, list) else None
        if not isinstance(scanned, list) or observed_errors is None or rules_skipped is None:
            assessment = "unknown"
        elif observed_errors or rules_skipped or (skipped_count or 0) > 0:
            assessment = "partial"
        elif not isinstance(skipped_paths, list):
            assessment = "unknown"
        elif not scanned:
            assessment = "limited"
        elif rules_loaded is None:
            assessment = "unknown"
        elif rules_loaded == 0:
            assessment = "limited"
        else:
            assessment = "complete"

        coverage = {
            "assessment": assessment,
            "filesDiscovered": len(context.project.source_files),
            "attemptedFiles": len(scanned_sources),
            "filesAnalyzed": len(successfully_parsed),
            "analyzedFiles": sorted(successfully_parsed),
            "parseErrorFiles": sorted(parse_error_files, key=lambda item: (item["path"], item["type"])),
            "pathsReportedScanned": len(scanned) if isinstance(scanned, list) else None,
            "csharpFilesDiscovered": sum(path.casefold().endswith(".cs") for path in context.project.source_files),
            "csharpFilesAnalyzed": sum(path.casefold().endswith(".cs") for path in successfully_parsed),
            "rulesetsConfigured": ["p/security-audit"],
            "rulesLoaded": rules_loaded,
            "rulesSkipped": rules_skipped,
            "parseErrors": parse_errors,
            "ruleLoadStatus": "no_reported_rule_errors" if observed_errors == 0 else "unknown",
        }
        if skipped_count is not None:
            coverage["filesSkipped"] = len(skipped_sources)
            coverage["pathsReportedSkipped"] = skipped_count
            coverage["skippedFiles"] = [
                {
                    "path": _safe_text(_workspace_relative(item.get("path"))) if isinstance(item, dict) else _safe_text(_workspace_relative(item)),
                    **({"reason": _safe_text(str(item["reason"]))} if isinstance(item, dict) and item.get("reason") else {}),
                }
                for item in skipped_paths
            ]
        if observed_errors is not None:
            coverage["errors"] = observed_errors
        return coverage

    def command(self, context: ScannerContext) -> list[str]:
        command = [
            "semgrep", "scan", "--config", "p/security-audit", "--json", "--metrics", "off",
            "--exclude", ".git", "--exclude", "node_modules", "--exclude", "bin",
            "--exclude", "obj", "--exclude", "dist", "--exclude", "build",
            "--exclude", "artifacts", "--exclude", "coverage", "--exclude", "security-results",
        ]
        for path in context.exclude_paths:
            command.extend(["--exclude", path])
        for path in context.exclude_files:
            command.extend(["--exclude", path])
        command.append(str(context.workspace))
        return command


def _run_process(command: list[str], cwd: Path, timeout: int) -> tuple[str, str, int]:
    process = subprocess.Popen(
        command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=(os.name != "nt"),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        else:
            process.kill()
        process.communicate()
        raise ScanTimeout from None
    return stdout, stderr, process.returncode


def sanitize_data(value: Any, secret_context: bool = False) -> Any:
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            key_text = str(key)
            child_is_secret = secret_context or key_text.lower() in {"secrets", "secretmatches"}
            if secret_context and key_text.lower() in {"match", "secret", "code", "lines", "content", "value"}:
                output[key_text] = "[REDACTED]" if item is not None else None
            else:
                output[key_text] = sanitize_data(item, child_is_secret)
        return output
    if isinstance(value, list):
        return [sanitize_data(item, secret_context) for item in value]
    if isinstance(value, str):
        return _safe_text(value)
    return value


def _is_parse_error(error: Any) -> bool:
    if not isinstance(error, dict):
        return False
    error_type = _semgrep_error_type(error).casefold()
    return "parse" in error_type or "pars" in error_type


def _semgrep_error_type(error: dict[str, Any]) -> str:
    error_type = error.get("type")
    if isinstance(error_type, list) and error_type:
        error_type = error_type[0]
    return error_type[:120] if isinstance(error_type, str) else "unknown"


def _workspace_relative(value: Any) -> str:
    path = str(value or "").replace("\\", "/")
    if path.startswith("/workspace/"):
        return path[len("/workspace/"):]
    while path.startswith("./"):
        path = path[2:]
    return path


def _safe_text(value: str) -> str:
    text = re.sub(r"(?i)(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]*\s*[:=]\s*[\"']?)([^\s\"'`,;]+)", r"\1[REDACTED]", value)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b", "[REDACTED]", text)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", text, flags=re.S)
    return text
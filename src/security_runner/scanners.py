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
        raw: Any = {}
        version = self._version()

        if not self.enabled:
            status = "skipped"
            reason = "disabled by configuration"
        elif not self.can_run(context):
            status = "not_applicable"
            reason = "not applicable to detected project"
        else:
            try:
                output, stderr, returncode = _run_process(self.command(context), context.workspace, context.timeout_seconds)
                try:
                    raw = json.loads(output) if output.strip() else {}
                except json.JSONDecodeError:
                    raw = {"_runner": {"message": "Scanner did not emit valid JSON", "returnCode": returncode}}
                    error = "scanner output was not valid JSON"
                findings = normalize(self.name, raw) if isinstance(raw, dict) else []
                if returncode == 1 and findings:
                    status = "completed_with_findings"
                elif returncode != 0:
                    status = "failed"
                    error = f"scanner exited with code {returncode}"
                if stderr and status == "failed":
                    error = f"{error}: {_safe_text(stderr[-500:]).strip()}"
            except ScanTimeout:
                status = "timeout"
                error = f"scanner exceeded {context.timeout_seconds}s timeout"
                raw = {"_runner": {"message": "Scanner timed out"}}
            except (OSError, subprocess.SubprocessError) as exc:
                status = "failed"
                error = _safe_text(str(exc))
                raw = {"_runner": {"message": "Scanner could not be executed"}}

        safe_raw = sanitize_data(raw)
        raw_path.write_text(json.dumps(safe_raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        findings = normalize(self.name, safe_raw) if status in {"completed", "completed_with_findings", "failed"} else []
        if status == "completed":
            status = "completed_with_findings" if findings else "clean"
        finished = datetime.now(timezone.utc)
        duration = int((time.monotonic() - started_clock) * 1000)
        result = ScannerResult(
            name=self.name, version=version, status=status, started_at=started.isoformat(),
            finished_at=finished.isoformat(), duration_ms=duration, raw_output=raw_relative, error=error,
            reason=reason, finding_count=len(findings),
        )
        if status in {"clean", "completed_with_findings"}:
            print(f"[{self.name}] Completed in {duration / 1000:.1f}s", flush=True)
        elif status in {"skipped", "not_applicable"}:
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

    def command(self, context: ScannerContext) -> list[str]:
        skipped_dirs = [".git", "node_modules", "bin", "obj", "dist", "build", "artifacts", "coverage", "target", "security-results"]
        skipped_dirs.extend(path for path in context.exclude_paths if path not in skipped_dirs)
        return [
            "trivy", "fs", "--quiet", "--no-progress", "--format", "json",
            "--scanners", "vuln,misconfig,secret",
            "--skip-dirs", ",".join(skipped_dirs),
            "--timeout", f"{context.timeout_seconds}s", str(context.workspace),
        ]


class OsvScanner(Scanner):
    name = "osv-scanner"
    output_name = "osv"
    version_command = ["osv-scanner", "--version"]

    def can_run(self, context: ScannerContext) -> bool:
        return bool(context.project.lockfiles)

    def command(self, context: ScannerContext) -> list[str]:
        return ["osv-scanner", "scan", "source", "--recursive", "--format", "json", str(context.workspace)]


class SastScanner(Scanner):
    name = "semgrep"
    version_command = ["semgrep", "--version"]

    def can_run(self, context: ScannerContext) -> bool:
        return context.project.has_source

    def command(self, context: ScannerContext) -> list[str]:
        command = [
            "semgrep", "scan", "--config", "p/security-audit", "--json", "--metrics", "off",
            "--exclude", ".git", "--exclude", "node_modules", "--exclude", "bin",
            "--exclude", "obj", "--exclude", "dist", "--exclude", "build",
            "--exclude", "artifacts", "--exclude", "coverage", "--exclude", "security-results",
        ]
        for path in context.exclude_paths:
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


def _safe_text(value: str) -> str:
    text = re.sub(r"(?i)(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]*\s*[:=]\s*[\"']?)([^\s\"'`,;]+)", r"\1[REDACTED]", value)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b", "[REDACTED]", text)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", text, flags=re.S)
    return text
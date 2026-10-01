import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from security_runner.detection import detect_project
from security_runner.models import ScannerContext
from security_runner.normalization import deduplicate
from security_runner.policy import evaluate
from security_runner.remediations import PRIORITY_ORDER, build_remediations
from security_runner.scanners import OsvScanner, SastScanner, TrivyScanner
from security_runner import __version__

EXIT_GATE_FAILED = 1
EXIT_RUNNER_FAILED = 2
EXIT_CONFIG_ERROR = 3
EXIT_INTERNAL_ERROR = 4


class ConfigurationError(Exception):
    pass


def load_config(config_path: Path | None) -> dict[str, Any]:
    default_path = Path("/config/default.yaml")
    if not default_path.exists():
        default_path = Path(__file__).parents[2] / ".." / "config" / "default.yaml"
        default_path = default_path.resolve()
    try:
        config = yaml.safe_load(default_path.read_text(encoding="utf-8")) or {}
        if config_path and config_path.exists():
            override = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            config = _merge(config, override)
        _validate_config(config)
        return config
    except (OSError, yaml.YAMLError, TypeError) as exc:
        raise ConfigurationError(f"Unable to load configuration: {exc}") from exc


def run_scan(workspace: Path, output: Path, config: dict[str, Any], scanner_instances: list[Any] | None = None) -> tuple[int, dict[str, Any]]:
    workspace = workspace.resolve()
    output = output.resolve()
    if not workspace.is_dir():
        raise RuntimeError(f"Workspace does not exist: {workspace}")
    output.mkdir(parents=True, exist_ok=True)
    raw_dir = output / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    scan_id = os.environ.get("SECURITY_SCAN_ID") or str(uuid.uuid4())
    output_exclusion = os.environ.get("SECURITY_SCAN_OUTPUT_RELATIVE_PATH")
    exclude_paths = [output_exclusion] if output_exclusion else []

    print("[runner] Detecting project...", flush=True)
    project = detect_project(workspace, set(exclude_paths))
    (output / "project.json").write_text(json.dumps(project.report(), indent=2) + "\n", encoding="utf-8")
    print(f"[runner] Detected {', '.join(project.technologies) if project.technologies else 'no known technologies'}", flush=True)

    scanner_config = config.get("scanner", {})
    timeout_config = config.get("timeouts", {})
    scanners = scanner_instances or [
        TrivyScanner(scanner_config.get("trivy", {}).get("enabled", True)),
        OsvScanner(scanner_config.get("osv", {}).get("enabled", True)),
        SastScanner(scanner_config.get("sast", {}).get("enabled", True)),
    ]
    all_findings: list[dict[str, Any]] = []
    scanner_results = []
    for scanner in scanners:
        timeout = int(timeout_config.get(scanner.name, timeout_config.get("default", 300)))
        context = ScannerContext(workspace, output, raw_dir, project, timeout, exclude_paths)
        result, findings = scanner.execute(context)
        scanner_results.append(result.report())
        all_findings.extend(findings)

    print("[runner] Normalizing results...", flush=True)
    findings = deduplicate(all_findings)
    remediations = build_remediations(findings)
    (output / "findings.json").write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "remediations.json").write_text(json.dumps(remediations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    gate = evaluate(findings, config["policy"], remediations)
    active_scanners = [result for result in scanner_results if result["status"] not in {"skipped", "not_applicable"}]
    successful_scanners = [
        result for result in active_scanners
        if result["status"] in {"clean", "completed", "completed_with_findings"}
    ]
    failed_scanners = [result for result in active_scanners if result not in successful_scanners]
    execution_status = "completed" if active_scanners and not failed_scanners else "incomplete"
    if execution_status == "incomplete":
        if not active_scanners:
            incomplete_reason = "No applicable scanners were executed; security assessment is indeterminate."
        else:
            failed_names = ", ".join(result["name"] for result in failed_scanners)
            incomplete_reason = f"Scanner execution incomplete ({failed_names}); security assessment is indeterminate."
        gate = {
            **gate,
            "policyStatus": gate["status"],
            "status": "indeterminate",
            "reason": incomplete_reason,
        }
    summary = _summary(findings, remediations, gate, execution_status)
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    finished = datetime.now(timezone.utc)
    scan_report = {
        "scanId": scan_id,
        "status": execution_status,
        "executionStatus": execution_status,
        "securityGate": gate,
        "generator": {"name": "Vesper", "version": __version__},
        "startedAt": started.isoformat(),
        "finishedAt": finished.isoformat(),
        "scanners": scanner_results,
    }
    (output / "scan.json").write_text(json.dumps(scan_report, indent=2) + "\n", encoding="utf-8")
    _print_summary(project.technologies, summary, remediations, scanner_results)
    if execution_status != "completed":
        return EXIT_RUNNER_FAILED, scan_report
    return (EXIT_GATE_FAILED if gate["status"] == "failed" else 0), scan_report


def _summary(
    findings: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
    gate: dict[str, Any],
    execution_status: str,
) -> dict[str, Any]:
    severities = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    categories = {key: 0 for key in ("sast", "dependency", "secret", "iac", "container")}
    category_severity = {category: dict.fromkeys(severities, 0) for category in categories}
    for finding in findings:
        severities[finding["severity"]] += 1
        categories[finding["category"]] += 1
        category_severity[finding["category"]][finding["severity"]] += 1
    priorities = {priority: 0 for priority in PRIORITY_ORDER}
    for remediation in remediations:
        priorities[remediation["priority"]] += 1
    return {
        "generator": {"name": "Vesper", "version": __version__},
        "status": execution_status,
        "total": len(findings),
        "severity": severities,
        "categories": categories,
        "categorySeverity": category_severity,
        "findings": {"total": len(findings), "severity": severities, "categories": categories},
        "remediations": {"total": len(remediations), "priority": priorities},
        "gate": gate,
    }


def _print_summary(
    technologies: list[str],
    summary: dict[str, Any],
    remediations: list[dict[str, Any]],
    scanner_results: list[dict[str, Any]],
) -> None:
    print("\nVesper Security Scan", flush=True)
    print(f"Status        {summary['status'].upper()}", flush=True)
    print(f"Technologies  {', '.join(technologies) if technologies else 'Unknown'}", flush=True)
    print(f"Findings      {summary['total']}", flush=True)
    print(f"Remediations  {len(remediations)}", flush=True)
    print("\nSeverity", flush=True)
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        print(f"  {severity.title():<10} {summary['severity'][severity]}", flush=True)

    gate = summary["gate"]
    print("\nVesper Security Gate", flush=True)
    print(f"  {gate['status'].upper()}", flush=True)
    if gate["status"] == "failed":
        print(f"  {gate['reason']}", flush=True)
        print(f"  Blocking findings: {gate['blockingFindings']}", flush=True)
        print(f"  Blocking remediations: {gate['blockingRemediations']}", flush=True)

    priority_remediations = [item for item in remediations if item["priority"] in {"p0", "p1", "p2"}]
    if priority_remediations:
        print("\nPriority Remediations", flush=True)
        for remediation in priority_remediations[:8]:
            print(f"  [{remediation['priority'].upper()}] {remediation['title']}", flush=True)
            print(f"       {remediation['summary']}", flush=True)
            if remediation["findingCount"] > 1:
                print(f"       Resolves {remediation['findingCount']} findings", flush=True)

    print("\nScanner Coverage", flush=True)
    for result in scanner_results:
        status = result["status"].replace("_", " ")
        reason = result.get("reason")
        details = f": {reason}" if reason else f" ({result['durationMs'] / 1000:.1f}s)"
        print(f"  {result['name']:<14} {status}{details}", flush=True)
    print("\nReports: findings.json, remediations.json, summary.json, raw/", flush=True)


def _category_severity_count(category: str, severity: str, summary: dict[str, Any]) -> int:
    return summary["categorySeverity"].get(category, {}).get(severity, 0)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _validate_config(config: dict[str, Any]) -> None:
    if not isinstance(config, dict) or not isinstance(config.get("policy"), dict):
        raise ConfigurationError("Configuration must contain a policy mapping")
    policy = config["policy"]
    fail_on = policy.get("failOn", [])
    if not isinstance(fail_on, list) or any(value not in {"critical", "high", "medium", "low", "info", "unknown"} for value in fail_on):
        raise ConfigurationError("policy.failOn must be a list of normalized severities")
    if not isinstance(policy.get("failOnSecrets", False), bool):
        raise ConfigurationError("policy.failOnSecrets must be a boolean")
    max_high = policy.get("maxHigh")
    if max_high is not None and (not isinstance(max_high, int) or max_high < 0):
        raise ConfigurationError("policy.maxHigh must be a non-negative integer or null")
    timeouts = config.get("timeouts", {})
    for name, value in timeouts.items():
        if not isinstance(value, int) or value < 1 or value > 3600:
            raise ConfigurationError(f"timeouts.{name} must be an integer from 1 to 3600")


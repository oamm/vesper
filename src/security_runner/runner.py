import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from security_runner.baseline import (
    BaselineError,
    compare_findings,
    validate_baseline,
    validate_comparison,
)
from security_runner.detection import detect_project
from security_runner.models import ScannerContext
from security_runner.normalization import SEVERITY_WEIGHT, deduplicate
from security_runner.policy import evaluate
from security_runner.remediations import PRIORITY_BY_SEVERITY, PRIORITY_ORDER, build_remediations
from security_runner.components import ComponentError, component_summary, validate_component_inventory
from security_runner.scanners import GrypeScanner, OsvScanner, SastScanner, SyftScanner, TrivyScanner
from security_runner import __version__

EXIT_GATE_FAILED = 1
EXIT_RUNNER_FAILED = 2
EXIT_CONFIG_ERROR = 3
EXIT_INTERNAL_ERROR = 4

SCANNER_CAPABILITIES = {
    "trivy": ("dependency", "secret", "container", "iac"),
    "osv-scanner": ("dependency",),
    "semgrep": ("sast",),
    "syft": (),
    "grype": ("dependency",),
}


class ConfigurationError(Exception):
    pass


class ReportConsistencyError(Exception):
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


def run_scan(
    workspace: Path,
    output: Path,
    config: dict[str, Any],
    scanner_instances: list[Any] | None = None,
    baseline: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    if baseline is not None:
        validate_baseline(baseline)
    workspace = workspace.resolve()
    output = output.resolve()
    if not workspace.is_dir():
        raise RuntimeError(f"Workspace does not exist: {workspace}")
    output.mkdir(parents=True, exist_ok=True)
    raw_dir = output / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    started_at_text = os.environ.get("SECURITY_SCAN_STARTED_AT")
    if started_at_text is None:
        started_at = datetime.now(timezone.utc)
        started_at_text = started_at.isoformat()
    else:
        started_at = datetime.fromisoformat(started_at_text.replace("Z", "+00:00"))
        if started_at.tzinfo is None:
            raise ValueError("SECURITY_SCAN_STARTED_AT must include a timezone.")
        started_at = started_at.astimezone(timezone.utc)
    scan_id = os.environ.get("SECURITY_SCAN_ID") or str(uuid.uuid4())
    output_exclusion = os.environ.get("SECURITY_SCAN_OUTPUT_RELATIVE_PATH")
    exclude_paths = [output_exclusion] if output_exclusion else []
    baseline_exclusion = os.environ.get("SECURITY_SCAN_BASELINE_RELATIVE_PATH")
    exclude_files = [baseline_exclusion.replace("\\", "/")] if baseline_exclusion else []

    print(f"[runner] Scan {scan_id} started at {started_at_text}", flush=True)
    print("[runner] Detecting project...", flush=True)
    project = detect_project(workspace, set(exclude_paths), set(exclude_files))
    print(f"[runner] Detected {', '.join(project.technologies) if project.technologies else 'no known technologies'}", flush=True)

    scanner_config = config.get("scanner", {})
    timeout_config = config.get("timeouts", {})
    scanners = scanner_instances or [
        TrivyScanner(scanner_config.get("trivy", {}).get("enabled", True)),
        OsvScanner(scanner_config.get("osv", {}).get("enabled", True)),
        SastScanner(scanner_config.get("sast", {}).get("enabled", True)),
    ]
    if "syft" in scanner_config:
        scanners.append(SyftScanner(scanner_config.get("syft", {}).get("enabled", False)))
    if "grype" in scanner_config:
        scanners.append(GrypeScanner(scanner_config.get("grype", {}).get("enabled", False)))
    all_findings: list[dict[str, Any]] = []
    scanner_results = []
    component_inventory = None
    syft_result = None
    for scanner in scanners:
        if scanner.name == "grype" and hasattr(scanner, "set_input_coverage"):
            scanner.set_input_coverage(component_inventory, syft_result.get("coverage") if syft_result else None)
        timeout = int(timeout_config.get(scanner.name, timeout_config.get("default", 300)))
        context = ScannerContext(workspace, output, raw_dir, project, timeout, exclude_paths, exclude_files)
        result, findings = scanner.execute(context)
        scanner_results.append(result.report())
        if scanner.name == "syft":
            syft_result = result.report()
        all_findings.extend(findings)
        if "components" in getattr(scanner, "extra_artifacts", {}):
            if component_inventory is not None:
                raise ReportConsistencyError("Multiple scanners produced component inventories.")
            component_inventory = scanner.extra_artifacts["components"]

    print("[runner] Normalizing results...", flush=True)
    findings = deduplicate(all_findings)
    remediations = build_remediations(findings)
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
    finished = datetime.now(timezone.utc)
    duration_ms = max(0, int((finished - started_at).total_seconds() * 1000))
    comparison = None
    if baseline is not None:
        comparison_scan = {
            "executionStatus": execution_status,
            "scanId": scan_id,
            "startedAt": started_at_text,
            "scanners": scanner_results,
        }
        comparison = compare_findings(baseline, findings, remediations, comparison_scan, project.report())
        if execution_status == "completed":
            gate = _apply_baseline_gate(gate, findings, remediations, comparison, config)
        else:
            gate = {**gate, "baselineDelta": _baseline_delta(comparison, remediations, config)}
    summary = _summary(findings, remediations, gate, execution_status, scanner_results, project, component_inventory)
    if comparison is not None:
        summary["baselineComparison"] = {
            "baselineId": comparison["baseline"]["baselineId"],
            "schemaVersion": comparison["schemaVersion"],
        }
    report_schemas = {"project": 2, "scan": 2, "findings": 2, "remediations": 2, "summary": 2}
    if component_inventory is not None:
        report_schemas["components"] = 1
    if comparison is not None:
        report_schemas["comparison"] = comparison["schemaVersion"]
    scan_report = {
        "schemaVersion": 2,
        "reportSchemas": report_schemas,
        "scanId": scan_id,
        "startedAt": started_at_text,
        "finishedAt": finished.isoformat(),
        "durationMs": duration_ms,
        "status": execution_status,
        "executionStatus": execution_status,
        "securityGate": gate,
        "generator": {"name": "Vesper", "version": __version__},
        "scanners": scanner_results,
    }
    if comparison is not None:
        scan_report["baselineId"] = comparison["baseline"]["baselineId"]
    project_report = project.report()
    if comparison is not None:
        validate_comparison(comparison, baseline, findings, scan_report)
    _validate_report_consistency(project_report, findings, remediations, summary, scan_report, comparison, component_inventory)
    (output / "project.json").write_text(json.dumps(project_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "findings.json").write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "remediations.json").write_text(json.dumps(remediations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "scan.json").write_text(json.dumps(scan_report, indent=2) + "\n", encoding="utf-8")
    if component_inventory is not None:
        (output / "components.json").write_text(json.dumps(component_inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if comparison is not None:
        (output / "comparison.json").write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _print_summary(project.technologies, summary, remediations, scanner_results)
    if execution_status != "completed":
        return EXIT_RUNNER_FAILED, scan_report
    return (EXIT_GATE_FAILED if gate["status"] == "failed" else 0), scan_report


def _summary(
    findings: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
    gate: dict[str, Any],
    execution_status: str,
    scanner_results: list[dict[str, Any]],
    project: Any,
    component_inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    severities = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    categories = {key: 0 for key in ("sast", "dependency", "secret", "iac", "container")}
    for finding in findings:
        severities[finding["severity"]] += 1
        categories[finding["category"]] += 1
    priorities = {priority: 0 for priority in PRIORITY_ORDER}
    for remediation in remediations:
        priorities[remediation["priority"]] += 1
    coverage_by_scanner = {
        result["name"]: {
            "status": result["status"],
            "findingCount": result.get("findingCount", 0),
            "assessment": (result.get("coverage") or {}).get("assessment", "unknown"),
            "reasonCode": result.get("reasonCode"),
            "reason": result.get("reason"),
            "targets": _coverage_target_counts(result.get("coverage") or {}),
            "metrics": _compact_coverage_metrics(result.get("coverage") or {}),
        }
        for result in scanner_results
    }
    coverage_by_capability = _capability_coverage(scanner_results)
    coverage_warnings = _coverage_warnings(scanner_results, project)
    summary = {
        "schemaVersion": 2,
        "generator": {"name": "Vesper", "version": __version__},
        "status": execution_status,
        "findings": {"total": len(findings), "severity": severities, "categories": categories},
        "remediations": {"total": len(remediations), "priority": priorities},
        "coverage": {"scanners": coverage_by_scanner, "capabilities": coverage_by_capability, "warnings": coverage_warnings},
        "gate": gate,
    }
    if component_inventory is not None:
        summary["components"] = component_summary(component_inventory)
    artifact_findings = [
        finding for finding in findings
        if any(evidence.get("scanner") == "grype" for evidence in finding.get("scannerEvidence", []))
    ]
    if artifact_findings:
        summary["artifactVulnerabilities"] = {
            "findings": len(artifact_findings),
            "componentsAffected": len({
                (finding.get("package") or {}).get("componentId")
                for finding in artifact_findings
                if (finding.get("package") or {}).get("componentId")
            }),
        }
    return summary


def _apply_baseline_gate(
    absolute_gate: dict[str, Any],
    findings: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
    comparison: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    delta = _baseline_delta(comparison, remediations, config)
    baseline_policy = config.get("baseline", {})
    new_finding_ids = set(delta["blockingFindingIds"])
    blocking_ids = set(absolute_gate.get("blockingFindingIds", [])) | new_finding_ids
    reasons = []
    if absolute_gate.get("status") == "failed":
        reasons.append(absolute_gate.get("reason", "Absolute security policy failed"))
    if new_finding_ids:
        severities = sorted({
            record["severity"] for record in comparison["findings"]["new"]
            if record.get("findingId") in new_finding_ids
        })
        reasons.append(f"New findings at configured severities: {', '.join(severities)}")
    blocking_remediations = sum(
        1 for remediation in remediations
        if blocking_ids.intersection(remediation.get("affectedFindings", []))
    )
    return {
        **absolute_gate,
        "status": "failed" if reasons else "passed",
        "reason": "; ".join(reasons) or "Policy passed",
        "blockingFindings": len(blocking_ids),
        "blockingRemediations": blocking_remediations,
        "blockingFindingIds": sorted(blocking_ids),
        "baselineDelta": delta,
    }


def _baseline_delta(
    comparison: dict[str, Any],
    remediations: list[dict[str, Any]],
    config: dict[str, Any],
) -> dict[str, Any]:
    fail_on_new = set(config.get("baseline", {}).get("failOnNew", ["critical", "high"]))
    blockers = {
        record["findingId"] for record in comparison["findings"]["new"]
        if record.get("severity") in fail_on_new
    }
    return {
        "newFindings": len(comparison["findings"]["new"]),
        "failOnNew": sorted(fail_on_new),
        "blockingFindingIds": sorted(blockers),
    }


def _capability_coverage(scanner_results: list[dict[str, Any]]) -> dict[str, Any]:
    scanners_by_name = {result["name"]: result for result in scanner_results}
    capability_scanners: dict[str, list[str]] = {}
    for scanner, capabilities in SCANNER_CAPABILITIES.items():
        for capability in capabilities:
            capability_scanners.setdefault(capability, []).append(scanner)

    rank = {"not_applicable": 0, "complete": 1, "limited": 2, "partial": 3, "unknown": 4}
    capabilities = {}
    for capability, scanner_names in sorted(capability_scanners.items()):
        detectors = {}
        applicable_assessments = []
        for name in scanner_names:
            result = scanners_by_name.get(name)
            if result is None:
                continue
            coverage = result.get("coverage") or {}
            capability_evidence = (coverage.get("capabilities") or {}).get(capability, {})
            assessment = capability_evidence.get("assessment", coverage.get("assessment", "unknown"))
            detectors[name] = {"status": result["status"], "assessment": assessment}
            if capability_evidence.get("requested") is not None:
                detectors[name]["requested"] = capability_evidence["requested"]
            if result["status"] not in {"skipped", "not_applicable", "unsupported_manifest"}:
                applicable_assessments.append(assessment)
            elif result["status"] == "unsupported_manifest":
                applicable_assessments.append("partial")

        if not applicable_assessments:
            overall = "not_applicable"
        else:
            overall = max(applicable_assessments, key=lambda value: rank.get(value, rank["unknown"]))
        capabilities[capability] = {"assessment": overall, "detectors": detectors}
    return capabilities


def _coverage_warnings(scanner_results: list[dict[str, Any]], project: Any) -> list[dict[str, Any]]:
    warnings = []
    for result in scanner_results:
        coverage = result.get("coverage") or {}
        assessment = coverage.get("assessment", "unknown")
        if result["status"] == "unsupported_manifest":
            unsupported_count = coverage.get("unsupportedInputCount") or (
                coverage.get("unsupportedManifestCount", 0) + coverage.get("unsupportedProjectCount", 0)
            )
            warnings.append({
                "code": result.get("reasonCode") or "unsupported_manifest",
                "scanner": result["name"],
                "message": f"{unsupported_count} dependency input(s) lack supported scanner coverage; see project.json.",
                "artifactCount": unsupported_count,
                "detailsLocation": "project.json",
                "executionLocation": "scan.json",
            })
        elif result["status"] == "not_applicable" and coverage.get("candidateArtifacts"):
            warnings.append({
                "code": result.get("reasonCode") or "limited_coverage",
                "scanner": result["name"],
                "message": result.get("reason") or "Candidate artifacts were detected but not analyzed.",
                "artifacts": coverage["candidateArtifacts"],
            })
        elif assessment in {"partial", "limited"}:
            unsupported_count = coverage.get("unsupportedInputCount") or (
                coverage.get("unsupportedManifestCount", 0) + coverage.get("unsupportedProjectCount", 0)
            )
            details = (
                f"{unsupported_count} unsupported dependency input(s); see project.json for details."
                if unsupported_count else ""
            )
            if result["name"] == "semgrep":
                partials = []
                if coverage.get("filesSkipped"):
                    partials.append(f"{coverage['filesSkipped']} path(s) skipped")
                if coverage.get("parseErrors"):
                    partials.append(f"{coverage['parseErrors']} parse error(s)")
                if partials:
                    details = "; ".join(partials) + "."
            warnings.append({
                "code": f"{result['name']}_{assessment}_coverage",
                "scanner": result["name"],
                "message": details or result.get("reason") or f"{result['name']} reported {assessment} coverage.",
                **({
                    "artifactCount": unsupported_count,
                    "detailsLocation": "project.json",
                    "executionLocation": "scan.json",
                } if unsupported_count else {}),
            })
        elif assessment == "unknown" and result["status"] in {"clean", "completed_with_findings"}:
            warnings.append({
                "code": f"{result['name']}_coverage_unknown",
                "scanner": result["name"],
                "message": f"{result['name']} completed, but its output does not expose enough metrics to measure coverage.",
            })

    if project.exclusions:
        warnings.append({
            "code": "project_path_excluded",
            "excludedPathCount": len(project.exclusions),
            "message": "Generated, transient, output, or explicitly excluded paths were omitted; see project.json for the exact list.",
        })
    return sorted(warnings, key=lambda item: (item.get("scanner", ""), item.get("code", ""), item.get("path", "")))


def _coverage_target_counts(coverage: dict[str, Any]) -> dict[str, int]:
    counts = coverage.get("targetCounts")
    if isinstance(counts, dict) and all(isinstance(value, int) and not isinstance(value, bool) for value in counts.values()):
        return dict(sorted(counts.items()))
    return {}


def _compact_coverage_metrics(coverage: dict[str, Any]) -> dict[str, Any]:
    detail_keys = {
        "assessment", "filesDiscovered", "filesAnalyzed", "filesSkipped", "sourceFilesDiscovered",
        "sourceFilesAnalyzed", "sourceFilesSkipped", "csharpFilesDiscovered", "csharpFilesAnalyzed",
        "pathsReportedScanned", "pathsReportedSkipped", "rulesLoaded", "rulesSkipped", "parseErrors",
        "errors", "ruleLoadStatus", "rulesetsConfigured", "resultSourcesWithFindings",
    }
    return {
        key: value for key, value in coverage.items()
        if key in detail_keys and (value is None or isinstance(value, (str, int, float, bool)))
    }


def _validate_report_consistency(
    project: dict[str, Any],
    findings: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
    summary: dict[str, Any],
    scan: dict[str, Any],
    comparison: dict[str, Any] | None = None,
    component_inventory: dict[str, Any] | None = None,
) -> None:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ReportConsistencyError(message)

    finding_ids = [finding.get("id") for finding in findings]
    finding_id_set = set(finding_ids)
    require(None not in finding_id_set and len(finding_ids) == len(finding_id_set), "Finding IDs must be present and unique.")
    require(project.get("schemaVersion") == 2, "Unsupported project report schema version.")
    require(project.get("artifactCount") == len(project.get("artifacts", [])), "Project artifact count does not match artifact inventory.")
    require(sum(project.get("artifactSummary", {}).values()) == project.get("artifactCount"), "Project artifact summary does not match artifact inventory.")
    require(project.get("sourceFileCount", 0) <= project.get("fileCount", 0), "Project source count exceeds its file count.")
    require(summary.get("schemaVersion") == 2 and scan.get("schemaVersion") == 2, "Unsupported summary or scan report schema version.")
    expected_schemas = {"project": 2, "scan": 2, "findings": 2, "remediations": 2, "summary": 2}
    if component_inventory is not None:
        expected_schemas["components"] = 1
    if comparison is not None:
        expected_schemas["comparison"] = 1
    require(scan.get("reportSchemas") == expected_schemas, "Scan report schema manifest is inconsistent.")
    if comparison is None:
        require("baselineComparison" not in summary and "baselineId" not in scan, "Baseline metadata exists without a comparison report.")
    else:
        require(
            summary.get("baselineComparison") == {
                "baselineId": comparison.get("baseline", {}).get("baselineId"),
                "schemaVersion": comparison.get("schemaVersion"),
            },
            "Summary baseline metadata is inconsistent.",
        )
        require(scan.get("baselineId") == comparison.get("baseline", {}).get("baselineId"), "Scan baseline ID is inconsistent.")
    require(summary.get("status") == scan.get("executionStatus"), "Scan and summary execution statuses disagree.")
    require(summary.get("gate") == scan.get("securityGate"), "Scan and summary gate reports disagree.")
    require(scan.get("executionStatus") in {"completed", "incomplete"}, "Scan has an unsupported execution status.")
    require((scan.get("executionStatus") == "incomplete") == (summary.get("gate", {}).get("status") == "indeterminate"), "Incomplete scans must have an indeterminate gate.")
    require(all(finding.get("schemaVersion") == 2 for finding in findings), "Finding schema markers are inconsistent.")
    require(all(remediation.get("schemaVersion") == 2 for remediation in remediations), "Remediation schema markers are inconsistent.")
    if component_inventory is None:
        require("components" not in summary, "Component summary exists without a component inventory.")
    else:
        try:
            validate_component_inventory(component_inventory)
            require(summary.get("components") == component_summary(component_inventory), "Component summary is inconsistent.")
        except ComponentError as exc:
            raise ReportConsistencyError(str(exc)) from exc
    component_ids = {
        component.get("id") for component in (component_inventory or {}).get("components", [])
        if isinstance(component, dict)
    }
    for finding in findings:
        if any(evidence.get("scanner") == "grype" for evidence in finding.get("scannerEvidence", [])):
            component_id = (finding.get("package") or {}).get("componentId")
            require(component_id in component_ids, "Grype finding references a missing component.")
    artifact_findings = [
        finding for finding in findings
        if any(evidence.get("scanner") == "grype" for evidence in finding.get("scannerEvidence", []))
    ]
    if artifact_findings:
        require(
            summary.get("artifactVulnerabilities", {}).get("findings") == len(artifact_findings),
            "Artifact vulnerability summary count is inconsistent.",
        )

    severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    category_counts = {key: 0 for key in ("sast", "dependency", "secret", "iac", "container")}
    for finding in findings:
        require(finding.get("severity") in severity_counts, "Finding has an unsupported severity.")
        require(finding.get("category") in category_counts, "Finding has an unsupported category.")
        severity_counts[finding["severity"]] += 1
        category_counts[finding["category"]] += 1

    require(summary.get("findings", {}).get("total") == len(findings), "Canonical finding total is inconsistent.")
    require(summary.get("findings", {}).get("severity") == severity_counts, "Canonical severity counts are inconsistent.")
    require(summary.get("findings", {}).get("categories") == category_counts, "Canonical category counts are inconsistent.")
    require(sum(summary.get("findings", {}).get("categories", {}).values()) == len(findings), "Category total does not match findings.")
    require(sum(summary.get("findings", {}).get("severity", {}).values()) == len(findings), "Severity total does not match findings.")

    for remediation in remediations:
        affected = remediation.get("affectedFindings", [])
        require(len(affected) == remediation.get("findingCount"), "Remediation findingCount does not match affectedFindings.")
        require(set(affected) <= finding_id_set, "Remediation references a missing finding.")
        referenced = [finding for finding in findings if finding.get("id") in set(affected)]
        expected_files = sorted({finding["location"]["file"] for finding in referenced if finding.get("location", {}).get("file")})
        require(remediation.get("affectedFiles", []) == expected_files, "Remediation affectedFiles do not match referenced finding locations.")
        expected_identifiers = sorted({
            identifier
            for finding in referenced
            for identifier in ((finding.get("security") or {}).get("identifiers") or (finding.get("security") or {}).get("cve", []))
        })
        require(remediation.get("securityIdentifiers", []) == expected_identifiers, "Remediation security identifiers do not match referenced findings.")
        if referenced:
            highest = max((finding["severity"] for finding in referenced), key=lambda value: SEVERITY_WEIGHT[value])
            require(remediation.get("priority") == PRIORITY_BY_SEVERITY[highest], "Remediation priority does not match the documented severity policy.")
            require(f"severity:{highest}" in remediation.get("priorityReasons", []), "Remediation priority rationale omits its severity basis.")
        recommended = (remediation.get("package") or {}).get("recommendedVersion")
        require(("fixed_version_available" in remediation.get("priorityReasons", [])) == bool(recommended), "Remediation fixed-version rationale is inconsistent.")

    priorities = {key: 0 for key in PRIORITY_ORDER}
    for remediation in remediations:
        require(remediation.get("priority") in priorities, "Remediation has an unsupported priority.")
        priorities[remediation["priority"]] += 1
    require(summary.get("remediations", {}).get("total") == len(remediations), "Remediation total is inconsistent.")
    require(summary.get("remediations", {}).get("priority") == priorities, "Remediation priority counts are inconsistent.")

    gate = summary.get("gate", {})
    blocking_ids = gate.get("blockingFindingIds", [])
    require(set(blocking_ids) <= finding_id_set, "Gate references a missing blocking finding.")
    require(gate.get("blockingFindings") == len(set(blocking_ids)), "Gate blocking finding count is inconsistent.")
    expected_blocking_remediations = sum(
        1 for remediation in remediations if set(remediation.get("affectedFindings", [])) & set(blocking_ids)
    )
    require(gate.get("blockingRemediations") == expected_blocking_remediations, "Gate blocking remediation count is inconsistent.")
    if comparison is not None:
        delta = gate.get("baselineDelta")
        new_records = comparison.get("findings", {}).get("new", [])
        new_ids = {record.get("findingId") for record in new_records}
        require(isinstance(delta, dict), "Baseline-aware gate metadata is missing.")
        require(delta.get("newFindings") == len(new_records), "Baseline gate new-finding count is inconsistent.")
        fail_on_new = delta.get("failOnNew")
        require(
            isinstance(fail_on_new, list)
            and all(severity in severity_counts for severity in fail_on_new),
            "Baseline gate severity policy is malformed.",
        )
        expected_delta_blockers = {
            record["findingId"] for record in new_records if record.get("severity") in fail_on_new
        }
        require(
            set(delta.get("blockingFindingIds", [])) == expected_delta_blockers
            and set(delta.get("blockingFindingIds", [])) <= new_ids,
            "Baseline gate blockers do not match configured new-finding severities.",
        )

    scanner_results = {result["name"]: result for result in scan.get("scanners", [])}
    coverage_scanners = summary.get("coverage", {}).get("scanners", {})
    for name, result in scanner_results.items():
        require(coverage_scanners.get(name, {}).get("status") == result.get("status"), "Scanner coverage status disagrees with scan metadata.")
        provenance_count = sum(
            1 for finding in findings
            if any(source.get("scanner") == name for source in finding.get("scannerEvidence", []))
        )
        require(provenance_count <= result.get("findingCount", 0), "Normalized scanner provenance exceeds the native finding count.")


def _print_summary(
    technologies: list[str],
    summary: dict[str, Any],
    remediations: list[dict[str, Any]],
    scanner_results: list[dict[str, Any]],
) -> None:
    finding_summary = summary["findings"]
    print("\nVesper Security Scan", flush=True)
    print(f"Status        {summary['status'].upper()}", flush=True)
    print(f"Technologies  {', '.join(technologies) if technologies else 'Unknown'}", flush=True)
    print(f"Findings      {finding_summary['total']}", flush=True)
    print(f"Remediations  {len(remediations)}", flush=True)
    print("\nSeverity", flush=True)
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        print(f"  {severity.title():<10} {finding_summary['severity'][severity]}", flush=True)

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
        assessment = (result.get("coverage") or {}).get("assessment", "unknown")
        details = f": {reason}" if reason else f" ({result['durationMs'] / 1000:.1f}s)"
        if status not in {"skipped", "not applicable", "unsupported manifest"}:
            details = f"{details[:-1]}; coverage {assessment})" if details.endswith(")") else f"{details} (coverage {assessment})"
        print(f"  {result['name']:<14} {status}{details}", flush=True)
    warnings = summary.get("coverage", {}).get("warnings", [])
    if warnings:
        print("\nCoverage Warnings", flush=True)
        for warning in warnings:
            print(f"  [{warning['code']}] {warning.get('message') or warning.get('reason') or warning.get('path')}", flush=True)
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
    baseline = config.get("baseline", {})
    if not isinstance(baseline, dict):
        raise ConfigurationError("baseline must be a mapping")
    fail_on_new = baseline.get("failOnNew", ["critical", "high"])
    if not isinstance(fail_on_new, list) or any(value not in {"critical", "high", "medium", "low", "info", "unknown"} for value in fail_on_new):
        raise ConfigurationError("baseline.failOnNew must be a list of normalized severities")
    timeouts = config.get("timeouts", {})
    for name, value in timeouts.items():
        if not isinstance(value, int) or value < 1 or value > 3600:
            raise ConfigurationError(f"timeouts.{name} must be an integer from 1 to 3600")


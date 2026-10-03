import hashlib
import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

BASELINE_SCHEMA_VERSION = 1
COMPARISON_SCHEMA_VERSION = 1
IDENTITY_VERSION = 1
STATES = ("new", "existing", "changed", "resolved", "unverified")
CAPABILITY_BY_CATEGORY = {
    "dependency": "dependency",
    "sast": "sast",
    "secret": "secret",
    "container": "container",
    "iac": "iac",
    "api_behavior": "api_behavior",
}
SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
SCANNERS_BY_CAPABILITY = {
    "dependency": {"osv-scanner", "trivy", "grype"},
    "sast": {"semgrep"},
    "secret": {"trivy", "gitleaks"},
    "container": {"trivy"},
    "iac": {"trivy"},
    "api_behavior": {"api-execution"},
}


class BaselineError(ValueError):
    pass


def normalize_target(value: Any, workspace_root: str | None = None) -> str:
    target = str(value or "").replace("\\", "/")
    if not target:
        raise BaselineError("A finding has no project-relative target.")

    if workspace_root:
        root = workspace_root.replace("\\", "/").rstrip("/")
        prefix = root + "/"
        if target.casefold().startswith(prefix.casefold()):
            target = target[len(prefix):]
        elif target.casefold() == root.casefold():
            target = ""

    if target == "/workspace":
        target = ""
    elif target.startswith("/workspace/"):
        target = target[len("/workspace/"):]
    elif target.startswith("/") or re.match(r"^[A-Za-z]:/", target):
        raise BaselineError("Finding target must be project-relative, not an absolute host path.")

    while target.startswith("./"):
        target = target[2:]
    segments = [segment for segment in target.split("/") if segment not in {"", "."}]
    if not segments or ".." in segments:
        raise BaselineError("Finding target is empty or escapes the project root.")
    return "/".join(segments)


def create_baseline(scan_directory: Path, output_path: Path) -> dict[str, Any]:
    artifacts = _load_scan_artifacts(scan_directory)
    scan = artifacts["scan"]
    if scan.get("executionStatus") != "completed":
        raise BaselineError("A baseline can only be created from a completed scan.")

    remediation_by_finding = _remediations_by_finding(artifacts["remediations"])
    try:
        baseline_findings = [
            _baseline_finding(finding, remediation_by_finding.get(finding["id"]))
            for finding in artifacts["findings"]
        ]
    except (AttributeError, KeyError, TypeError) as exc:
        raise BaselineError("Finding report is malformed and cannot provide stable baseline identity.") from exc
    _require_unique_identities(baseline_findings, "baseline")
    baseline: dict[str, Any] = {
        "schemaVersion": BASELINE_SCHEMA_VERSION,
        "createdAt": scan["startedAt"],
        "sourceScan": {"scanId": scan["scanId"], "startedAt": scan["startedAt"]},
        "generator": scan.get("generator", {"name": "Vesper", "version": "unknown"}),
        "coverage": _coverage_snapshot(scan),
        "findings": sorted(baseline_findings, key=_record_sort_key),
    }
    baseline["baselineId"] = _baseline_id(baseline)
    output_path = Path(output_path)
    protected_reports = {Path(scan_directory).resolve() / f"{name}.json" for name in ("project", "scan", "findings", "remediations", "summary")}
    if output_path.resolve() in protected_reports:
        raise BaselineError("Baseline output cannot replace a source scan report.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    try:
        temporary.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output_path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    return baseline


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        baseline = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Unable to read baseline: {exc}") from exc
    return validate_baseline(baseline)


def validate_baseline(baseline: Any) -> dict[str, Any]:
    if not isinstance(baseline, dict) or baseline.get("schemaVersion") != BASELINE_SCHEMA_VERSION:
        raise BaselineError("Unsupported or malformed baseline schema.")
    baseline_id = baseline.get("baselineId")
    if not isinstance(baseline_id, str) or not re.fullmatch(r"baseline-[0-9a-f]{64}", baseline_id):
        raise BaselineError("Baseline ID is missing or malformed.")
    source_scan = baseline.get("sourceScan")
    if not isinstance(source_scan, dict) or not all(isinstance(source_scan.get(key), str) and source_scan[key] for key in ("scanId", "startedAt")):
        raise BaselineError("Baseline source scan metadata is missing.")
    try:
        uuid.UUID(source_scan["scanId"])
    except (ValueError, AttributeError) as exc:
        raise BaselineError("Baseline source scan ID is invalid.") from exc
    if not _is_timestamp(source_scan["startedAt"]) or baseline.get("createdAt") != source_scan["startedAt"]:
        raise BaselineError("Baseline creation timestamp does not match its source scan.")
    if not isinstance(baseline.get("generator"), dict) or baseline["generator"].get("name") != "Vesper":
        raise BaselineError("Baseline generator metadata is missing or unsupported.")
    if (
        not isinstance(baseline.get("coverage"), dict)
        or not isinstance(baseline["coverage"].get("scanners"), dict)
        or not isinstance(baseline["coverage"].get("capabilities"), dict)
        or not isinstance(baseline.get("findings"), list)
    ):
        raise BaselineError("Baseline coverage and findings are required.")

    identities = set()
    finding_ids = set()
    fingerprints = set()
    for finding in baseline["findings"]:
        if not isinstance(finding, dict):
            raise BaselineError("Baseline finding entries must be objects.")
        if finding.get("identityVersion") != IDENTITY_VERSION:
            raise BaselineError("Baseline finding identity version is unsupported.")
        if finding.get("fingerprintVersion") != 2 or not isinstance(finding.get("fingerprint"), str) or not re.fullmatch(r"[0-9a-f]{64}", finding["fingerprint"]):
            raise BaselineError("Baseline finding fingerprint metadata is invalid.")
        if not isinstance(finding.get("findingId"), str) or not finding["findingId"]:
            raise BaselineError("Baseline finding ID is missing.")
        if finding["findingId"] in finding_ids or finding["fingerprint"] in fingerprints:
            raise BaselineError("Baseline finding IDs or fingerprints are duplicated.")
        finding_ids.add(finding["findingId"])
        fingerprints.add(finding["fingerprint"])
        category = finding.get("category")
        if not isinstance(category, str) or category not in CAPABILITY_BY_CATEGORY or finding.get("capability") != CAPABILITY_BY_CATEGORY[category]:
            raise BaselineError("Baseline finding capability does not match its category.")
        try:
            target = normalize_target(finding.get("target"))
        except BaselineError as exc:
            raise BaselineError(f"Baseline finding target is invalid: {exc}") from exc
        if target != finding.get("target"):
            raise BaselineError("Baseline finding target is not normalized.")
        if not isinstance(finding.get("severity"), str) or finding.get("severity") not in SEVERITY_WEIGHT or not isinstance(finding.get("semanticState"), dict):
            raise BaselineError("Baseline finding semantic state is invalid.")
        identity = finding.get("identity")
        identity_data = finding.get("identityData")
        if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise BaselineError("Baseline finding identity is missing or malformed.")
        if (
            not isinstance(identity_data, dict)
            or identity_data.get("identityVersion") != IDENTITY_VERSION
            or identity_data.get("capability") != finding["capability"]
            or identity_data.get("category") != finding["category"]
            or (category != "api_behavior" and identity_data.get("target") != finding["target"])
            or hashlib.sha256(_canonical_json(identity_data).encode("utf-8")).hexdigest() != identity
        ):
            raise BaselineError("Baseline finding identity does not match its semantic identity data.")
        identity_candidates = finding.get("identityCandidates")
        if not isinstance(identity_candidates, list) or not identity_candidates or any(
            not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in identity_candidates
        ) or identity_candidates != sorted(set(identity_candidates)):
            raise BaselineError("Baseline finding identity candidates are malformed.")
        if finding["category"] == "dependency":
            identifiers = finding.get("identifiers")
            package = finding.get("package")
            if not isinstance(identifiers, list) or not identifiers or not isinstance(package, dict):
                raise BaselineError("Baseline dependency identifiers or package identity are missing.")
            identity_base = {
                "identityVersion": IDENTITY_VERSION,
                "capability": finding["capability"],
                "category": finding["category"],
                "target": finding["target"],
                "ecosystem": str(package.get("ecosystem") or "unknown").casefold(),
                "package": str(package.get("name") or "").casefold(),
            }
            expected_candidates = sorted({
                hashlib.sha256(_canonical_json({**identity_base, "vulnerability": str(identifier).strip().upper()}).encode("utf-8")).hexdigest()
                for identifier in identifiers if isinstance(identifier, str) and identifier.strip()
            })
            if identity_candidates != expected_candidates or identity_data.get("vulnerability") != _canonical_vulnerability(identifiers):
                raise BaselineError("Baseline dependency identity candidates do not match its identifiers.")
        elif category == "api_behavior":
            evidence = finding.get("behaviorEvidence")
            if (
                not isinstance(evidence, dict)
                or not isinstance(evidence.get("operation"), str)
                or not evidence["operation"]
                or evidence.get("behaviorType") not in {"unexpected_5xx", "response_schema_violation", "unexpected_status"}
                or not isinstance(evidence.get("expectedStatuses"), list)
            ):
                raise BaselineError("API behavioral identity evidence is missing or malformed.")
            if (
                identity_data.get("target") != finding["target"]
                or identity_data.get("operation") != evidence["operation"]
                or identity_data.get("behaviorType") != evidence["behaviorType"]
                or identity_data.get("expectedStatuses") != sorted(str(value) for value in evidence["expectedStatuses"])
            ):
                raise BaselineError("API behavioral identity does not match its evidence.")
        elif identity_candidates != [identity]:
            raise BaselineError("Non-dependency finding must have exactly one semantic identity candidate.")
        if identity in identities:
            raise BaselineError("Baseline contains duplicate finding identities.")
        identities.add(identity)
        if not isinstance(finding.get("detectors"), list) or any(not isinstance(item, str) for item in finding["detectors"]):
            raise BaselineError("Baseline finding detector provenance is malformed.")

    if _baseline_id(baseline) != baseline_id:
        raise BaselineError("Baseline content does not match its baseline ID.")
    return baseline


def compare_findings(
    baseline: dict[str, Any],
    current_findings: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
    scan: dict[str, Any],
    project: dict[str, Any],
    api_execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline = validate_baseline(baseline)
    remediation_by_finding = _remediations_by_finding(remediations)
    current_records = [
        _baseline_finding(finding, remediation_by_finding.get(finding["id"]))
        for finding in current_findings
    ]
    _require_unique_identities(current_records, "current scan")
    old_by_candidate = {
        candidate: finding
        for finding in baseline["findings"]
        for candidate in finding["identityCandidates"]
    }
    matched_current: dict[str, dict[str, Any]] = {}
    matched_old_ids: set[str] = set()
    for current in current_records:
        candidates = {old_by_candidate[item]["identity"]: old_by_candidate[item] for item in current["identityCandidates"] if item in old_by_candidate}
        if len(candidates) > 1:
            raise BaselineError("Current finding matches multiple baseline identities through aliases.")
        if candidates:
            old = next(iter(candidates.values()))
            if old["identity"] in matched_old_ids:
                raise BaselineError("Multiple current findings match one baseline identity.")
            matched_current[current["identity"]] = old
            matched_old_ids.add(old["identity"])
    current_scanners = scan.get("scanners", [])
    comparison_findings: dict[str, list[dict[str, Any]]] = {state: [] for state in STATES}

    for current_identity, old in matched_current.items():
        current = next(item for item in current_records if item["identity"] == current_identity)
        state = "existing" if old["semanticState"] == current["semanticState"] else "changed"
        record = {
            "state": state,
            "findingId": current["findingId"],
            "fingerprint": current["fingerprint"],
            "baselineFingerprint": old["fingerprint"],
            "severity": current["severity"],
            "category": current["category"],
            "target": current["target"],
            "detectorsAdded": sorted(set(current["detectors"]) - set(old["detectors"])),
            "detectorsRemoved": sorted(set(old["detectors"]) - set(current["detectors"])),
        }
        if state == "changed":
            record["baselineFinding"] = _baseline_display(old)
            record["semanticChanges"] = sorted(
                key for key in set(old["semanticState"]) | set(current["semanticState"])
                if old["semanticState"].get(key) != current["semanticState"].get(key)
            )
        comparison_findings[state].append(record)

    matched_current_ids = set(matched_current)
    for current in current_records:
        if current["identity"] in matched_current_ids:
            continue
        comparison_findings["new"].append({
            "state": "new",
            "findingId": current["findingId"],
            "fingerprint": current["fingerprint"],
            "severity": current["severity"],
            "category": current["category"],
            "target": current["target"],
        })

    matched_old_ids = {old["identity"] for old in matched_current.values()}
    for old in baseline["findings"]:
        if old["identity"] in matched_old_ids:
            continue
        reason_code, evidence = _resolution_evidence(old, current_scanners, project, api_execution)
        state = "resolved" if reason_code is None else "unverified"
        record = {
            "state": state,
            "baselineFingerprint": old["fingerprint"],
            "baselineFinding": _baseline_display(old),
        }
        if reason_code is not None:
            record["reasonCode"] = reason_code
        else:
            record["resolutionEvidence"] = evidence
        comparison_findings[state].append(record)

    for records in comparison_findings.values():
        records.sort(key=_comparison_sort_key)
    return {
        "schemaVersion": COMPARISON_SCHEMA_VERSION,
        "baseline": {
            "baselineId": baseline["baselineId"],
            "scanId": baseline["sourceScan"]["scanId"],
            "startedAt": baseline["sourceScan"]["startedAt"],
        },
        "current": {"scanId": scan["scanId"], "startedAt": scan["startedAt"]},
        "summary": {state: len(comparison_findings[state]) for state in STATES},
        "findings": comparison_findings,
    }


def validate_comparison(
    comparison: Any,
    baseline: dict[str, Any],
    findings: list[dict[str, Any]],
    scan: dict[str, Any],
) -> None:
    baseline = validate_baseline(baseline)
    if not isinstance(comparison, dict) or comparison.get("schemaVersion") != COMPARISON_SCHEMA_VERSION:
        raise BaselineError("Comparison schema is unsupported or malformed.")
    if comparison.get("baseline", {}).get("baselineId") != baseline["baselineId"]:
        raise BaselineError("Comparison baseline ID does not match the supplied baseline.")
    if comparison.get("current") != {"scanId": scan.get("scanId"), "startedAt": scan.get("startedAt")}:
        raise BaselineError("Comparison current scan metadata is inconsistent.")
    if comparison.get("baseline", {}).get("scanId") != baseline["sourceScan"]["scanId"]:
        raise BaselineError("Comparison source scan metadata is inconsistent.")
    groups = comparison.get("findings")
    summary = comparison.get("summary")
    if not isinstance(groups, dict) or not isinstance(summary, dict) or set(groups) != set(STATES) or set(summary) != set(STATES):
        raise BaselineError("Comparison state groups are incomplete.")

    current_ids = {finding.get("id") for finding in findings}
    baseline_fingerprints = {finding["fingerprint"] for finding in baseline["findings"]}
    baseline_by_fingerprint = {finding["fingerprint"]: finding for finding in baseline["findings"]}
    referenced_current: set[str] = set()
    referenced_baseline: set[str] = set()
    for state in STATES:
        records = groups[state]
        if not isinstance(records, list) or summary[state] != len(records):
            raise BaselineError(f"Comparison {state} count is inconsistent.")
        for record in records:
            if not isinstance(record, dict) or record.get("state") != state:
                raise BaselineError(f"Comparison {state} entry is malformed.")
            if state in {"new", "existing", "changed"}:
                finding_id = record.get("findingId")
                if finding_id not in current_ids or finding_id in referenced_current:
                    raise BaselineError("Comparison current finding reference is missing or duplicated.")
                referenced_current.add(finding_id)
            if state in {"existing", "changed"}:
                baseline_fingerprint = record.get("baselineFingerprint")
                if baseline_fingerprint not in baseline_fingerprints:
                    raise BaselineError("Comparison baseline finding reference is missing.")
                if baseline_fingerprint in referenced_baseline:
                    raise BaselineError("Comparison baseline finding appears in conflicting states.")
                referenced_baseline.add(baseline_fingerprint)
            if state in {"resolved", "unverified"}:
                baseline_fingerprint = record.get("baselineFingerprint")
                if baseline_fingerprint not in baseline_fingerprints or not isinstance(record.get("baselineFinding"), dict):
                    raise BaselineError("Comparison resolved/unverified baseline evidence is missing.")
                if baseline_fingerprint in referenced_baseline:
                    raise BaselineError("Comparison baseline finding appears in conflicting states.")
                referenced_baseline.add(baseline_fingerprint)
                if state == "unverified" and not isinstance(record.get("reasonCode"), str):
                    raise BaselineError("Unverified comparison entry has no reason code.")
                if state == "resolved" and baseline_by_fingerprint[baseline_fingerprint].get("category") == "api_behavior":
                    evidence = record.get("resolutionEvidence")
                    execution = scan.get("apiExecution") or {}
                    operation = (baseline_by_fingerprint[baseline_fingerprint].get("behaviorEvidence") or {}).get("operation")
                    operation_record = next(
                        (item for item in execution.get("operations", []) if isinstance(item, dict) and item.get("operation") == operation),
                        None,
                    )
                    required = {
                        "unexpected_5xx": "statusValidation",
                        "response_schema_violation": "responseSchemaValidation",
                        "unexpected_status": "statusValidation",
                    }.get((baseline_by_fingerprint[baseline_fingerprint].get("behaviorEvidence") or {}).get("behaviorType"))
                    if (
                        not isinstance(evidence, dict)
                        or evidence.get("scanner") != "api-execution"
                        or execution.get("activeTesting") is not True
                        or execution.get("status") == "failed"
                        or not isinstance(operation_record, dict)
                        or operation_record.get("state") != "exercised"
                        or not required
                        or (operation_record.get("validation") or {}).get(required) is not True
                    ):
                        raise BaselineError("API behavioral resolution lacks positive runtime coverage evidence.")
    if referenced_current != current_ids:
        raise BaselineError("Comparison does not classify every current finding exactly once.")
    if referenced_baseline != baseline_fingerprints:
        raise BaselineError("Comparison does not classify every baseline finding exactly once.")


def _load_scan_artifacts(scan_directory: Path) -> dict[str, Any]:
    scan_directory = Path(scan_directory)
    try:
        artifacts = {
            name: json.loads((scan_directory / f"{name}.json").read_text(encoding="utf-8"))
            for name in ("project", "scan", "findings", "remediations", "summary")
        }
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Scan report set is incomplete or corrupt: {exc}") from exc
    project, scan, findings, remediations, summary = (artifacts[name] for name in ("project", "scan", "findings", "remediations", "summary"))
    if not isinstance(project, dict) or project.get("schemaVersion") != 2:
        raise BaselineError("Unsupported project report schema; baseline creation requires schema v2.")
    project_artifacts = project.get("artifacts")
    artifact_summary = project.get("artifactSummary")
    if (
        not isinstance(project_artifacts, list)
        or not isinstance(artifact_summary, dict)
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in artifact_summary.values())
        or project.get("artifactCount") != len(project_artifacts)
        or sum(artifact_summary.values()) != project.get("artifactCount")
    ):
        raise BaselineError("Project report inventory is malformed or inconsistent.")
    required_schemas = {"project": 2, "scan": 2, "findings": 2, "remediations": 2, "summary": 2}
    if not isinstance(scan, dict) or scan.get("schemaVersion") != 2:
        raise BaselineError("Unsupported or corrupt scan report schema.")
    report_schemas = scan.get("reportSchemas")
    if not isinstance(report_schemas, dict) or any(report_schemas.get(key) != value for key, value in required_schemas.items()):
        raise BaselineError("Unsupported or corrupt scan report schema manifest.")
    if not isinstance(findings, list) or not isinstance(remediations, list):
        raise BaselineError("Findings and remediations reports must be arrays.")
    if not isinstance(summary, dict) or summary.get("schemaVersion") != 2:
        raise BaselineError("Unsupported or corrupt summary report schema.")
    summary_findings = summary.get("findings")
    if not isinstance(summary_findings, dict):
        raise BaselineError("Summary finding counts are missing or malformed.")
    scan_id = scan.get("scanId")
    started_at = scan.get("startedAt")
    try:
        uuid.UUID(scan_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise BaselineError("Scan identity is invalid.") from exc
    if not isinstance(started_at, str) or not _is_timestamp(started_at):
        raise BaselineError("Scan identity or timestamp is invalid.")
    if summary.get("status") != scan.get("executionStatus") or summary_findings.get("total") != len(findings):
        raise BaselineError("Scan, summary, and findings reports disagree.")
    if not isinstance(summary.get("gate"), dict) or not isinstance(scan.get("securityGate"), dict) or summary.get("gate") != scan.get("securityGate"):
        raise BaselineError("Scan and summary gate reports disagree.")
    if not isinstance(scan.get("scanners"), list):
        raise BaselineError("Scan scanner metadata is malformed.")
    finding_ids = set()
    severity_counts = {severity: 0 for severity in SEVERITY_WEIGHT}
    categories = set(CAPABILITY_BY_CATEGORY) - {"api_behavior"}
    if "api_behavior" in summary_findings.get("categories", {}) or any(
        isinstance(finding, dict) and finding.get("category") == "api_behavior" for finding in findings
    ):
        categories.add("api_behavior")
    category_counts = {category: 0 for category in categories}
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("schemaVersion") != 2:
            raise BaselineError("Finding report contains an unsupported entry.")
        if not isinstance(finding.get("id"), str) or not finding["id"] or finding["id"] in finding_ids:
            raise BaselineError("Finding IDs are missing or duplicated.")
        finding_ids.add(finding["id"])
        if finding.get("severity") not in severity_counts or finding.get("category") not in category_counts:
            raise BaselineError("Finding report contains an unsupported severity or category.")
        severity_counts[finding["severity"]] += 1
        category_counts[finding["category"]] += 1
        if finding.get("fingerprintVersion") != 2 or not isinstance(finding.get("fingerprint"), str) or not re.fullmatch(r"[0-9a-f]{64}", finding["fingerprint"]):
            raise BaselineError("Finding identity version is unsupported.")
    for remediation in remediations:
        affected = remediation.get("affectedFindings") if isinstance(remediation, dict) else None
        if not isinstance(affected, list) or any(not isinstance(item, str) for item in affected) or not set(affected) <= finding_ids:
            raise BaselineError("Remediation report references a missing finding.")
        if len(affected) != remediation.get("findingCount"):
            raise BaselineError("Remediation finding counts are inconsistent.")
    if summary_findings.get("severity") != severity_counts or summary_findings.get("categories") != category_counts:
        raise BaselineError("Summary finding counts do not match the findings report.")
    if scan.get("executionStatus") not in {"completed", "incomplete"}:
        raise BaselineError("Scan execution status is unsupported.")
    return artifacts


def _baseline_finding(finding: dict[str, Any], remediation: dict[str, Any] | None) -> dict[str, Any]:
    category = finding.get("category")
    capability = CAPABILITY_BY_CATEGORY.get(category)
    if capability is None:
        raise BaselineError(f"Unsupported finding category in baseline: {category!r}.")
    location = finding.get("location") or {}
    behavior_evidence = finding.get("behaviorEvidence") or {}
    raw_target = behavior_evidence.get("operation") if category == "api_behavior" else location.get("file")
    target = normalize_target(raw_target)
    package = finding.get("package") or {}
    security = finding.get("security") or {}
    identifiers = [str(value) for value in security.get("identifiers", []) if value]
    if not identifiers:
        identifiers = [str(value) for value in security.get("cve", []) if value]
    if category == "dependency":
        identifier = _canonical_vulnerability(identifiers)
        if not package.get("name"):
            raise BaselineError("Dependency finding has no package identity.")
        identity_base = {
            "identityVersion": IDENTITY_VERSION,
            "capability": capability,
            "category": category,
            "target": target,
            "ecosystem": str(package.get("ecosystem") or "unknown").casefold(),
            "package": str(package["name"]).casefold(),
        }
        identity_data_candidates = [
            {**identity_base, "vulnerability": value.strip().upper()}
            for value in sorted(set(identifiers), key=_vulnerability_sort_key)
        ]
        identity_data = {**identity_base, "vulnerability": identifier}
    else:
        scanner_evidence = finding.get("scannerEvidence") or []
        rule_ids = sorted({str(item.get("ruleId")) for item in scanner_evidence if item.get("ruleId")})
        rule_id = rule_ids[0] if rule_ids else str(finding.get("type") or "unknown")
        identity_data = {
            "identityVersion": IDENTITY_VERSION,
            "capability": capability,
            "category": category,
            "target": target,
            "rule": rule_id.casefold(),
            "line": location.get("line"),
        }
        identity_data_candidates = [identity_data]
    identity_candidate_pairs = [
        (hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest(), data)
        for data in identity_data_candidates
    ]
    identity_candidates = sorted({candidate for candidate, _ in identity_candidate_pairs})
    identity = hashlib.sha256(_canonical_json(identity_data).encode("utf-8")).hexdigest()
    detectors = sorted({str(item.get("scanner")) for item in finding.get("scannerEvidence", []) if item.get("scanner")})
    semantic_state = {
        "severity": finding.get("severity", "unknown"),
        "installedVersion": package.get("version"),
        "recommendedVersion": ((remediation or {}).get("package") or {}).get("recommendedVersion"),
    }
    if category == "api_behavior":
        evidence = behavior_evidence
        operation = str(evidence.get("operation") or location.get("operation") or "")
        behavior = str(evidence.get("behaviorType") or finding.get("type") or "")
        expected = sorted(str(value) for value in evidence.get("expectedStatuses", []) if value is not None)
        observed = sorted(str(value) for value in evidence.get("observedStatuses", []) if value is not None)
        target = operation
        identity_data = {
            "identityVersion": IDENTITY_VERSION,
            "capability": capability,
            "category": category,
            "target": operation,
            "operation": operation,
            "behaviorType": behavior,
            "expectedStatuses": expected,
        }
        identity_candidates = [hashlib.sha256(_canonical_json(identity_data).encode("utf-8")).hexdigest()]
        identity = identity_candidates[0]
        semantic_state = {
            "severity": finding.get("severity", "unknown"),
            "expectedStatuses": expected,
            "observedStatuses": observed,
        }
    elif category == "dependency":
        identity = hashlib.sha256(_canonical_json(identity_data).encode("utf-8")).hexdigest()
    else:
        identity = hashlib.sha256(_canonical_json(identity_data).encode("utf-8")).hexdigest()
    minimal_package = None
    if package:
        minimal_package = {
            "name": package.get("name"),
            "ecosystem": package.get("ecosystem"),
            "version": package.get("version"),
        }
    return {
        "findingId": finding["id"],
        "fingerprint": finding["fingerprint"],
        "fingerprintVersion": finding["fingerprintVersion"],
        "identityVersion": IDENTITY_VERSION,
        "identity": identity,
        "identityData": identity_data,
        "identityCandidates": identity_candidates,
        "capability": capability,
        "category": category,
        "target": target,
        "severity": finding.get("severity", "unknown"),
        "title": str(finding.get("title") or finding.get("type") or "Finding")[:240],
        "identifiers": sorted(set(identifiers)),
        "package": minimal_package,
        "semanticState": semantic_state,
        "detectors": detectors,
        **({"behaviorEvidence": {
            "operation": identity_data["operation"],
            "behaviorType": identity_data["behaviorType"],
            "expectedStatuses": identity_data["expectedStatuses"],
        }} if category == "api_behavior" else {}),
        **({"historical": True} if (finding.get("secretEvidence") or {}).get("scope") == "historical" else {}),
    }


def _resolution_evidence(
    finding: dict[str, Any],
    scanners: list[dict[str, Any]],
    project: dict[str, Any],
    api_execution: dict[str, Any] | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    capability = finding["capability"]
    target = finding["target"]
    relevant = [scanner for scanner in scanners if scanner.get("name") in SCANNERS_BY_CAPABILITY[capability]]
    if not relevant:
        return "capability_not_executed", None
    if capability == "api_behavior":
        if not isinstance(api_execution, dict) or api_execution.get("activeTesting") is not True:
            return "passive_scan", None
        if api_execution.get("status") == "failed":
            return "runtime_failed", None
        operation = (finding.get("behaviorEvidence") or {}).get("operation") or target
        record = next((item for item in api_execution.get("operations", []) if isinstance(item, dict) and item.get("operation") == operation), None)
        if record is None:
            return "missing_operation", None
        state = record.get("state")
        if state == "auth_limited":
            return "auth_limited", None
        if state in {"not_attempted", "unknown"}:
            return "operation_not_attempted", None
        if state in {"failed", "partial"}:
            return "runtime_failed", None
        if state != "exercised":
            return "operation_not_attempted", None
        behavior = (finding.get("behaviorEvidence") or {}).get("behaviorType")
        validation = record.get("validation") or {}
        required = {
            "unexpected_5xx": "statusValidation",
            "response_schema_violation": "responseSchemaValidation",
            "unexpected_status": "statusValidation",
        }.get(behavior)
        if not required or validation.get(required) is not True:
            return "validation_unavailable", None
        return None, {
            "scanner": "api-execution",
            "operation": operation,
            "state": state,
            "validation": {required: True},
        }
    if capability == "dependency":
        osv = next((scanner for scanner in relevant if scanner.get("name") == "osv-scanner"), None)
        if osv:
            coverage = osv.get("coverage") or {}
            targets = coverage.get("targets") or []
            target_record = next((item for item in targets if _safe_target(item.get("path")) == target), None)
            if target_record:
                if target_record.get("state") == "completed" and osv.get("status") in {"clean", "completed", "completed_with_findings"}:
                    return None, {"scanner": "osv-scanner", "target": target, "state": "completed"}
                if target_record.get("state") == "failed" or osv.get("status") in {"failed", "timeout"}:
                    return "scanner_failed", None
                return "target_not_covered", None
            unsupported = set(project.get("unsupportedDependencyManifests", [])) | set(project.get("unsupportedDependencyProjects", []))
            if target in unsupported:
                return "unsupported_target", None
            if osv.get("status") in {"failed", "timeout"}:
                return "scanner_failed", None
        if any(scanner.get("status") in {"failed", "timeout"} for scanner in relevant):
            return "scanner_failed", None
        if all(scanner.get("status") in {"skipped", "not_applicable", "unsupported_manifest"} for scanner in relevant):
            return "capability_not_executed", None
        if any(scanner.get("coverage", {}).get("assessment") == "unknown" for scanner in relevant if scanner.get("name") == "trivy"):
            return "coverage_unknown", None
        return "target_not_covered", None

    if capability == "secret" and finding.get("historical"):
        gitleaks = next((scanner for scanner in relevant if scanner.get("name") == "gitleaks"), None)
        if gitleaks is None or gitleaks.get("status") in {"failed", "timeout"}:
            return "scanner_failed" if gitleaks else "capability_not_executed", None
        if gitleaks.get("status") in {"not_applicable", "skipped", "unsupported_manifest"}:
            return "capability_not_executed", None
        coverage = gitleaks.get("coverage") or {}
        if coverage.get("repositoryHistory") == "shallow" or coverage.get("assessment") != "complete":
            return "coverage_unknown", None
        if coverage.get("repositoryHistory") != "complete":
            return "coverage_unknown", None
        return None, {"scanner": "gitleaks", "target": target, "state": "history_complete"}

    scanner_name = "semgrep" if capability == "sast" else "trivy"
    scanner = next((item for item in relevant if item.get("name") == scanner_name), None)
    if scanner is None:
        return "capability_not_executed", None
    if scanner.get("status") in {"failed", "timeout"}:
        return "scanner_failed", None
    if scanner.get("status") in {"not_applicable", "skipped", "unsupported_manifest"}:
        return "capability_not_executed", None
    coverage = scanner.get("coverage") or {}
    if capability == "sast":
        parse_errors = coverage.get("parseErrorFiles") or []
        if any(_safe_target(item.get("path")) == target for item in parse_errors):
            return "parse_error", None
        analyzed = {_safe_target(path) for path in coverage.get("analyzedFiles", [])}
        if target not in analyzed:
            return "target_not_covered", None
        if not isinstance(coverage.get("rulesLoaded"), int) or coverage.get("rulesLoaded", 0) <= 0 or coverage.get("rulesSkipped") != 0:
            return "coverage_unknown", None
        if coverage.get("assessment") != "complete" or coverage.get("errors") != 0:
            return "coverage_unknown", None
        return None, {"scanner": "semgrep", "target": target, "state": "analyzed", "rulesLoaded": coverage["rulesLoaded"]}
    capability_evidence = (coverage.get("capabilities") or {}).get(capability) or {}
    if capability_evidence.get("assessment") == "complete" and target in capability_evidence.get("coveredTargets", []):
        return None, {"scanner": "trivy", "target": target, "state": "covered"}
    if coverage.get("assessment") == "unknown" or capability_evidence.get("assessment") == "unknown":
        return "coverage_unknown", None
    if scanner.get("status") in {"not_applicable", "skipped", "unsupported_manifest"}:
        return "capability_not_executed", None
    return "target_not_covered", None


def _coverage_snapshot(scan: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for scanner in scan.get("scanners", []):
        coverage = scanner.get("coverage") or {}
        snapshot: dict[str, Any] = {
            "status": scanner.get("status"),
            "assessment": coverage.get("assessment", "unknown"),
        }
        if isinstance(coverage.get("targetCounts"), dict):
            snapshot["targetCounts"] = coverage["targetCounts"]
        if isinstance(coverage.get("targets"), list):
            snapshot["targets"] = [
                {"path": _safe_target(item.get("path")), "state": item.get("state")}
                for item in coverage["targets"] if isinstance(item, dict) and item.get("path")
            ]
        for key in ("analyzedFiles", "parseErrorFiles", "rulesLoaded", "rulesSkipped", "errors"):
            if key in coverage:
                if key == "parseErrorFiles":
                    snapshot[key] = [
                        {"path": _safe_target(item.get("path")), "type": item.get("type", "unknown")}
                        for item in coverage[key] if isinstance(item, dict)
                    ]
                else:
                    snapshot[key] = coverage[key]
        result[scanner.get("name", "unknown")] = snapshot
    capabilities = {}
    for scanner in scan.get("scanners", []):
        coverage = scanner.get("coverage") or {}
        for capability, evidence in (coverage.get("capabilities") or {}).items():
            capabilities.setdefault(capability, {})[scanner["name"]] = {
                key: evidence.get(key) for key in ("assessment", "requested", "coveredTargets") if key in evidence
            }
    return {"scanners": result, "capabilities": capabilities}


def _remediations_by_finding(remediations: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for remediation in remediations:
        for finding_id in remediation.get("affectedFindings", []):
            result[finding_id] = remediation
    return result


def _baseline_display(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        key: finding[key]
        for key in ("fingerprint", "title", "severity", "category", "capability", "target", "identifiers", "package", "semanticState", "behaviorEvidence", "historical")
        if key in finding
    }


def _canonical_vulnerability(identifiers: list[str]) -> str:
    normalized = sorted({value.strip().upper() for value in identifiers if value and value.strip()}, key=_vulnerability_sort_key)
    if normalized:
        return normalized[0]
    raise BaselineError("Dependency finding has no stable vulnerability identifier.")


def _vulnerability_sort_key(value: str) -> tuple[int, str]:
    if value.startswith("CVE-"):
        return 0, value
    if value.startswith("GHSA-"):
        return 1, value
    if value.startswith("OSV-"):
        return 2, value
    return 3, value


def _require_unique_identities(findings: list[dict[str, Any]], location: str) -> None:
    candidates = [candidate for finding in findings for candidate in finding["identityCandidates"]]
    if len(candidates) != len(set(candidates)):
        raise BaselineError(f"{location} contains duplicate or ambiguous semantic finding identities.")


def _baseline_id(baseline: dict[str, Any]) -> str:
    content = {key: value for key, value in baseline.items() if key != "baselineId"}
    return "baseline-" + hashlib.sha256(_canonical_json(content).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _is_timestamp(value: str) -> bool:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _safe_target(value: Any) -> str:
    try:
        return normalize_target(value)
    except BaselineError:
        return ""


def _record_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -SEVERITY_WEIGHT.get(record.get("severity", "unknown"), 0),
        record.get("category", ""),
        record.get("target", "").casefold(),
        record.get("fingerprint", ""),
    )


def _comparison_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    finding = record.get("baselineFinding") or {}
    return (
        -SEVERITY_WEIGHT.get(record.get("severity", finding.get("severity", "unknown")), 0),
        record.get("category", finding.get("category", "")),
        record.get("target", finding.get("target", "")).casefold(),
        record.get("fingerprint", record.get("baselineFingerprint", "")),
    )

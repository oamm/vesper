import hashlib
import re
from typing import Any

SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
SEVERITY_WEIGHT = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in SEVERITIES:
        return normalized
    if normalized in {"error", "fatal", "blocker"}:
        return "critical"
    if normalized in {"warning", "moderate"}:
        return "medium"
    if normalized in {"note", "informational"}:
        return "info"
    return "unknown"


def normalize(scanner: str, raw: Any) -> list[dict[str, Any]]:
    if scanner == "trivy":
        return _normalize_trivy(raw)
    if scanner == "osv-scanner":
        return _normalize_osv(raw)
    if scanner == "semgrep":
        return _normalize_semgrep(raw)
    if scanner == "grype":
        return _normalize_grype(raw)
    if scanner == "gitleaks":
        return normalize_gitleaks(raw)
    return []


def normalize_api_behavior(api_execution: dict[str, Any], api_contract: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn deterministic Schemathesis contract failures into bounded findings."""
    supported = {"unexpected_5xx", "response_schema_violation", "unexpected_status"}
    operations = {
        item.get("id"): item
        for item in api_contract.get("operations", [])
        if isinstance(item, dict) and item.get("id")
    }
    grouped: dict[tuple[str, str, tuple[str, ...]], list[dict[str, Any]]] = {}
    for event in api_execution.get("events", []):
        if not isinstance(event, dict) or event.get("classification") not in supported:
            continue
        operation_id = str(event.get("operation") or "")
        if operation_id not in operations:
            raise ValueError("API behavioral evidence references an unknown contract operation.")
        operation = operations[operation_id]
        expected = tuple(sorted(str(item.get("status")) for item in operation.get("responses", []) if isinstance(item, dict)))
        key = (operation_id, str(event["classification"]), expected)
        grouped.setdefault(key, []).append(event)

    findings: list[dict[str, Any]] = []
    for (operation_id, behavior, expected), events in sorted(grouped.items()):
        events = sorted(events, key=lambda item: (
            str(item.get("status", "")),
            str(item.get("path", "")),
            str(item.get("caseId", "")),
        ))
        representative = events[:3]
        status_values = sorted({str(item.get("status")) for item in events if item.get("status") is not None})
        severity = "medium" if behavior in {"unexpected_5xx", "response_schema_violation"} else "low"
        title = {
            "unexpected_5xx": f"Unexpected 5xx response for {operation_id}",
            "response_schema_violation": f"Response schema violation for {operation_id}",
            "unexpected_status": f"Unexpected status response for {operation_id}",
        }[behavior]
        expected_text = ", ".join(expected) or "no documented response status"
        observed_text = ", ".join(status_values) or "unknown status"
        description = (
            f"The authorized API execution observed {observed_text} for {operation_id}, "
            f"while the contract documents {expected_text}. This is runtime behavioral evidence; "
            "exploitability is not established."
        )
        finding = _finding(
            "api_behavior", behavior, title, description, severity, "schemathesis", behavior,
            "", None, None, [], [], None, None,
            f"{behavior} on {operation_id}", behavior,
            identity_extra="|".join([operation_id, behavior, *expected]),
        )
        finding["capability"] = "api_behavior"
        finding["findingNature"] = "api_behavior"
        finding["location"] = {"file": "", "operation": operation_id, "line": None, "column": None}
        finding["description"] = description
        finding["behaviorEvidence"] = {
            "contractDigest": api_execution.get("contract", {}).get("digest"),
            "apiIdentityVersion": api_execution.get("contract", {}).get("apiIdentityVersion"),
            "operation": operation_id,
            "behaviorType": behavior,
            "expectedStatuses": list(expected),
            "observedStatuses": status_values,
            "candidateCount": len(events),
            "retainedEvidenceCount": len(representative),
            "evidenceTruncated": len(events) > len(representative),
            "examples": [
                {
                    "caseId": _safe_text(item.get("caseId"))[:120],
                    "method": _safe_text(item.get("method"))[:16],
                    "path": _redact_behavior_text(item.get("path")),
                    "status": item.get("status"),
                    "contentType": _safe_text(item.get("contentType"))[:200],
                    "check": _redact_behavior_text(item.get("check")),
                }
                for item in representative
            ],
        }
        finding["evidence"] = {"message": description, "behavior": behavior, "operation": operation_id}
        findings.append(finding)
    return findings


def normalize_gitleaks(raw: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for leak in raw if isinstance(raw, list) else []:
        if not isinstance(leak, dict):
            continue
        rule_id = leak.get("RuleID") or "secret"
        path = _normalize_file_path(leak.get("File") or leak.get("SymlinkFile") or "")
        commit = str(leak.get("Commit") or "").strip()
        line = _line(leak, "StartLine")
        title = leak.get("Description") or rule_id
        safe_description = "Secret detected in Git history; rotate or revoke the credential and remove the historical exposure."
        finding = _finding(
            "secret", rule_id, title, safe_description, "unknown", "gitleaks", rule_id,
            path, line, _line(leak, "StartColumn"), [], [], None, None,
            "Historical Git secret evidence", rule_id, identity_extra=commit,
        )
        finding["secretEvidence"] = {
            "scope": "historical",
            "currentPresence": "unknown",
            "commit": _safe_text(commit) if commit else None,
            "rule": _safe_text(rule_id),
        }
        finding["location"]["history"] = True
        finding["scannerEvidence"][0].update({
            "historical": True,
            "commit": _safe_text(commit) if commit else None,
            "date": _safe_text(leak.get("Date") or "") or None,
            "nativeRule": _safe_text(rule_id),
            "nativeFile": path,
            "nativeLine": line,
        })
        findings.append(finding)
    return findings


def normalize_grype(raw: Any, inventory: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    components = (inventory or {}).get("components") if isinstance(inventory, dict) else []
    component_by_purl = {str(item.get("purl")): item for item in components if isinstance(item, dict) and item.get("purl")}
    component_by_semantic = {
        _component_key(item.get("ecosystem"), item.get("name"), item.get("version")): item
        for item in components if isinstance(item, dict)
    }
    for match in (raw.get("matches") or []) if isinstance(raw, dict) else []:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vuln_id = vulnerability.get("id") or "vulnerability"
        related = match.get("relatedVulnerabilities") or []
        aliases = [item.get("id") for item in related if isinstance(item, dict) and item.get("id")]
        identifiers = [vuln_id, *aliases]
        purl = artifact.get("purl") or artifact.get("PURL")
        package_name = artifact.get("name") or "unknown"
        package_version = artifact.get("version") or "unknown"
        ecosystem = _ecosystem(purl or artifact.get("type")) or "unknown"
        component = component_by_purl.get(str(purl)) if purl else None
        if component is None:
            component = component_by_semantic.get(_component_key(ecosystem, package_name, package_version))
        occurrences = component.get("occurrences", []) if isinstance(component, dict) else []
        locations = artifact.get("locations") or []
        target = occurrences[0].get("path") if occurrences else _grype_location(locations)
        package = {
            "name": package_name,
            "version": package_version,
            "fixedVersion": _grype_fixed_versions(vulnerability.get("fix")),
            "ecosystem": ecosystem,
        }
        if component:
            package["componentId"] = component.get("id")
            package["occurrences"] = occurrences
            if component.get("purl"):
                package["purl"] = component["purl"]
        finding = _finding(
            "dependency", vuln_id, vulnerability.get("fix", {}).get("state") or vuln_id,
            vulnerability.get("description"), vulnerability.get("severity"), "grype", vuln_id,
            target, None, None, [], sorted({value for value in identifiers if str(value).startswith("CVE-")}),
            _grype_cvss(vulnerability), package,
            (vulnerability.get("urls") or [vuln_id])[0], vuln_id,
        )
        finding["scannerEvidence"][0].update({
            "nativeFixedVersion": package.get("fixedVersion"),
            "nativeMatch": {key: artifact.get(key) for key in ("name", "version", "purl", "type") if artifact.get(key) is not None},
            "databaseStatus": (raw.get("descriptor") or {}).get("db") if isinstance(raw.get("descriptor"), dict) else None,
        })
        if component:
            finding["component"] = {
                "id": component.get("id"),
                "purl": component.get("purl"),
                "occurrences": occurrences,
            }
        findings.append(finding)
    return findings


def _component_key(ecosystem: Any, name: Any, version: Any) -> tuple[str, str, str]:
    return (str(ecosystem or "unknown").casefold(), str(name or "").casefold(), str(version or ""))


def _grype_location(locations: Any) -> str:
    if isinstance(locations, list):
        for location in locations:
            if isinstance(location, dict) and location.get("path"):
                return _normalize_file_path(location["path"])
    return "sbom"


def _grype_fixed_versions(fix: Any) -> str | None:
    if not isinstance(fix, dict):
        return None
    versions = fix.get("versions") or []
    if not isinstance(versions, list):
        return None
    values = sorted({str(value) for value in versions if value})
    return ", ".join(values) if values else None


def _grype_cvss(vulnerability: dict[str, Any]) -> float | None:
    for entry in vulnerability.get("cvss") or []:
        if isinstance(entry, dict) and isinstance(entry.get("metrics"), dict):
            score = entry["metrics"].get("baseScore")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                return float(score)
    return None


def _normalize_trivy(raw: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(raw, dict):
        return findings
    for result in raw.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            aliases = item.get("Aliases") or []
            cve = sorted({value for value in [item.get("VulnerabilityID"), *aliases] if str(value).startswith("CVE-")})
            package_url = item.get("PkgIdentifier", {}).get("PURL") if isinstance(item.get("PkgIdentifier"), dict) else None
            package = {
                "name": item.get("PkgName"),
                "version": item.get("InstalledVersion"),
                "fixedVersion": item.get("FixedVersion"),
                "ecosystem": _ecosystem(package_url or item.get("PkgType")),
            }
            findings.append(_finding(
                "dependency", item.get("VulnerabilityID", "vulnerability"), item.get("Title") or item.get("VulnerabilityID"),
                item.get("Description"), item.get("Severity"), "trivy", item.get("VulnerabilityID"),
                target, None, None, item.get("CweIDs") or [], cve,
                item.get("CVSS", {}).get("nvd", {}).get("V3Score") if isinstance(item.get("CVSS"), dict) else None,
                package, item.get("PrimaryURL") or item.get("Description"), item.get("VulnerabilityID"),
            ))
        for item in result.get("Secrets") or []:
            if not isinstance(item, dict):
                continue
            finding = _finding(
                "secret", item.get("RuleID", "secret"), item.get("Title") or "Potential secret detected",
                item.get("Match") or item.get("Message"), item.get("Severity"), "trivy", item.get("RuleID"),
                target, _line(item, "StartLine"), _line(item, "StartColumn"), [], [], None, None,
                item.get("Match") or item.get("RuleID"), item.get("RuleID"),
            )
            findings.append(finding)
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            misconfig_type = str(item.get("Type") or result.get("Type") or "").lower()
            category = "container" if "docker" in misconfig_type or "container" in misconfig_type else "iac"
            findings.append(_finding(
                category, item.get("ID", "misconfiguration"), item.get("Title") or item.get("ID"),
                item.get("Description") or item.get("Message"), item.get("Severity"), "trivy", item.get("ID"),
                target, item.get("CauseMetadata", {}).get("StartLine") if isinstance(item.get("CauseMetadata"), dict) else None,
                None, item.get("CweIDs") or [], [], None, None, item.get("Message"), item.get("ID"),
            ))
    return findings


def _normalize_osv(raw: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(raw, dict):
        return findings
    for result in raw.get("results") or raw.get("Results") or []:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or result.get("Source") or {}
        path = source.get("path") or source.get("Path") or ""
        for package_result in result.get("packages") or result.get("Packages") or []:
            if not isinstance(package_result, dict):
                continue
            package = package_result.get("package") or package_result.get("Package") or {}
            for item in package_result.get("vulnerabilities") or package_result.get("Vulnerabilities") or []:
                if not isinstance(item, dict):
                    continue
                aliases = item.get("aliases") or item.get("Aliases") or []
                vuln_id = item.get("id") or item.get("ID") or "vulnerability"
                cve = sorted({value for value in [vuln_id, *aliases] if str(value).startswith("CVE-")})
                finding = _finding(
                    "dependency", vuln_id, item.get("summary") or item.get("Summary") or vuln_id,
                    item.get("details") or item.get("Details"), _osv_severity(item), "osv-scanner", vuln_id,
                    path, None, None, [], cve, _osv_cvss(item), {
                        "name": package.get("name") or package.get("Name"),
                        "version": package.get("version") or package.get("Version"),
                        "fixedVersion": None,
                        "ecosystem": _ecosystem(package.get("ecosystem") or package.get("Ecosystem")),
                    }, item.get("details") or item.get("summary"), vuln_id,
                )
                vectors = _osv_cvss_vectors(item)
                if vectors:
                    finding["security"]["cvssVector"] = vectors[0] if len(vectors) == 1 else vectors
                findings.append(finding)
    return findings


def _normalize_semgrep(raw: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(raw, dict):
        return findings
    for item in raw.get("results") or []:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        cwe_value = metadata.get("cwe") or []
        cwes = [cwe_value] if isinstance(cwe_value, str) else cwe_value
        cwes = sorted({match.group(0) for value in cwes for match in re.finditer(r"CWE-\d+", str(value), re.I)})
        findings.append(_finding(
            "sast", item.get("check_id", "finding"), extra.get("message") or item.get("check_id"),
            extra.get("message"), extra.get("severity"), "semgrep", item.get("check_id"),
            item.get("path"), (item.get("start") or {}).get("line"), (item.get("start") or {}).get("col"),
            cwes, [], None, None, extra.get("lines"), item.get("check_id"),
            metadata.get("confidence", "unknown"),
        ))
    return findings


def _finding(category: str, finding_type: Any, title: Any, description: Any, severity: Any,
             scanner: str, rule_id: Any, path: Any, line: Any, column: Any, cwe: Any,
             cve: Any, cvss: Any, package: Any, evidence: Any, raw_id: Any,
             confidence: Any = "unknown", identity_extra: Any = None) -> dict[str, Any]:
    normalized_severity = normalize_severity(severity)
    type_value = _safe_text(finding_type or category)
    cwe_list = cwe if isinstance(cwe, list) else [cwe] if cwe else []
    cve_list = cve if isinstance(cve, list) else [cve] if cve else []
    location_file = _safe_text(_normalize_file_path(path))
    package_value = package if isinstance(package, dict) and package.get("name") else None
    identity_key = sorted(str(value).casefold() for value in cve_list)[0] if cve_list else type_value.casefold()
    components = [category, identity_key, location_file, str(line or "")]
    if identity_extra:
        components.append(str(identity_extra))
    if package_value:
        components.extend([
            str(package_value.get("ecosystem") or "unknown").casefold(),
            str(package_value.get("name") or "").casefold(),
            str(package_value.get("version") or ""),
        ])
    fingerprint = hashlib.sha256("|".join(components).encode("utf-8")).hexdigest()
    cwe_out = sorted({_safe_text(value) for value in cwe_list if value})
    cve_out = sorted({_safe_text(value) for value in cve_list if value})
    native_title = _safe_text(title or "")
    native_description = _safe_text(description or "")
    native_id = _safe_text(raw_id or "")
    identifiers = sorted({_safe_text(str(value)) for value in [raw_id, *cve_list] if value})
    if category == "dependency" and package_value:
        package_label = str(package_value["name"])
        if package_value.get("version"):
            package_label += f" {package_value['version']}"
        vulnerability_id = cve_out[0] if cve_out else native_id
        title_out = f"{package_label} affected by {vulnerability_id}" if vulnerability_id else f"{package_label} vulnerability"
        ecosystem = package_value.get("ecosystem") or "unknown ecosystem"
        description_out = f"Detected {ecosystem} package {package_label} in {location_file or 'an unspecified repository path'}."
    else:
        title_out = native_title or type_value
        description_out = native_description
    finding_nature, context_required, context_reason = _finding_nature(category, rule_id, native_title, native_description)
    detection_confidence = _safe_text(confidence or "unknown").casefold()
    impact = {"type": _impact_type(category, cwe_out, title, description)}
    return {
        "schemaVersion": 2,
        "fingerprintVersion": 2,
        "id": f"finding-{fingerprint[:20]}",
        "fingerprint": fingerprint,
        "category": category,
        "findingNature": finding_nature,
        "type": type_value,
        "severity": normalized_severity,
        "remediationPriority": {"critical": "p0", "high": "p1", "medium": "p2", "low": "p3", "info": "p4", "unknown": "p4"}[normalized_severity],
        "detectionConfidence": detection_confidence,
        "confidence": detection_confidence,
        "reachability": "unknown",
        "applicability": "unknown",
        "contextRequired": context_required,
        "title": _safe_text(title_out),
        "description": description_out,
        "scanner": {"name": scanner, "ruleId": _safe_text(rule_id or "")},
        "location": {"file": location_file, "line": line, "column": column},
        "security": {"cwe": cwe_out, "cve": cve_out, "identifiers": identifiers, "cvss": cvss},
        "package": package_value,
        "impact": impact,
        "evidence": {"message": _safe_text(evidence or "")},
        "scannerEvidence": [{
            "scanner": scanner,
            "ruleId": _safe_text(rule_id or ""),
            "rawId": native_id,
            "nativeId": native_id,
            "nativeTitle": native_title,
            "nativeDescription": native_description,
        }],
        "scannerMetadata": {"nativeSeverity": _safe_text(severity or "unknown")},
        **({"contextReason": context_reason} if context_reason else {}),
    }


def _finding_nature(category: str, rule_id: Any, title: str, description: str) -> tuple[str, bool, str | None]:
    rule = str(rule_id or "").casefold()
    text = f"{title} {description}".casefold()
    if category == "dependency":
        return "dependency_vulnerability", False, None
    if category == "secret":
        return "secret", False, None
    if category == "sast":
        return "vulnerability", False, None
    if category == "iac":
        return "iac", False, None
    if category == "container" and ("ds026" in rule or "healthcheck" in text or "health check" in text):
        return "hardening", True, "Container health may be managed by deployment-orchestrator probes."
    if category == "container":
        return "misconfiguration", False, None
    return "unknown", False, None


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for finding in findings:
        fingerprint = finding["fingerprint"]
        if fingerprint not in merged:
            merged[fingerprint] = finding
            continue
        existing = merged[fingerprint]
        evidence = {(item["scanner"], item["rawId"]): item for item in existing["scannerEvidence"]}
        for item in finding["scannerEvidence"]:
            evidence[(item["scanner"], item["rawId"])] = item
        existing["scannerEvidence"] = sorted(evidence.values(), key=lambda item: (item["scanner"], item["rawId"]))
        if SEVERITY_WEIGHT[finding["severity"]] > SEVERITY_WEIGHT[existing["severity"]]:
            existing["severity"] = finding["severity"]
            existing["remediationPriority"] = {
                "critical": "p0", "high": "p1", "medium": "p2", "low": "p3", "info": "p4", "unknown": "p4",
            }[finding["severity"]]
        for key in ("cwe", "cve"):
            existing["security"][key] = sorted(set(existing["security"][key] + finding["security"][key]))
        existing["security"]["identifiers"] = sorted(set(existing["security"]["identifiers"] + finding["security"]["identifiers"]))
        if finding.get("component") and not existing.get("component"):
            existing["component"] = finding["component"]
        if finding.get("package", {}).get("componentId") and not existing.get("package", {}).get("componentId"):
            existing.setdefault("package", {})["componentId"] = finding["package"]["componentId"]
            existing["package"]["occurrences"] = finding["package"].get("occurrences", [])
    for finding in merged.values():
        evidence = sorted(finding["scannerEvidence"], key=lambda item: (item["scanner"], item["rawId"], item.get("ruleId", "")))
        detectors = sorted({item["scanner"] for item in evidence})
        primary = evidence[0]
        finding["scannerEvidence"] = evidence
        finding["detectors"] = detectors
        finding["corroboration"] = {"detectorCount": len(detectors), "detectors": detectors}
        finding["primaryScanner"] = {
            "name": primary["scanner"],
            "ruleId": primary.get("ruleId", ""),
            "selectionReason": "stable_lexicographic_compatibility_alias",
        }
        finding["scanner"] = {"name": primary["scanner"], "ruleId": primary.get("ruleId", "")}
    return sorted(
        merged.values(),
        key=lambda item: (
            -SEVERITY_WEIGHT[item["severity"]],
            item["category"],
            str((item.get("package") or {}).get("name") or item.get("scanner", {}).get("ruleId") or "").casefold(),
            str(item.get("location", {}).get("file") or "").casefold(),
            ",".join((item.get("security") or {}).get("identifiers") or (item.get("security") or {}).get("cve", [])),
            item["fingerprint"],
        ),
    )


def _line(item: dict[str, Any], key: str) -> int | None:
    value = item.get(key)
    return value if isinstance(value, int) else None


def _normalize_file_path(value: Any) -> str:
    path = str(value or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if path == "/workspace":
        return ""
    if path.startswith("/workspace/"):
        path = path[len("/workspace/"):]
    return path


def _ecosystem(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if text.startswith("pkg:"):
        text = text[4:].split("/", 1)[0]
    aliases = {"nuget": "nuget", "npm": "npm", "pypi": "pypi", "golang": "go", "cargo": "cargo"}
    return aliases.get(text.casefold(), text.casefold())


def _impact_type(category: str, cwes: list[str], title: Any, description: Any) -> str:
    if category == "secret":
        return "secret_exposure"
    if category == "container":
        return "container_hardening"
    if category == "iac":
        return "misconfiguration"

    evidence = f"{title or ''} {description or ''}".casefold()
    cwe_set = {value.upper() for value in cwes}
    if "CWE-400" in cwe_set or "denial of service" in evidence or "denial-of-service" in evidence:
        return "denial_of_service"
    if "CWE-78" in cwe_set or "remote code execution" in evidence:
        return "remote_code_execution"
    if "privilege escalation" in evidence:
        return "privilege_escalation"
    if "authentication bypass" in evidence:
        return "authentication_bypass"
    if "authorization bypass" in evidence:
        return "authorization_bypass"
    if "information disclosure" in evidence:
        return "information_disclosure"
    if "cryptographic weakness" in evidence or "weak cryptographic" in evidence:
        return "cryptographic_weakness"
    return "unknown"


def _osv_severity(item: dict[str, Any]) -> str:
    database_severity = item.get("database_specific", {}).get("severity") if isinstance(item.get("database_specific"), dict) else None
    normalized_database_severity = normalize_severity(database_severity)
    if normalized_database_severity != "unknown":
        return normalized_database_severity

    for entry in item.get("severity") or []:
        if not isinstance(entry, dict) or not entry.get("type", "").upper().startswith("CVSS"):
            continue
        score = _numeric_cvss_score(entry.get("score"))
        if score is not None:
            return _cvss_severity(score)
    return "unknown"


def _osv_cvss(item: dict[str, Any]) -> float | None:
    for entry in item.get("severity") or []:
        if isinstance(entry, dict) and entry.get("type", "").upper().startswith("CVSS"):
            score = _numeric_cvss_score(entry.get("score"))
            if score is not None:
                return score
    return None


def _numeric_cvss_score(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        score = float(value)
        return score if 0.0 <= score <= 10.0 else None
    if isinstance(value, str) and re.fullmatch(r"\s*(?:10(?:\.0+)?|[0-9](?:\.\d+)?)\s*", value):
        return float(value.strip())
    return None


def _osv_cvss_vectors(item: dict[str, Any]) -> list[str]:
    vectors = []
    for entry in item.get("severity") or []:
        if isinstance(entry, dict) and entry.get("type", "").upper().startswith("CVSS"):
            score = entry.get("score")
            if isinstance(score, str) and (score.startswith("CVSS:") or score.startswith("AV:") or "/AV:" in score):
                vectors.append(score)
    return sorted(set(vectors))


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _safe_text(value: Any) -> str:
    text = str(value)
    text = re.sub(r"(?i)(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]*\s*[:=]\s*[\"']?)([^\s\"'`,;]+)", r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b", "[REDACTED]", text)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", text, flags=re.S)
    return text


def _redact_behavior_text(value: Any) -> str:
    return _safe_text(value)[:2000]

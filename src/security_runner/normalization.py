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
    return []


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
             confidence: Any = "high") -> dict[str, Any]:
    normalized_severity = normalize_severity(severity)
    type_value = _safe_text(finding_type or category)
    cwe_list = cwe if isinstance(cwe, list) else [cwe] if cwe else []
    cve_list = cve if isinstance(cve, list) else [cve] if cve else []
    location_file = _safe_text(_normalize_file_path(path))
    package_value = package if isinstance(package, dict) and package.get("name") else None
    identity_key = sorted(cve_list)[0] if cve_list else type_value
    components = [category, identity_key, location_file, str(line or "")]
    if package_value:
        components.extend([str(package_value.get("name") or ""), str(package_value.get("version") or "")])
    fingerprint = hashlib.sha256("|".join(components).encode("utf-8")).hexdigest()
    cwe_out = sorted({_safe_text(value) for value in cwe_list if value})
    cve_out = sorted({_safe_text(value) for value in cve_list if value})
    return {
        "id": f"finding-{fingerprint[:20]}",
        "fingerprint": fingerprint,
        "category": category,
        "type": type_value,
        "severity": normalized_severity,
        "remediationPriority": {"critical": "p0", "high": "p1", "medium": "p2", "low": "p3", "info": "p4", "unknown": "p4"}[normalized_severity],
        "confidence": _safe_text(confidence or "unknown").lower(),
        "title": _safe_text(title or type_value),
        "description": _safe_text(description or ""),
        "scanner": {"name": scanner, "ruleId": _safe_text(rule_id or "")},
        "location": {"file": location_file, "line": line, "column": column},
        "security": {"cwe": cwe_out, "cve": cve_out, "cvss": cvss},
        "package": package_value,
        "impact": {"type": _impact_type(category, cwe_out, title, description), "summary": None},
        "reachability": "unknown",
        "evidence": {"message": _safe_text(evidence or ""), "snippet": None},
        "scannerEvidence": [{"scanner": scanner, "rawId": _safe_text(raw_id or "")}],
        "scannerMetadata": {"nativeSeverity": _safe_text(severity or "unknown")},
    }


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
        existing["scannerEvidence"] = list(evidence.values())
        if SEVERITY_WEIGHT[finding["severity"]] > SEVERITY_WEIGHT[existing["severity"]]:
            existing["severity"] = finding["severity"]
        for key in ("cwe", "cve"):
            existing["security"][key] = sorted(set(existing["security"][key] + finding["security"][key]))
    return sorted(merged.values(), key=lambda item: (item["category"], item["location"]["file"], item["fingerprint"]))


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
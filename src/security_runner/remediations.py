import hashlib
from collections import defaultdict
from typing import Any

PRIORITY_BY_SEVERITY = {
    "critical": "p0",
    "high": "p1",
    "medium": "p2",
    "low": "p3",
    "info": "p4",
    "unknown": "p4",
}
PRIORITY_ORDER = {f"p{index}": index for index in range(5)}


def build_remediations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        category = finding.get("category")
        if category == "dependency":
            package = finding.get("package") or {}
            key = (
                "dependency_upgrade",
                str(package.get("ecosystem") or "unknown").casefold(),
                str(package.get("name") or "unknown").casefold(),
                str(package.get("version") or "unknown"),
                str(finding.get("location", {}).get("file") or ""),
            )
            groups[key].append(finding)
        elif category in {"container", "iac"}:
            scanner = finding.get("scanner") or {}
            rule_id = str(scanner.get("ruleId") or finding.get("type") or "unknown")
            title = str(finding.get("title") or rule_id)
            key = ("container_hardening" if category == "container" else "iac_misconfiguration", scanner.get("name", "unknown"), rule_id, title.casefold())
            groups[key].append(finding)
        else:
            key = ("individual", finding.get("fingerprint"))
            groups[key].append(finding)

    remediations = [_make_group(key, group) for key, group in groups.items()]
    return sorted(remediations, key=lambda item: (PRIORITY_ORDER[item["priority"]], item["title"].casefold(), item["id"]))


def _make_group(key: tuple[Any, ...], findings: list[dict[str, Any]]) -> dict[str, Any]:
    remediation_type = str(key[0])
    package = None
    if remediation_type == "dependency_upgrade":
        first_package = findings[0].get("package") or {}
        package_name = str(first_package.get("name") or "Unknown package")
        current = first_package.get("version")
        candidates = sorted({
            version
            for finding in findings
            for version in _fixed_version_candidates((finding.get("package") or {}).get("fixedVersion"))
        })
        target = candidates[0] if len(candidates) == 1 else None
        actual_type = "dependency_upgrade" if candidates else "dependency_review"
        package = {
            "ecosystem": first_package.get("ecosystem"),
            "name": package_name,
            "currentVersion": current,
            "targetVersion": target,
            "candidateFixedVersions": candidates,
        }
        if target:
            title = f"Upgrade {package_name}"
            summary = f"Upgrade from {current} to {target} or a later compatible patched version."
        elif candidates:
            title = f"Upgrade {package_name}"
            summary = f"Scanner patch candidates differ ({', '.join(candidates)}). Confirm package constraints and choose a compatible patched version."
        else:
            title = f"Review {package_name} vulnerability"
            summary = f"Determine a patched version for {package_name} and update the affected dependency."
        remediation_type = actual_type
    elif remediation_type == "container_hardening" and _is_ds026(findings):
        title = "Define container health-check strategy"
        summary = "Define a consistent health-check policy and verify orchestrator probes before applying a blanket Docker HEALTHCHECK change."
    elif remediation_type in {"container_hardening", "iac_misconfiguration"}:
        title = _group_title(findings)
        summary = f"Review rule {key[2]} and apply a consistent correction to the affected artifacts."
    else:
        title = str(findings[0].get("title") or findings[0].get("type") or "Review finding")
        summary = str(findings[0].get("description") or "Review this finding and apply the recommended change.")

    severity = max((finding.get("severity", "unknown") for finding in findings), key=_severity_rank)
    identity = "|".join(str(part) for part in key)
    remediation_id = "remediation-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    identifiers = sorted({
        identifier
        for finding in findings
        for identifier in (finding.get("security") or {}).get("cve", [])
    })
    files = sorted({
        str(location.get("file"))
        for finding in findings
        for location in [finding.get("location") or {}]
        if location.get("file")
    })
    return {
        "id": remediation_id,
        "type": remediation_type,
        "priority": PRIORITY_BY_SEVERITY.get(severity, "p4"),
        "title": title,
        "summary": summary,
        "affectedFindings": sorted(finding["id"] for finding in findings),
        "affectedFiles": files,
        "findingCount": len(findings),
        "securityIdentifiers": identifiers,
        "package": package,
    }


def _is_ds026(findings: list[dict[str, Any]]) -> bool:
    return any(
        "DS026" in str((finding.get("scanner") or {}).get("ruleId", "")).upper()
        or "healthcheck" in str(finding.get("title", "")).casefold()
        for finding in findings
    )


def _group_title(findings: list[dict[str, Any]]) -> str:
    titles = sorted({str(finding.get("title") or finding.get("type") or "Review finding") for finding in findings})
    return titles[0]


def _severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def _fixed_version_candidates(value: Any) -> list[str]:
    if not value:
        return []
    return sorted({part.strip() for part in str(value).split(",") if part.strip()})
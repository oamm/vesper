import hashlib
from collections import defaultdict
from typing import Any

from packaging.version import InvalidVersion, Version

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
    return sorted(
        remediations,
        key=lambda item: (
            PRIORITY_ORDER[item["priority"]],
            item["type"],
            str((item.get("package") or {}).get("name") or item["title"]).casefold(),
            item["id"],
        ),
    )


def _make_group(key: tuple[Any, ...], findings: list[dict[str, Any]]) -> dict[str, Any]:
    remediation_type = str(key[0])
    package = None
    if remediation_type == "dependency_upgrade":
        first_package = findings[0].get("package") or {}
        package_name = str(first_package.get("name") or "Unknown package")
        current = first_package.get("version")
        finding_candidate_sets = [
            _fixed_version_candidates((finding.get("package") or {}).get("fixedVersion"))
            for finding in findings
        ]
        candidates = sorted({
            version for candidate_set in finding_candidate_sets for version in candidate_set
        }, key=_version_sort_key)
        upgrade_candidates, recommended, selection_reason = _select_recommended_version(current, finding_candidate_sets)
        actual_type = "dependency_upgrade" if recommended else "dependency_review"
        package = {
            "ecosystem": first_package.get("ecosystem"),
            "name": package_name,
            "currentVersion": current,
            "targetVersion": recommended,
            "recommendedVersion": recommended,
            "candidateFixedVersions": candidates,
            "upgradeCandidates": upgrade_candidates,
            "selectionReason": selection_reason,
        }
        if recommended:
            title = f"Upgrade {package_name}"
            summary = f"Upgrade from {current} to {recommended} or a later compatible patched version."
        elif candidates:
            title = f"Review upgrade path for {package_name}"
            summary = (
                f"Scanner reported fixed versions ({', '.join(candidates)}), but Vesper could not prove a safe "
                f"upgrade from {current}. Confirm package constraints before selecting a target."
            )
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
        for identifier in (
            (finding.get("security") or {}).get("identifiers")
            or (finding.get("security") or {}).get("cve", [])
        )
    })
    files = sorted({
        str(location.get("file"))
        for finding in findings
        for location in [finding.get("location") or {}]
        if location.get("file")
    })
    priority = PRIORITY_BY_SEVERITY.get(severity, "p4")
    nature_values = sorted({finding.get("findingNature", "unknown") for finding in findings})
    context_reasons = sorted({finding["contextReason"] for finding in findings if finding.get("contextReason")})
    priority_reasons = [f"severity:{severity}"]
    if package and package.get("recommendedVersion"):
        priority_reasons.append("fixed_version_available")
    return {
        "schemaVersion": 2,
        "id": remediation_id,
        "type": remediation_type,
        "findingNature": nature_values[0] if len(nature_values) == 1 else "mixed",
        "contextRequired": bool(context_reasons),
        "contextReasons": context_reasons,
        "priority": priority,
        "priorityReasons": priority_reasons,
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


def _parse_version(value: str) -> Version | None:
    try:
        return Version(value.lstrip("vV"))
    except InvalidVersion:
        return None


def _version_sort_key(value: str) -> tuple[int, Any, str]:
    parsed = _parse_version(value)
    return (0, parsed, value) if parsed is not None else (1, Version("0"), value.casefold())


def _select_recommended_version(current: Any, candidate_sets: list[list[str]]) -> tuple[list[str], str | None, str]:
    candidates = sorted({candidate for candidate_set in candidate_sets for candidate in candidate_set}, key=_version_sort_key)
    if not candidates:
        return [], None, "no_fixed_version_reported"
    if not current:
        return [], None, "current_version_unavailable"

    current_version = _parse_version(str(current))
    if current_version is None:
        return [], None, "current_version_unparseable"

    parsed_candidate_sets = [
        [(candidate, _parse_version(candidate)) for candidate in candidate_set]
        for candidate_set in candidate_sets
    ]
    upgrade_candidates = sorted({
        candidate
        for candidate_set in parsed_candidate_sets
        for candidate, parsed in candidate_set
        if parsed is not None and parsed > current_version
    }, key=_version_sort_key)
    if not upgrade_candidates:
        return [], None, "no_candidate_is_an_upgrade"

    def compatible_line(parsed: Version) -> tuple[int, ...]:
        return (parsed.major, parsed.minor) if current_version.major == 0 else (parsed.major,)

    line_candidates = {
        compatible_line(parsed)
        for candidate_set in parsed_candidate_sets
        for _, parsed in candidate_set
        if parsed is not None and parsed > current_version
    }
    common_lines = [
        line for line in line_candidates
        if all(any(parsed is not None and parsed > current_version and compatible_line(parsed) == line
                   for _, parsed in candidate_set) for candidate_set in parsed_candidate_sets)
    ]
    if not common_lines:
        return upgrade_candidates, None, "no_common_compatible_fix_line"

    recommendations = []
    for line in common_lines:
        thresholds = [
            min(parsed for _, parsed in candidate_set if parsed is not None and parsed > current_version and compatible_line(parsed) == line)
            for candidate_set in parsed_candidate_sets
        ]
        recommendations.append(max(thresholds))
    recommended_version = min(recommendations)
    recommended = next(
        candidate for candidate in candidates
        if _parse_version(candidate) == recommended_version
    )
    selection_reason = "same_major_common_fixed_version" if current_version.major else "same_zero_major_minor_common_fixed_version"
    return upgrade_candidates, recommended, selection_reason
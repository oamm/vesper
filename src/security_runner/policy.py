from typing import Any

from security_runner.normalization import SEVERITIES


def evaluate(
    findings: list[dict[str, Any]],
    policy: dict[str, Any],
    remediations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    fail_on = {str(value).lower() for value in policy.get("failOn", [])}
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1

    reasons: list[str] = []
    gated = sorted(severity for severity in fail_on if severity in counts and counts[severity])
    if gated:
        reasons.append(f"Findings at configured severities: {', '.join(gated)}")
    secrets = sum(1 for finding in findings if finding["category"] == "secret")
    if policy.get("failOnSecrets", False) and secrets:
        reasons.append(f"{secrets} secret finding(s) detected")
    max_high = policy.get("maxHigh")
    if max_high is not None and counts["high"] > max_high:
        reasons.append(f"High findings ({counts['high']}) exceed maxHigh ({max_high})")

    blocking = [
        finding for finding in findings
        if finding["severity"] in fail_on
        or (policy.get("failOnSecrets", False) and finding["category"] == "secret")
        or (max_high is not None and counts["high"] > max_high and finding["severity"] == "high")
    ]
    blocking_ids = {finding["id"] for finding in blocking if finding.get("id")}
    blocking_remediations = sum(
        1 for remediation in (remediations or [])
        if blocking_ids.intersection(remediation.get("affectedFindings", []))
    )
    return {
        "status": "failed" if reasons else "passed",
        "reason": "; ".join(reasons) or "Policy passed",
        "blockingFindings": len(blocking),
        "blockingRemediations": blocking_remediations,
        "blockingFindingIds": sorted(blocking_ids),
    }
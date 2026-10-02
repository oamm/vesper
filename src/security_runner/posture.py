"""Normalization and validation for repository posture evidence."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


POSTURE_SCHEMA_VERSION = 1
MAX_CHECKS = 64
MAX_EVIDENCE = 32
MAX_STRING = 1000


class PostureError(ValueError):
    pass


def validate_scorecard(raw: Any) -> str:
    if not isinstance(raw, dict):
        raise PostureError("Scorecard output schema is unsupported (expected an object).")
    checks = raw.get("checks")
    if not isinstance(checks, list) or len(checks) > MAX_CHECKS:
        raise PostureError("Scorecard output schema is unsupported (expected a bounded checks array).")
    if "score" in raw and raw["score"] is not None and not _number(raw["score"]):
        raise PostureError("Scorecard output schema is unsupported (score must be numeric).")
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str) or not check["name"].strip():
            raise PostureError("Scorecard output schema is unsupported (checks require names).")
        if check.get("score") is not None and not _number(check["score"]):
            raise PostureError("Scorecard output schema is unsupported (check score must be numeric).")
    return str(raw.get("scorecard", {}).get("version") or "unknown") if isinstance(raw.get("scorecard"), dict) else "unknown"


def normalize_scorecard(raw: dict[str, Any], workspace: Path, remote: str | None, commit: str | None) -> dict[str, Any]:
    validate_scorecard(raw)
    repository = normalize_repository_identity(remote, commit or _git_value(workspace, ["rev-parse", "HEAD"]))
    checks = []
    for item in raw.get("checks", []):
        name = _text(item.get("name"), "unknown")
        score = item.get("score") if _number(item.get("score")) else None
        documentation = item.get("documentation") if isinstance(item.get("documentation"), dict) else {}
        details = item.get("details") if isinstance(item.get("details"), list) else []
        checks.append({
            "id": name,
            "name": name,
            "state": _state(score),
            "score": score,
            "reason": _text(item.get("reason"), "")[:MAX_STRING],
            "documentation": {
                "short": _text(documentation.get("short"), "")[:MAX_STRING],
                "url": _safe_url(documentation.get("url")),
            },
            "evidenceSource": "local",
            "evidence": _bounded_details(details),
        })
    checks.sort(key=lambda check: check["id"])
    counts = {state.lower(): 0 for state in ("PASS", "FAIL", "WARN", "UNKNOWN", "NOT_APPLICABLE", "ERROR")}
    for check in checks:
        counts[check["state"].lower()] += 1
    return {
        "schemaVersion": POSTURE_SCHEMA_VERSION,
        "repository": repository,
        "mode": "local",
        "coverage": {
            "assessment": "partial" if checks else "unknown",
            "localChecks": len(checks),
            "providerChecks": 0,
            "unavailableChecks": "Provider-backed checks were not evaluated in local mode.",
        },
        "scorecard": {
            "score": raw.get("score") if _number(raw.get("score")) else None,
            "version": _text((raw.get("scorecard") or {}).get("version"), "unknown") if isinstance(raw.get("scorecard"), dict) else "unknown",
        },
        "counts": counts,
        "checks": checks,
    }


def validate_posture(posture: Any) -> None:
    if not isinstance(posture, dict) or posture.get("schemaVersion") != POSTURE_SCHEMA_VERSION:
        raise PostureError("Unsupported posture schema version.")
    checks = posture.get("checks")
    if not isinstance(checks, list) or len(checks) > MAX_CHECKS:
        raise PostureError("Posture checks are missing or exceed the report limit.")
    ids = [check.get("id") for check in checks if isinstance(check, dict)]
    if len(ids) != len(checks) or len(ids) != len(set(ids)):
        raise PostureError("Posture check IDs must be unique.")
    for check in checks:
        if check.get("state") not in {"PASS", "FAIL", "WARN", "UNKNOWN", "NOT_APPLICABLE", "ERROR"}:
            raise PostureError("Posture check has an unsupported state.")
    counts = posture.get("counts")
    if not isinstance(counts, dict) or sum(value for value in counts.values() if isinstance(value, int)) != len(checks):
        raise PostureError("Posture state counts are inconsistent.")


def posture_summary(posture: dict[str, Any]) -> dict[str, Any]:
    validate_posture(posture)
    counts = posture["counts"]
    return {
        "checks": len(posture["checks"]),
        "passed": counts.get("pass", 0),
        "failed": counts.get("fail", 0),
        "warn": counts.get("warn", 0),
        "unknown": counts.get("unknown", 0),
        "notApplicable": counts.get("not_applicable", 0),
        "coverage": posture["coverage"].get("assessment", "unknown"),
    }


def normalize_repository_identity(remote: str | None, commit: str | None) -> dict[str, Any]:
    value = (remote or "").strip()
    provider = "local"
    owner = None
    name = None
    normalized = None
    if value:
        candidate = value
        if candidate.startswith("git@") and ":" in candidate:
            host, path = candidate[4:].split(":", 1)
            candidate = f"https://{host}/{path}"
        parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
        host = parsed.hostname or ""
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        parts = [part for part in path.split("/") if part]
        if host:
            provider = host.lower()
            normalized = f"{provider}/{'/'.join(parts)}" if parts else provider
        if host.lower() in {"github.com", "gitlab.com", "bitbucket.org"} and len(parts) >= 2:
            owner, name = parts[-2], parts[-1]
            provider = host.lower().split(".")[0]
    return {key: value for key, value in {
        "provider": provider,
        "origin": normalized,
        "owner": owner,
        "name": name,
        "commit": commit,
    }.items() if value not in (None, "")}


def _state(score: float | int | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score < 0:
        return "NOT_APPLICABLE"
    if score >= 10:
        return "PASS"
    if score <= 0:
        return "FAIL"
    return "WARN"


def _bounded_details(details: list[Any]) -> list[str]:
    values = []
    for item in details[:MAX_EVIDENCE]:
        if isinstance(item, dict):
            text = "; ".join(f"{key}={_text(value, '')}" for key, value in sorted(item.items()) if key not in {"author", "email"})
        else:
            text = _text(item, "")
        if text:
            values.append(text[:MAX_STRING])
    return sorted(set(values))


def _git_value(workspace: Path, args: list[str]) -> str | None:
    import subprocess
    try:
        completed = subprocess.run(["git", *args], cwd=workspace, capture_output=True, text=True, timeout=3, check=False)
        return completed.stdout.strip() if completed.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def git_remote(workspace: Path) -> str | None:
    return _git_value(workspace, ["config", "--get", "remote.origin.url"])


def _safe_url(value: Any) -> str:
    text = _text(value, "")
    if not text.startswith(("https://", "http://")):
        return ""
    parsed = urlsplit(text)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"[:MAX_STRING]


def _text(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) else fallback


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)

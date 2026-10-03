import hashlib
import json
import os
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class ApiExecutionError(ValueError):
    pass


MAX_TEXT = 2000
MAX_BODY = 65536


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return str(value)[:limit] if value is not None else ""


def normalize_target(value: str) -> dict[str, Any]:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ApiExecutionError("API target is not a valid URL.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ApiExecutionError("API target must use http or https.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ApiExecutionError("API target must not contain credentials, query, or fragment data.")
    if not parsed.hostname:
        raise ApiExecutionError("API target must include a host.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ApiExecutionError("API target has an invalid port.") from exc
    base_path = "/" + parsed.path.strip("/") if parsed.path.strip("/") else "/"
    if not base_path.endswith("/"):
        base_path += "/"
    host = parsed.hostname.lower()
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    origin = urlunsplit((parsed.scheme.lower(), f"{display_host}:{port}" if port else display_host, base_path.rstrip("/") or "/", "", ""))
    return {
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "basePath": base_path,
        "origin": origin,
    }


def _safe_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items() if str(key).lower() not in {"authorization", "proxy-authorization", "cookie", "set-cookie"}}
    if isinstance(value, list):
        return [_safe_value(item) for item in value[:100]]
    if isinstance(value, str):
        return value[:MAX_TEXT]
    return value


def _operation_id(case: Any) -> str:
    return f"{str(case.method).upper()} {case.path}"


def _case_metadata(case: Any) -> dict[str, Any]:
    return {
        "caseId": _text(getattr(case, "id", ""), 200),
        "operation": _operation_id(case),
        "method": str(case.method).upper(),
        "path": _text(getattr(case, "formatted_path", case.path)),
    }


def _contains_external_ref(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_external_ref(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_external_ref(item) for item in value)
    return value == "external_ref_unresolved"


def execute_contract(
    contract_source: Path,
    contract: dict[str, Any],
    output_path: Path,
    raw_path: Path,
    target: str,
    max_examples: int,
    max_requests: int,
    request_timeout: float,
    global_timeout: float,
    test_mode: str,
    bearer_env: str | None,
    api_key_header: str | None,
    api_key_env: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if max_examples < 1 or max_examples > 100:
        raise ApiExecutionError("API max examples must be between 1 and 100.")
    if max_requests < 1 or max_requests > 1000:
        raise ApiExecutionError("API max requests must be between 1 and 1000.")
    if request_timeout <= 0 or request_timeout > 300 or global_timeout <= 0 or global_timeout > 3600:
        raise ApiExecutionError("API timeouts are outside the permitted bounds.")
    if test_mode not in {"read-only", "all"}:
        raise ApiExecutionError("API test mode must be read-only or all.")
    target_info = normalize_target(target)
    if _contains_external_ref(contract):
        raise ApiExecutionError("Active API testing does not resolve remote or out-of-workspace contract references.")
    token = os.environ.get(bearer_env) if bearer_env else None
    api_key = os.environ.get(api_key_env) if api_key_env else None
    if bearer_env and token is None:
        raise ApiExecutionError(f"Configured bearer credential environment variable is unavailable: {bearer_env}.")
    if api_key_header and api_key_env and api_key is None:
        raise ApiExecutionError(f"Configured API key environment variable is unavailable: {api_key_env}.")
    try:
        import schemathesis
    except ImportError as exc:
        raise ApiExecutionError("Schemathesis is not installed in the runner image.") from exc

    schema = schemathesis.openapi.from_path(str(contract_source))
    if hasattr(schema, "config"):
        schema.config.update(base_url=target_info["origin"], request_timeout=request_timeout, max_redirects=0)
    else:
        schema.base_url = target_info["origin"]
    operations = {}
    for item in schema.get_all_operations():
        operation = item.ok()
        operation_id = getattr(operation, "label", None) or getattr(operation, "verbose_name", None)
        if not operation_id:
            operation_id = f"{str(operation.method).upper()} {operation.path}"
        operations[operation_id] = operation
    contract_ids = {item.get("id") for item in contract.get("operations", [])}
    contract_auth = {item.get("id"): item.get("authentication") for item in contract.get("operations", [])}
    if set(operations) - contract_ids:
        raise ApiExecutionError("Schemathesis discovered an operation absent from api-contract.json.")
    headers: dict[str, str] = {"User-Agent": "Vesper-Schemathesis"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if api_key_header and api_key:
        headers[api_key_header] = api_key
    start = time.monotonic()
    requests_sent = 0
    operation_records: dict[str, dict[str, Any]] = {
        identifier: {
            "operation": identifier,
            "state": "not_attempted",
            "generatedCases": 0,
            "completedCases": 0,
            "candidateFailures": [],
            "validation": {"statusValidation": False, "responseSchemaValidation": False},
        }
        for identifier in sorted(contract_ids)
    }
    events: list[dict[str, Any]] = []
    for identifier, operation in sorted(operations.items()):
        if test_mode == "read-only" and operation.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            continue
        record = operation_records[identifier]
        strategy = operation.as_strategy()
        for _ in range(max_examples):
            if requests_sent >= max_requests or time.monotonic() - start >= global_timeout:
                break
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                case = strategy.example()
            record["generatedCases"] += 1
            metadata = _case_metadata(case)
            try:
                if headers:
                    case_headers = dict(getattr(case, "headers", {}) or {})
                    case_headers.update(headers)
                    case.headers = case_headers
                body = getattr(case, "body", None)
                if isinstance(body, (str, bytes)) and len(body) > MAX_BODY:
                    record["candidateFailures"].append({**metadata, "classification": "request_too_large"})
                    continue
                response = case.call(base_url=target_info["origin"], headers=headers, timeout=request_timeout, allow_redirects=False)
                requests_sent += 1
                record["completedCases"] += 1
                status = int(response.status_code)
                body_bytes = response.content
                response_truncated = len(body_bytes) > MAX_BODY
                event = {**metadata, "status": status, "durationMs": 0, "responseTruncated": response_truncated}
                record["validation"]["statusValidation"] = True
                record["validation"]["responseSchemaValidation"] = not response_truncated
                if status in {401, 403} and contract_auth.get(identifier) == "authenticated" and not (token or api_key):
                    event["classification"] = "auth_limited"
                elif status >= 500:
                    event["classification"] = "unexpected_5xx"
                else:
                    event["classification"] = "response"
                try:
                    if not response_truncated:
                        case.validate_response(response)
                except BaseException as exc:
                    if contract_auth.get(identifier) == "authenticated" and not (token or api_key) and (status in {401, 403} or "authentication" in str(exc).lower()):
                        event["classification"] = "auth_limited"
                    elif status >= 500:
                        event["classification"] = "unexpected_5xx"
                        event["check"] = _text(str(exc))
                    else:
                        event["classification"] = "response_schema_violation"
                        event["check"] = _text(str(exc))
                event["contentType"] = _text(response.headers.get("content-type", ""), 200)
                events.append(event)
                if event["classification"] not in {"response", "auth_limited"}:
                    record["candidateFailures"].append({key: value for key, value in event.items() if key not in {"caseId"}})
            except Exception as exc:
                record["candidateFailures"].append({**metadata, "classification": "connection_error", "message": _text(str(exc))})
                events.append({**metadata, "classification": "connection_error", "message": _text(str(exc))})
        operation_events = [event for event in events if event.get("operation") == identifier]
        if any(event.get("classification") == "auth_limited" for event in operation_events):
            record["state"] = "auth_limited"
        elif record["completedCases"] and record["candidateFailures"]:
            record["state"] = "failed"
        elif record["completedCases"]:
            record["state"] = "exercised"
        elif record["generatedCases"]:
            record["state"] = "failed"
    if requests_sent >= max_requests or time.monotonic() - start >= global_timeout:
        for record in operation_records.values():
            if record["state"] == "not_attempted":
                record["state"] = "not_attempted"
    artifact = {
        "schemaVersion": 1,
        "contract": {"digest": contract["contract"]["contentDigest"], "apiIdentityVersion": contract["apiIdentityVersion"]},
        "target": {key: target_info[key] for key in ("scheme", "host", "port", "basePath")},
        "activeTesting": True,
        "status": "completed",
        "mode": test_mode,
        "limits": {"maxExamplesPerOperation": max_examples, "maxRequests": max_requests, "requestTimeoutSeconds": request_timeout, "globalTimeoutSeconds": global_timeout, "concurrency": 1},
        "operations": [operation_records[key] for key in sorted(operation_records)],
        "events": events[:max_requests],
        "summary": {"known": len(operation_records), "attempted": sum(item["generatedCases"] > 0 for item in operation_records.values()), "exercised": sum(item["state"] == "exercised" for item in operation_records.values()), "authLimited": sum(any(event.get("operation") == item["operation"] and event.get("classification") == "auth_limited" for event in events) for item in operation_records.values()), "failed": sum(item["state"] == "failed" for item in operation_records.values()), "notAttempted": sum(item["state"] == "not_attempted" for item in operation_records.values()), "requests": requests_sent},
        "coverage": {"assessment": "complete" if all(item["state"] in {"exercised", "not_attempted"} for item in operation_records.values()) else "partial", "contractCoverage": contract["coverage"].get("contractCoverage", "unknown"), "runtimeOperationCoverage": "partial"},
        "credentialSource": {"bearerEnvironment": bearer_env, "apiKeyEnvironment": api_key_env, "apiKeyHeader": api_key_header},
    }
    raw = {"schemaVersion": 1, "engine": "schemathesis", "contractDigest": contract["contract"]["contentDigest"], "target": artifact["target"], "events": events[:max_requests]}
    raw_path.write_text(json.dumps(_safe_value(raw), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact, raw

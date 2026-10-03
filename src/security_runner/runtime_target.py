"""Passive runtime-target configuration for future DAST adapters."""

import hashlib
import json
import os
from typing import Any
from urllib.parse import urlsplit


class RuntimeTargetError(ValueError):
    pass


SCHEMA_VERSION = 1
SUPPORTED_AUTH = {"none", "bearer", "api_key", "cookie_session", "static_headers"}


def normalize_runtime_target(value: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeTargetError("Runtime target must be a non-empty URL.")
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise RuntimeTargetError("Runtime target is not a valid URL.") from exc
    if scheme not in {"http", "https"}:
        raise RuntimeTargetError("Runtime target must use http or https.")
    if parsed.username or parsed.password:
        raise RuntimeTargetError("Runtime target must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise RuntimeTargetError("Runtime target must not contain query or fragment data.")
    if not host:
        raise RuntimeTargetError("Runtime target must include a host.")
    effective_port = port or (443 if scheme == "https" else 80)
    path = "/" + parsed.path.strip("/") if parsed.path.strip("/") else "/"
    if path != "/" and not path.endswith("/"):
        path += "/"
    host = host.lower()
    target = {"scheme": scheme, "host": host, "port": effective_port, "basePath": path}
    canonical = json.dumps(target, sort_keys=True, separators=(",", ":")).encode("utf-8")
    target["targetId"] = hashlib.sha256(canonical).hexdigest()
    target["origin"] = {"scheme": scheme, "host": host, "port": effective_port}
    return target


def _auth_metadata() -> dict[str, Any]:
    mode = os.environ.get("SECURITY_SCAN_RUNTIME_AUTH_MODE", "none").strip().lower()
    if mode not in SUPPORTED_AUTH:
        raise RuntimeTargetError(f"Unsupported runtime authentication mode: {mode}.")
    env_name = os.environ.get("SECURITY_SCAN_RUNTIME_AUTH_ENV", "").strip()
    if mode != "none" and not env_name:
        raise RuntimeTargetError("Runtime authentication requires SECURITY_SCAN_RUNTIME_AUTH_ENV.")
    metadata: dict[str, Any] = {"mode": mode, "configured": mode == "none" or bool(env_name)}
    if env_name:
        metadata["source"] = {"kind": "environment", "name": env_name}
    if mode == "api_key":
        header = os.environ.get("SECURITY_SCAN_RUNTIME_AUTH_HEADER", "").strip()
        if not header:
            raise RuntimeTargetError("API-key runtime authentication requires SECURITY_SCAN_RUNTIME_AUTH_HEADER.")
        metadata["header"] = header
    return metadata


def load_runtime_target() -> dict[str, Any] | None:
    target_value = os.environ.get("SECURITY_SCAN_RUNTIME_TARGET")
    passive = os.environ.get("SECURITY_SCAN_ENABLE_PASSIVE_RUNTIME_ANALYSIS", "").lower() == "true"
    active = os.environ.get("SECURITY_SCAN_ENABLE_ACTIVE_DAST", "").lower() == "true"
    if not target_value and not passive and not active:
        return None
    if (passive or active) and not target_value:
        raise RuntimeTargetError("Runtime target is required when passive or active runtime analysis is enabled.")
    target = normalize_runtime_target(target_value or "")
    auth = _auth_metadata()
    base_path = target["basePath"]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "target": target,
        "authorization": {"passive": passive, "active": active},
        "scope": {
            "origins": [target["origin"]],
            "paths": [base_path],
            "redirectPolicy": "same-origin",
            "linkDiscovery": "same-origin",
        },
        "authentication": auth,
        "execution": {"passive": "not_started", "active": "not_started"},
    }


def validate_runtime_target(document: dict[str, Any]) -> None:
    if not isinstance(document, dict) or document.get("schemaVersion") != SCHEMA_VERSION:
        raise RuntimeTargetError("Unsupported runtime-target schema version.")
    target = document.get("target")
    if not isinstance(target, dict):
        raise RuntimeTargetError("Runtime target metadata is malformed.")
    normalized = normalize_runtime_target(_target_url(target))
    if {key: target.get(key) for key in ("scheme", "host", "port", "basePath", "targetId")} != {key: normalized.get(key) for key in ("scheme", "host", "port", "basePath", "targetId")}:
        raise RuntimeTargetError("Runtime target identity is not normalized.")
    if target.get("origin") != normalized["origin"]:
        raise RuntimeTargetError("Runtime target origin is inconsistent.")
    authorization = document.get("authorization")
    if not isinstance(authorization, dict) or not isinstance(authorization.get("passive"), bool) or not isinstance(authorization.get("active"), bool):
        raise RuntimeTargetError("Runtime authorization metadata is malformed.")
    scope = document.get("scope")
    if not isinstance(scope, dict) or scope.get("origins") != [normalized["origin"]] or scope.get("paths") != [normalized["basePath"]] or scope.get("redirectPolicy") != "same-origin":
        raise RuntimeTargetError("Runtime scope metadata is inconsistent.")
    auth = document.get("authentication")
    if not isinstance(auth, dict) or auth.get("mode") not in SUPPORTED_AUTH or not isinstance(auth.get("configured"), bool):
        raise RuntimeTargetError("Runtime authentication metadata is malformed.")
    if auth.get("mode") != "none" and not auth.get("configured"):
        raise RuntimeTargetError("Configured runtime authentication must not be incomplete.")
    if auth.get("mode") == "api_key" and not auth.get("header"):
        raise RuntimeTargetError("API-key runtime authentication is missing its header.")


def _target_url(target: dict[str, Any]) -> str:
    scheme = target.get("scheme", "")
    host = target.get("host", "")
    port = target.get("port", "")
    path = target.get("basePath", "/")
    display_host = f"[{host}]" if ":" in str(host) and not str(host).startswith("[") else host
    return f"{scheme}://{display_host}:{port}{path}"

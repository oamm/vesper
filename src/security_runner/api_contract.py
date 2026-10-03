import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


class ApiContractError(ValueError):
    pass


MAX_BYTES = 8 * 1024 * 1024
MAX_PATHS = 2000
MAX_OPERATIONS = 5000
MAX_TEXT = 4000


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return str(value)[:limit] if value is not None else ""


def _ref(value: Any) -> str | None:
    return _text(value) if isinstance(value, str) and value.startswith("#/") else None


def _schema(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    if "$ref" in value:
        result["ref"] = _ref(value["$ref"]) or "external_ref_unresolved"
    for key in ("type", "format", "nullable"):
        if key in value and isinstance(value[key], (str, bool)):
            result[key] = value[key]
    return result or None


def _parameters(values: Any) -> list[dict[str, Any]]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ApiContractError("OpenAPI parameters must be an array.")
    normalized = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        if not isinstance(item, dict):
            raise ApiContractError("OpenAPI parameter must be an object.")
        if "$ref" in item:
            normalized.append({"ref": _ref(item["$ref"]) or "external_ref_unresolved"})
            continue
        name, location = item.get("name"), item.get("in")
        if not isinstance(name, str) or not isinstance(location, str) or location not in {"path", "query", "header", "cookie"}:
            raise ApiContractError("OpenAPI parameter requires a valid name and location.")
        key = (location, name)
        if key in seen:
            continue
        seen.add(key)
        normalized.append({
            "name": name,
            "in": location,
            "required": bool(item.get("required", False)),
            "schema": _schema(item.get("schema")),
        })
    return sorted(normalized, key=lambda item: (item.get("in", ""), item.get("name", ""), item.get("ref", "")))


def _content(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    return [{"contentType": str(key), "schema": _schema(item.get("schema")) if isinstance(item, dict) else None}
            for key, item in sorted(value.items()) if isinstance(key, str)]


def normalize_contract(document: Any, source: str, digest: str, fmt: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ApiContractError("OpenAPI document root must be an object.")
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise ApiContractError("Only OpenAPI 3.x contracts are supported.")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ApiContractError("OpenAPI document must contain a paths object.")
    if len(paths) > MAX_PATHS:
        raise ApiContractError("OpenAPI path count exceeds the configured limit.")
    schemes = []
    raw_schemes = ((document.get("components") or {}).get("securitySchemes") if isinstance(document.get("components"), dict) else {})
    if isinstance(raw_schemes, dict):
        for name, value in sorted(raw_schemes.items()):
            if not isinstance(value, dict):
                raise ApiContractError("OpenAPI security scheme must be an object.")
            scheme = {key: _text(value[key]) for key in ("type", "scheme", "bearerFormat", "in", "name", "openIdConnectUrl") if key in value}
            scheme["name"] = name
            schemes.append(scheme)
    global_security = document.get("security")
    if global_security is not None and not isinstance(global_security, list):
        raise ApiContractError("OpenAPI security must be an array.")
    operations = []
    methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    for path, path_item in sorted(paths.items()):
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise ApiContractError("OpenAPI paths must map valid templates to objects.")
        inherited = _parameters(path_item.get("parameters"))
        for method, operation in sorted(path_item.items()):
            if method.lower() not in methods:
                continue
            if not isinstance(operation, dict):
                raise ApiContractError("OpenAPI operation must be an object.")
            parameters = _parameters(inherited + _parameters(operation.get("parameters")))
            responses = operation.get("responses")
            if not isinstance(responses, dict):
                raise ApiContractError("OpenAPI operation must define responses.")
            response_list = []
            for code, response in sorted(responses.items()):
                if not isinstance(response, dict):
                    raise ApiContractError("OpenAPI response must be an object.")
                response_list.append({"status": str(code), "content": _content(response.get("content")), "ref": _ref(response.get("$ref"))})
            security = operation.get("security", global_security)
            if security is not None and not isinstance(security, list):
                raise ApiContractError("OpenAPI operation security must be an array.")
            if security == []:
                auth = "public"
            elif security is None:
                auth = "unknown"
            else:
                auth = "authenticated"
            operations.append({
                "id": f"{method.upper()} {path}",
                "method": method.upper(),
                "path": path,
                "operationId": operation.get("operationId") if isinstance(operation.get("operationId"), str) else None,
                "parameters": parameters,
                "requestBody": {"required": bool(operation["requestBody"].get("required", False)), "content": _content(operation["requestBody"].get("content"))} if isinstance(operation.get("requestBody"), dict) else None,
                "responses": response_list,
                "security": security if isinstance(security, list) else None,
                "authentication": auth,
            })
            if len(operations) > MAX_OPERATIONS:
                raise ApiContractError("OpenAPI operation count exceeds the configured limit.")
    servers = [{"url": _text(item.get("url")), "description": _text(item.get("description"))} for item in document.get("servers", []) if isinstance(item, dict) and isinstance(item.get("url"), str)]
    return {
        "schemaVersion": 1,
        "apiIdentityVersion": 1,
        "contract": {"format": fmt, "version": version, "source": source, "contentDigest": digest, "title": _text((document.get("info") or {}).get("title")) if isinstance(document.get("info"), dict) else "", "documentVersion": _text((document.get("info") or {}).get("version")) if isinstance(document.get("info"), dict) else ""},
        "servers": sorted(servers, key=lambda item: item["url"]),
        "securitySchemes": schemes,
        "operations": sorted(operations, key=lambda item: item["id"]),
        "coverage": {"assessment": "complete", "contractCoverage": "complete", "runtimeOperationCoverage": "not_applicable", "unresolvedExternalRefs": []},
    }


def load_contract(workspace: Path, requested: str | None = None) -> tuple[dict[str, Any] | None, Path | None, str]:
    candidates = [requested] if requested else ["openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"]
    source = next((workspace / item for item in candidates if item and not Path(item).is_absolute() and (workspace / item).is_file()), None)
    if requested and source is None:
        raise ApiContractError("Configured API contract was not found inside the workspace.")
    if source is None:
        return None, None, "not_found"
    resolved = source.resolve()
    if workspace.resolve() not in resolved.parents and resolved != workspace.resolve():
        raise ApiContractError("API contract path escapes the workspace.")
    if source.stat().st_size > MAX_BYTES:
        raise ApiContractError("API contract exceeds the configured size limit.")
    raw_bytes = source.read_bytes()
    try:
        document = json.loads(raw_bytes) if source.suffix.lower() == ".json" else yaml.safe_load(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ApiContractError(f"API contract could not be parsed: {exc}") from exc
    fmt = "json" if source.suffix.lower() == ".json" else "yaml"
    return normalize_contract(document, source.relative_to(workspace).as_posix(), hashlib.sha256(raw_bytes).hexdigest(), fmt), source, "available"

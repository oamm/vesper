import hashlib
import json
import re
from typing import Any


COMPONENT_SCHEMA_VERSION = 1
MAX_COMPONENTS = 100_000
MAX_OCCURRENCES = 100_000
MAX_STRING_LENGTH = 1_024


class ComponentError(ValueError):
    pass


def normalize_components(raw: dict[str, Any], raw_output: str) -> dict[str, Any]:
    components = raw.get("components")
    if not isinstance(components, list):
        raise ComponentError("Syft CycloneDX components must be an array.")
    if len(components) > MAX_COMPONENTS:
        raise ComponentError("Syft component count exceeds the report limit.")

    by_identity: dict[str, dict[str, Any]] = {}
    occurrence_count = 0
    for native in components:
        if not isinstance(native, dict):
            raise ComponentError("Syft component entries must be objects.")
        normalized = _normalize_component(native)
        occurrence_count += len(normalized["occurrences"])
        if occurrence_count > MAX_OCCURRENCES:
            raise ComponentError("Syft occurrence count exceeds the report limit.")
        existing = by_identity.get(normalized["id"])
        if existing is None:
            by_identity[normalized["id"]] = normalized
            continue
        existing["occurrences"] = _merge_occurrences(existing["occurrences"], normalized["occurrences"])
        existing["evidence"] = _merge_evidence(existing["evidence"], normalized["evidence"])
        existing["licenses"] = _merge_strings(existing.get("licenses", []), normalized.get("licenses", []))

    normalized_components = sorted(by_identity.values(), key=lambda item: item["id"])
    for component in normalized_components:
        component["occurrences"].sort(key=lambda item: (item["path"], item.get("source", "")))
        component["evidence"].sort(key=lambda item: (item["scanner"], item.get("source", ""), item.get("nativeRef", "")))
        if component.get("licenses"):
            component["licenses"].sort()

    spec_version = raw.get("specVersion")
    if not isinstance(spec_version, str) or not spec_version:
        raise ComponentError("Syft CycloneDX specVersion is missing.")
    return {
        "schemaVersion": COMPONENT_SCHEMA_VERSION,
        "format": "CycloneDX",
        "specVersion": spec_version[:MAX_STRING_LENGTH],
        "rawOutput": raw_output,
        "components": normalized_components,
    }


def component_summary(inventory: dict[str, Any]) -> dict[str, Any]:
    components = inventory.get("components")
    if not isinstance(components, list):
        raise ComponentError("Component inventory is missing its component list.")
    ecosystems: dict[str, int] = {}
    occurrences = 0
    for component in components:
        ecosystem = component.get("ecosystem", "unknown")
        ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
        occurrences += len(component.get("occurrences", []))
    return {
        "total": len(components),
        "unique": len(components),
        "occurrences": occurrences,
        "ecosystems": dict(sorted(ecosystems.items())),
    }


def validate_component_inventory(inventory: Any) -> dict[str, Any]:
    if not isinstance(inventory, dict) or inventory.get("schemaVersion") != COMPONENT_SCHEMA_VERSION:
        raise ComponentError("Unsupported or malformed component inventory schema.")
    components = inventory.get("components")
    if not isinstance(components, list):
        raise ComponentError("Component inventory must contain a components array.")
    ids: set[str] = set()
    occurrences: set[tuple[str, str]] = set()
    for component in components:
        if not isinstance(component, dict) or not isinstance(component.get("id"), str):
            raise ComponentError("Component inventory entries must have an ID.")
        if component["id"] in ids:
            raise ComponentError("Component inventory IDs are duplicated.")
        ids.add(component["id"])
        if not isinstance(component.get("occurrences"), list):
            raise ComponentError("Component occurrences must be an array.")
        for occurrence in component["occurrences"]:
            if not isinstance(occurrence, dict) or not isinstance(occurrence.get("path"), str):
                raise ComponentError("Component occurrence paths are malformed.")
            path = occurrence["path"]
            if not path or path.startswith("/") or re.match(r"^[A-Za-z]:/", path) or ".." in path.split("/"):
                raise ComponentError("Component occurrence paths must be project-relative.")
            key = (component["id"], path)
            if key in occurrences:
                raise ComponentError("Component occurrence entries are duplicated.")
            occurrences.add(key)
    return inventory


def _normalize_component(native: dict[str, Any]) -> dict[str, Any]:
    name = _bounded_text(native.get("name"), "name")
    version = _bounded_text(native.get("version"), "version") or "unknown"
    if not name:
        raise ComponentError("Syft components require a name.")
    purl = _bounded_text(native.get("purl"), "purl") or None
    ecosystem = _ecosystem(purl, native)
    identity_source = purl.casefold() if purl else f"{ecosystem.casefold()}|{name.casefold()}|{version}"
    component_id = "component-" + hashlib.sha256(identity_source.encode("utf-8")).hexdigest()
    occurrences = _extract_occurrences(native)
    evidence = [{
        "scanner": "syft",
        "source": "raw/syft.cdx.json",
        **({"nativeRef": _bounded_text(native.get("bom-ref"), "bom-ref")} if native.get("bom-ref") else {}),
        **({"foundBy": _bounded_text(_property(native, "syft:package:foundBy"), "foundBy")} if _property(native, "syft:package:foundBy") else {}),
    }]
    licenses = _extract_licenses(native)
    result = {
        "id": component_id,
        "type": _bounded_text(native.get("type"), "type") or "library",
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        **({"purl": purl} if purl else {}),
        "occurrences": occurrences,
        "evidence": evidence,
    }
    if licenses:
        result["licenses"] = licenses
    return result


def _extract_occurrences(native: dict[str, Any]) -> list[dict[str, str]]:
    values: list[Any] = []
    evidence = native.get("evidence")
    if isinstance(evidence, dict):
        values.extend(evidence.get("occurrences") or [])
    values.extend(native.get("locations") or [])
    if native.get("type") == "file" and isinstance(native.get("name"), str) and native["name"].startswith("/"):
        values.append(native["name"])
    for prop in native.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str) and prop["name"].startswith("syft:location:"):
            values.append(prop.get("value"))
    result = []
    for value in values:
        location = value.get("location") if isinstance(value, dict) and "location" in value else value
        path = location.get("path") if isinstance(location, dict) else location
        if isinstance(path, str) and path:
            normalized = _normalize_path(path)
            result.append({"path": normalized})
    return _merge_occurrences([], result)


def _extract_licenses(native: dict[str, Any]) -> list[str]:
    licenses = native.get("licenses")
    values: list[str] = []
    if isinstance(licenses, list):
        for entry in licenses:
            if not isinstance(entry, dict):
                continue
            license_data = entry.get("license")
            if isinstance(license_data, dict):
                value = license_data.get("id") or license_data.get("name")
                if isinstance(value, str) and value:
                    values.append(_bounded_text(value, "license"))
    return sorted(set(values))


def _ecosystem(purl: str | None, native: dict[str, Any]) -> str:
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].casefold()
    value = _property(native, "syft:package:type") or _property(native, "syft:package:foundBy")
    return _bounded_text(value, "ecosystem").casefold() if value else "unknown"


def _property(native: dict[str, Any], name: str) -> str | None:
    for prop in native.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name and isinstance(prop.get("value"), str):
            return prop["value"]
    return None


def _normalize_path(value: str) -> str:
    path = value.replace("\\", "/")
    if path.startswith("/workspace/"):
        path = path[len("/workspace/"):]
    elif path.startswith("/"):
        path = path[1:]
    elif path.startswith("./"):
        path = path[2:]
    if not path or path.startswith("/") or re.match(r"^[A-Za-z]:/", path) or ".." in path.split("/"):
        raise ComponentError("Syft occurrence path is not project-relative.")
    return _bounded_text(path, "occurrence path")


def _bounded_text(value: Any, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > MAX_STRING_LENGTH:
        raise ComponentError(f"Syft {field} exceeds the report string limit.")
    return value.strip()


def _merge_occurrences(left: list[dict[str, str]], right: list[dict[str, str]]) -> list[dict[str, str]]:
    merged = {(item["path"], item.get("source", "")): item for item in left + right}
    return list(merged.values())


def _merge_evidence(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {json.dumps(item, sort_keys=True): item for item in left + right}
    return list(merged.values())


def _merge_strings(left: list[str], right: list[str]) -> list[str]:
    return sorted(set(left + right))

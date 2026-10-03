"""Bounded passive runtime observation and ZAP evidence normalization."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from security_runner.models import ScannerContext, ScannerResult
from security_runner.normalization import normalize_zap_alerts
from security_runner.runtime_target import RuntimeTargetError, load_runtime_target


MAX_RESOURCES = 25
MAX_DEPTH = 2
MAX_REQUESTS = 50
REQUEST_TIMEOUT = 10
TOTAL_TIMEOUT = 60
MAX_BODY = 1_048_576


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "link", "img", "script", "iframe"}:
            return
        for key, value in attrs:
            if key.lower() in {"href", "src"} and value:
                self.links.append(value[:2000])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        return None


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme.lower() == "https" else 80)


def _in_scope(url: str, target: dict[str, Any]) -> bool:
    scheme, host, port = _origin(url)
    if (scheme, host, port) != (target["scheme"], target["host"], target["port"]):
        return False
    path = urllib.parse.urlsplit(url).path or "/"
    base = target["basePath"]
    return path == base.rstrip("/") or path.startswith(base)


def resource_identity(url: str, method: str, target: dict[str, Any]) -> str:
    parsed = urllib.parse.urlsplit(url)
    path = "/" + "/".join(part for part in parsed.path.split("/") if part not in {"", "."})
    if not path.startswith("/"):
        path = "/" + path
    if path == "":
        path = "/"
    if parsed.path.endswith("/") and path != "/":
        path += "/"
    query_names = sorted({key for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})
    origin = _origin(url)
    identity_value = {"origin": {"scheme": origin[0], "host": origin[1], "port": origin[2]}, "method": method.upper(), "path": path, "queryNames": query_names}
    encoded = json.dumps(identity_value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_headers(headers: Any) -> dict[str, Any]:
    selected = {}
    for name in ("content-type", "content-length", "content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy", "location"):
        value = headers.get(name)
        if value is not None:
            selected[name] = str(value)[:500]
    return selected


def _redact_native(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if str(key).lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie", "requestheader", "responseheader"}:
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = _redact_native(item, secrets)
        return result
    if isinstance(value, list):
        return [_redact_native(item, secrets) for item in value[:500]]
    if isinstance(value, str):
        output = value
        for secret in secrets:
            if secret:
                output = output.replace(secret, "<redacted>")
        parsed = urllib.parse.urlsplit(output)
        if parsed.scheme and parsed.netloc and parsed.query:
            output = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        return output[:2000]
    return value


def _runtime_url(target: dict[str, Any]) -> str:
    host = f"[{target['host']}]" if ":" in target["host"] else target["host"]
    return f"{target['scheme']}://{host}:{target['port']}{target['basePath']}"


def validate_runtime_surface(surface: dict[str, Any], runtime: dict[str, Any]) -> None:
    if not isinstance(surface, dict) or surface.get("schemaVersion") != 1 or surface.get("targetId") != runtime.get("target", {}).get("targetId"):
        raise ValueError("Runtime surface schema or target linkage is invalid.")
    resources = surface.get("resources")
    if not isinstance(resources, list):
        raise ValueError("Runtime surface resources are malformed.")
    identities = [item.get("identity") for item in resources if isinstance(item, dict)]
    if len(identities) != len(set(identities)) or None in identities:
        raise ValueError("Runtime surface resource identities must be unique.")
    if any(item.get("state") in {"observed", "auth_limited", "auth_failed"} and not _in_scope(_resource_url(item, runtime["target"]), runtime["target"]) for item in resources if isinstance(item, dict)):
        raise ValueError("Runtime surface contains an observed resource outside target scope.")


def _resource_url(resource: dict[str, Any], target: dict[str, Any]) -> str:
    host = f"[{target['host']}]" if ":" in target["host"] else target["host"]
    return f"{target['scheme']}://{host}:{target['port']}{resource.get('path', '/')}"


def _auth_headers(runtime: dict[str, Any]) -> dict[str, str]:
    auth = runtime.get("authentication", {})
    source = auth.get("source", {})
    env_name = source.get("name")
    value = os.environ.get(env_name, "") if env_name else ""
    if not value:
        return {}
    if auth.get("mode") == "bearer":
        return {"Authorization": f"Bearer {value}"}
    if auth.get("mode") == "api_key":
        return {str(auth.get("header")): value}
    if auth.get("mode") == "cookie_session":
        return {"Cookie": value}
    return {}


def _zap_url(port: int, endpoint: str) -> str:
    return f"http://127.0.0.1:{port}/JSON/{endpoint}"


def _zap_json(port: int, endpoint: str, timeout: float = 5) -> dict[str, Any]:
    with urllib.request.urlopen(_zap_url(port, endpoint), timeout=timeout) as response:
        value = json.loads(response.read(2_000_000).decode("utf-8", "replace"))
    if not isinstance(value, dict):
        raise RuntimeError("ZAP API returned an unsupported response envelope.")
    return value


def _start_zap(timeout: int) -> tuple[subprocess.Popen[str], int, str]:
    port = 18080 + (os.getpid() % 1000)
    zap_dir = tempfile.mkdtemp(prefix="vesper-zap-")
    command = [
        "/opt/zap/zap.sh", "-daemon", "-dir", zap_dir, "-host", "127.0.0.1", "-port", str(port),
        "-config", "api.disablekey=true", "-config", "api.addrs.addr.name=127.0.0.1",
        "-config", "api.addrs.addr.regex=false", "-config", "scanner.enabled=false",
    ]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    deadline = time.monotonic() + min(timeout, 30)
    while time.monotonic() < deadline:
        try:
            _zap_json(port, "core/view/version/", 1)
            return process, port, zap_dir
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            if process.poll() is not None:
                raise RuntimeError("ZAP passive process exited during startup.")
            time.sleep(0.25)
    process.terminate()
    shutil.rmtree(zap_dir, ignore_errors=True)
    raise RuntimeError("ZAP passive process did not become ready.")


def run_passive(runtime: dict[str, Any], raw_dir: Path, timeout: int) -> tuple[dict[str, Any], dict[str, Any]]:
    target = runtime["target"]
    max_resources = int(os.environ.get("SECURITY_SCAN_RUNTIME_MAX_RESOURCES", MAX_RESOURCES))
    max_depth = int(os.environ.get("SECURITY_SCAN_RUNTIME_MAX_DEPTH", MAX_DEPTH))
    max_requests = int(os.environ.get("SECURITY_SCAN_RUNTIME_MAX_REQUESTS", MAX_REQUESTS))
    request_timeout = float(os.environ.get("SECURITY_SCAN_RUNTIME_REQUEST_TIMEOUT", REQUEST_TIMEOUT))
    started = time.monotonic()
    process, port, zap_dir = _start_zap(timeout)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}))
    queue: list[tuple[str, str, int]] = [(_runtime_url(target), "seed", 0)]
    seen: set[str] = set()
    resources: list[dict[str, Any]] = []
    requests = 0
    failures = 0
    try:
        while queue and len(resources) < max_resources and requests < max_requests and time.monotonic() - started < min(timeout, TOTAL_TIMEOUT):
            url, source, depth = queue.pop(0)
            key = resource_identity(url, "GET", target)
            if key in seen:
                continue
            seen.add(key)
            if not _in_scope(url, target):
                resources.append({"identity": key, "method": "GET", "path": urllib.parse.urlsplit(url).path or "/", "source": source, "state": "out_of_scope"})
                continue
            requests += 1
            record: dict[str, Any] = {"identity": key, "method": "GET", "path": urllib.parse.urlsplit(url).path or "/", "source": source, "state": "failed"}
            try:
                auth_headers = _auth_headers(runtime)
                request = urllib.request.Request(url, headers={"User-Agent": "Vesper-passive/1", **auth_headers}, method="GET")
                response = opener.open(request, timeout=request_timeout)
                body = response.read(MAX_BODY + 1)
                content_type = response.headers.get("content-type", "")
                state = "auth_limited" if response.status in {401, 403} and not auth_headers else "auth_failed" if response.status in {401, 403} else "observed"
                record.update({"state": state, "status": response.status, "contentType": content_type.split(";", 1)[0].strip().lower(), "headers": _safe_headers(response.headers), "responseTruncated": len(body) > MAX_BODY})
                if depth < max_depth and len(body) <= MAX_BODY and "html" in content_type.lower():
                    parser = _Links()
                    parser.feed(body[:MAX_BODY].decode("utf-8", "replace"))
                    for link in sorted(set(parser.links)):
                        candidate = urllib.parse.urljoin(url, link)
                        if _in_scope(candidate, target):
                            queue.append((candidate, "html_link", depth + 1))
                        else:
                            resources.append({"identity": resource_identity(candidate, "GET", target), "method": "GET", "path": urllib.parse.urlsplit(candidate).path or "/", "source": "html_link", "state": "out_of_scope"})
                location = response.headers.get("location")
                if location:
                    candidate = urllib.parse.urljoin(url, location)
                    if _in_scope(candidate, target) and depth < max_depth:
                        queue.append((candidate, "redirect", depth + 1))
                    elif not _in_scope(candidate, target):
                        record["redirect"] = {"target": urllib.parse.urlsplit(candidate).path or "", "scopeDecision": "blocked"}
            except urllib.error.HTTPError as exc:
                auth_headers = _auth_headers(runtime)
                state = "auth_limited" if exc.code in {401, 403} and not auth_headers else "auth_failed" if exc.code in {401, 403} else "observed"
                record.update({"state": state, "status": exc.code, "contentType": (exc.headers.get("content-type", "") or "").split(";", 1)[0].strip().lower(), "headers": _safe_headers(exc.headers)})
            except (OSError, urllib.error.URLError, TimeoutError):
                failures += 1
            resources.append(record)
        time.sleep(0.25)
        for _ in range(20):
            pending = _zap_json(port, "pscan/view/recordsToScan/").get("recordsToScan", "0")
            if str(pending) in {"0", "0.0"}:
                break
            time.sleep(0.25)
        alerts = _zap_json(port, "core/view/alerts/").get("alerts", [])
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(zap_dir, ignore_errors=True)
    surface = {
        "schemaVersion": 1,
        "targetId": target["targetId"],
        "resources": sorted(resources, key=lambda item: (item.get("path", ""), item.get("method", ""), item.get("identity", ""))),
        "summary": {"discovered": len(resources), "requested": requests, "observed": sum(item.get("state") in {"observed", "auth_failed"} for item in resources), "authLimited": sum(item.get("state") == "auth_limited" for item in resources), "failed": failures, "outOfScope": sum(item.get("state") == "out_of_scope" for item in resources), "assessment": "partial"},
        "limits": {"maxResources": max_resources, "maxDepth": max_depth, "maxRequests": max_requests, "requestTimeoutSeconds": request_timeout, "truncated": bool(queue or len(resources) >= max_resources or requests >= max_requests)},
    }
    auth_source = runtime.get("authentication", {}).get("source", {}).get("name")
    secrets = [os.environ.get(auth_source, "")] if auth_source else []
    native = _redact_native({"zapVersion": "2.17.0", "passiveOnly": True, "activeScannerInvoked": False, "alerts": alerts, "observations": resources}, secrets)
    surface["summary"]["alerts"] = len(alerts)
    return native, surface


def execute_passive(context: ScannerContext) -> tuple[ScannerResult, list[dict[str, Any]], dict[str, Any]]:
    started = time.monotonic()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw_path = context.raw_dir / "zap-passive.json"
    try:
        runtime = load_runtime_target()
        if not runtime or not runtime["authorization"]["passive"]:
            result = ScannerResult("zap-passive", "not-applicable", "not_applicable", started_at, started_at, 0, "raw/zap-passive.json", reason="Passive runtime analysis was not explicitly authorized.", reason_code="passive_runtime_not_requested", coverage={"assessment": "not_applicable"})
            raw_path.write_text(json.dumps({"passiveOnly": True, "alerts": []}) + "\n", encoding="utf-8")
            return result, [], {"schemaVersion": 1, "targetId": "", "resources": [], "summary": {"assessment": "not_applicable"}}
        native, surface = run_passive(runtime, context.raw_dir, context.timeout_seconds)
        raw_path.write_text(json.dumps(native, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        findings = normalize_zap_alerts(native.get("alerts", []), surface, runtime)
        result = ScannerResult("zap-passive", native.get("zapVersion", "2.17.0"), "completed_with_findings" if findings else "clean", started_at, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), int((time.monotonic() - started) * 1000), "raw/zap-passive.json", finding_count=len(findings), coverage={"assessment": surface["summary"]["assessment"], **surface["summary"], "passiveOnly": True})
        return result, findings, surface
    except Exception as exc:
        raw_path.write_text(json.dumps({"passiveOnly": True, "error": str(exc)[:500]}) + "\n", encoding="utf-8")
        result = ScannerResult("zap-passive", "unavailable", "failed", started_at, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), int((time.monotonic() - started) * 1000), "raw/zap-passive.json", error=str(exc)[:500], reason_code="passive_runtime_failed", coverage={"assessment": "unknown", "passiveOnly": True})
        return result, [], {"schemaVersion": 1, "targetId": "", "resources": [], "summary": {"assessment": "unknown"}}

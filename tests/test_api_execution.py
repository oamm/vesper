import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from security_runner.api_contract import load_contract
from security_runner.api_execution import ApiExecutionError, execute_contract, normalize_target
from security_runner.normalization import normalize_api_behavior


class _FixtureHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    force_500 = False
    wrong_schema = False
    redirect = False

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        self.requests.append((self.path, authorization))
        if self.redirect:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/out-of-scope")
            self.end_headers()
            return
        if self.force_500:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"fixture failure"}')
            return
        if self.path.startswith("/loans/") and authorization != "Bearer fixture-token":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"auth required"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.path == "/health" and not self.wrong_schema:
            self.wfile.write(b'{"ok":true}')
        elif self.path == "/health":
            self.wfile.write(b'{"ok":"wrong"}')
        else:
            self.wfile.write(b'{"id":"fixture","status":"ok"}')

    def log_message(self, *_args):
        return


class ApiExecutionTests(unittest.TestCase):
    fixture = Path(__file__).parent / "fixtures" / "api-contract" / "openapi.yaml"

    def setUp(self):
        _FixtureHandler.requests = []
        _FixtureHandler.force_500 = False
        _FixtureHandler.wrong_schema = False
        _FixtureHandler.redirect = False
        self.server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)

    def _run(self, bearer_env=None, target=None):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract, source, _ = load_contract(self.fixture.parent, "openapi.yaml")
            output = root / "api-execution.json"
            raw = root / "schemathesis.json"
            env = {"FIXTURE_TOKEN": "fixture-token"} if bearer_env else {}
            with patch.dict(os.environ, env, clear=False):
                result, _ = execute_contract(
                    source,
                    contract,
                    output,
                    raw,
                    target or f"http://127.0.0.1:{self.server.server_port}",
                    1,
                    2,
                    5,
                    30,
                    "read-only",
                    bearer_env,
                    None,
                    None,
                )
            return result, output.read_text(encoding="utf-8"), raw.read_text(encoding="utf-8")

    def _run_with_fixture_mode(self, *, force_500=False, wrong_schema=False, redirect=False):
        _FixtureHandler.force_500 = force_500
        _FixtureHandler.wrong_schema = wrong_schema
        _FixtureHandler.redirect = redirect
        return self._run()

    def test_target_requires_safe_http_origin(self):
        target = normalize_target("HTTPS://Example.test:8443/api")
        self.assertEqual(target["scheme"], "https")
        self.assertEqual(target["host"], "example.test")
        self.assertEqual(target["basePath"], "/api/")
        for value in ("ftp://example.test", "https://user:pass@example.test", "https://example.test?a=1"):
            with self.assertRaises(ApiExecutionError):
                normalize_target(value)

    def test_real_schemathesis_execution_records_auth_limited_runtime_coverage(self):
        result, artifact, raw = self._run()
        self.assertEqual(result["summary"]["authLimited"], 1)
        self.assertEqual(result["summary"]["requests"], 2)
        self.assertEqual(result["target"]["host"], "127.0.0.1")
        self.assertNotIn("fixture-token", artifact)
        self.assertNotIn("fixture-token", raw)
        self.assertTrue(all(path.startswith("/") for path, _ in _FixtureHandler.requests))

    def test_real_schemathesis_execution_uses_secure_bearer_environment_source(self):
        result, artifact, raw = self._run("FIXTURE_TOKEN")
        self.assertEqual(result["summary"]["authLimited"], 0)
        self.assertEqual(result["summary"]["exercised"], 2)
        self.assertNotIn("fixture-token", artifact)
        self.assertNotIn("fixture-token", raw)
        self.assertIn(("Bearer fixture-token"), [header for path, header in _FixtureHandler.requests if path.startswith("/loans/")])

    def test_unexpected_5xx_is_candidate_runtime_evidence(self):
        result, _, _ = self._run_with_fixture_mode(force_500=True)
        self.assertGreaterEqual(result["summary"]["failed"], 1)
        self.assertTrue(any(event.get("classification") == "unexpected_5xx" for event in result["events"]))

    def test_schema_mismatch_is_candidate_runtime_evidence(self):
        result, _, _ = self._run_with_fixture_mode(wrong_schema=True)
        self.assertTrue(any(event.get("classification") == "response_schema_violation" for event in result["events"]))

    def test_cross_origin_redirect_is_not_followed(self):
        result, _, _ = self._run_with_fixture_mode(redirect=True)
        self.assertEqual(result["summary"]["requests"], 2)
        self.assertTrue(all(path != "/out-of-scope" for path, _ in _FixtureHandler.requests))

    def test_behavioral_events_deduplicate_and_exclude_auth_limitations(self):
        result, _, _ = self._run_with_fixture_mode(force_500=True)
        contract, _, _ = load_contract(self.fixture.parent, "openapi.yaml")
        result["events"].append({"operation": "GET /loans/{id}", "classification": "auth_limited", "status": 401})
        result["events"].append({"operation": "GET /health", "classification": "unexpected_5xx", "status": 500, "path": "/health?second=case", "caseId": "second"})
        findings = normalize_api_behavior(result, contract)
        self.assertEqual(len(findings), 2)
        self.assertEqual({finding["type"] for finding in findings}, {"unexpected_5xx"})
        self.assertTrue(all(finding["category"] == "api_behavior" for finding in findings))
        self.assertEqual(next(item for item in findings if item["behaviorEvidence"]["operation"] == "GET /health")["behaviorEvidence"]["candidateCount"], 2)

    def test_behavior_identity_does_not_include_target_or_case_values(self):
        contract, _, _ = load_contract(self.fixture.parent, "openapi.yaml")
        base = {
            "contract": {"contentDigest": "digest", "apiIdentityVersion": 1},
            "events": [{"operation": "GET /health", "classification": "unexpected_5xx", "status": 500, "path": "/health?x=1", "caseId": "a"}],
        }
        other = {**base, "events": [{"operation": "GET /health", "classification": "unexpected_5xx", "status": 500, "path": "/health?x=99", "caseId": "b"}]}
        self.assertEqual(normalize_api_behavior(base, contract)[0]["fingerprint"], normalize_api_behavior(other, contract)[0]["fingerprint"])

    def test_network_failure_remains_execution_evidence(self):
        result, _, _ = self._run(target="http://127.0.0.1:9")
        self.assertEqual(result["summary"]["failed"], 2)
        self.assertFalse(normalize_api_behavior(result, load_contract(self.fixture.parent, "openapi.yaml")[0]))


if __name__ == "__main__":
    unittest.main()

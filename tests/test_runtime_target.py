import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_runner.runtime_target import RuntimeTargetError, load_runtime_target, normalize_runtime_target, validate_runtime_target
from security_runner.runner import run_scan


class RuntimeTargetTests(unittest.TestCase):
    def test_normalizes_identity_and_scope_without_network(self):
        target = normalize_runtime_target("HTTPS://Example.Test:443/admin")
        self.assertEqual(target["scheme"], "https")
        self.assertEqual(target["host"], "example.test")
        self.assertEqual(target["port"], 443)
        self.assertEqual(target["basePath"], "/admin/")
        self.assertEqual(target["origin"], {"scheme": "https", "host": "example.test", "port": 443})

    def test_rejects_credentials_query_fragment_and_unsupported_schemes(self):
        for value in ("https://user:secret@example.test", "https://example.test/?token=x", "https://example.test/#x", "ftp://example.test"):
            with self.subTest(value=value), self.assertRaises(RuntimeTargetError):
                normalize_runtime_target(value)

    def test_authorization_requires_target_but_target_alone_is_passive_configuration(self):
        with patch.dict(os.environ, {"SECURITY_SCAN_RUNTIME_TARGET": "http://fixture.test:8080", "SECURITY_SCAN_ENABLE_PASSIVE_RUNTIME_ANALYSIS": "false", "SECURITY_SCAN_ENABLE_ACTIVE_DAST": "false"}, clear=False):
            target = load_runtime_target()
        self.assertFalse(target["authorization"]["passive"])
        self.assertEqual(target["execution"]["passive"], "not_started")
        with patch.dict(os.environ, {"SECURITY_SCAN_ENABLE_PASSIVE_RUNTIME_ANALYSIS": "true"}, clear=True), self.assertRaises(RuntimeTargetError):
            load_runtime_target()

    def test_m4_flags_do_not_authorize_m5(self):
        with patch.dict(os.environ, {"SECURITY_SCAN_ENABLE_API_TESTING": "true", "SECURITY_SCAN_API_TARGET": "http://api.test"}, clear=True):
            self.assertIsNone(load_runtime_target())

    def test_auth_metadata_never_contains_secret_value(self):
        with patch.dict(os.environ, {"SECURITY_SCAN_RUNTIME_TARGET": "https://example.test", "SECURITY_SCAN_RUNTIME_AUTH_MODE": "bearer", "SECURITY_SCAN_RUNTIME_AUTH_ENV": "VESPER_SENTINEL", "VESPER_SENTINEL": "do-not-persist"}, clear=True):
            target = load_runtime_target()
        encoded = json.dumps(target)
        self.assertNotIn("do-not-persist", encoded)
        self.assertIn("VESPER_SENTINEL", encoded)

    def test_runner_emits_passive_artifact_without_traffic_or_findings(self):
        config = {"policy": {"failOn": [], "failOnSecrets": False, "maxHigh": None}, "baseline": {"failOnNew": ["high"]}, "timeouts": {}, "scanner": {"trivy": {"enabled": False}, "osv": {"enabled": False}, "sast": {"enabled": False}}}
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            output = Path(temporary) / "output"
            env = {"SECURITY_SCAN_RUNTIME_TARGET": "https://production.example.invalid", "SECURITY_SCAN_ENABLE_PASSIVE_RUNTIME_ANALYSIS": "true"}
            with patch.dict(os.environ, env, clear=False):
                code, _ = run_scan(workspace, output, config, [])
            artifact = json.loads((output / "runtime-target.json").read_text(encoding="utf-8"))
            scan = json.loads((output / "scan.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 2)
            self.assertEqual(artifact["target"]["host"], "production.example.invalid")
            self.assertEqual(scan["runtimeTarget"]["target"], artifact["target"])
            self.assertEqual(summary["runtimeTarget"]["execution"]["passive"], "not_started")
            self.assertFalse(json.loads((output / "findings.json").read_text(encoding="utf-8")))

    def test_validation_rejects_credential_bearing_artifact(self):
        with patch.dict(os.environ, {"SECURITY_SCAN_RUNTIME_TARGET": "https://example.test", "SECURITY_SCAN_ENABLE_PASSIVE_RUNTIME_ANALYSIS": "true"}, clear=True):
            target = load_runtime_target()
        target["target"]["host"] = "user:password@example.test"
        with self.assertRaises(RuntimeTargetError):
            validate_runtime_target(target)


if __name__ == "__main__":
    unittest.main()

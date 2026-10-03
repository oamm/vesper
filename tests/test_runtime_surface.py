import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_runner.runtime_surface import normalize_zap_alerts, resource_identity, validate_runtime_surface
from security_runner.runtime_target import normalize_runtime_target


class RuntimeSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.runtime = {"target": normalize_runtime_target("https://example.test/app")}

    def test_resource_identity_ignores_query_values_but_keeps_names(self):
        first = resource_identity("https://example.test/app/items?id=1", "GET", self.runtime["target"])
        second = resource_identity("https://example.test/app/items?id=2", "GET", self.runtime["target"])
        other = resource_identity("https://example.test/app/items?slug=x", "GET", self.runtime["target"])
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_zap_alert_normalization_links_to_surface_resource(self):
        path = "/app/page-a"
        resource_id = resource_identity("https://example.test" + path, "GET", self.runtime["target"])
        surface = {"schemaVersion": 1, "targetId": self.runtime["target"]["targetId"], "resources": [{"identity": resource_id, "method": "GET", "path": path, "state": "observed"}], "summary": {}}
        alerts = [{"pluginId": "10021", "alert": "Missing Header", "risk": "Low", "confidence": "2", "url": "https://example.test/app/page-a", "description": "safe description", "solution": "safe fix", "evidence": "x"}]
        findings = normalize_zap_alerts(alerts, surface, self.runtime)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "runtime_passive")
        self.assertEqual(findings[0]["severity"], "low")
        self.assertEqual(findings[0]["runtimeEvidence"]["resourceId"], resource_id)
        self.assertNotIn("https://example.test", findings[0]["fingerprint"])

    def test_surface_validation_rejects_observed_resource_outside_scope(self):
        surface = {"schemaVersion": 1, "targetId": self.runtime["target"]["targetId"], "resources": [{"identity": "x", "method": "GET", "path": "/outside", "state": "observed"}], "summary": {}}
        with self.assertRaises(ValueError):
            validate_runtime_surface(surface, self.runtime)

    def test_surface_validation_accepts_out_of_scope_metadata_only(self):
        surface = {"schemaVersion": 1, "targetId": self.runtime["target"]["targetId"], "resources": [{"identity": "x", "method": "GET", "path": "/outside", "state": "out_of_scope"}], "summary": {}}
        validate_runtime_surface(surface, self.runtime)

    def test_passive_adapter_command_does_not_include_active_scanner(self):
        from security_runner.runtime_surface import _start_zap

        with patch("security_runner.runtime_surface.subprocess.Popen") as popen:
            process = popen.return_value
            process.poll.return_value = None
            with patch("security_runner.runtime_surface._zap_json", side_effect=RuntimeError("stop")), self.assertRaises(RuntimeError):
                _start_zap(1)
            command = popen.call_args.args[0]
            self.assertNotIn("-quickurl", command)
            self.assertNotIn("-activeScan", command)
            self.assertNotIn("fuzzer", " ".join(command).lower())


if __name__ == "__main__":
    unittest.main()

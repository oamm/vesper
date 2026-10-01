import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from security_runner.detection import detect_project
from security_runner.models import ScannerContext, ScannerResult
from security_runner.normalization import deduplicate, normalize, normalize_severity
from security_runner.policy import evaluate
from security_runner.remediations import build_remediations
from security_runner.runner import run_scan
from security_runner.scanners import OsvScanner, SastScanner, TrivyScanner


class DetectionTests(unittest.TestCase):
    def test_detects_mixed_project_and_ignores_build_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "src/App.csproj", "pnpm-lock.yaml", "Dockerfile", "infra/main.tf",
                "deploy/app.yaml", "deploy/service.yaml", "security-results/package-lock.json",
                "obj/ignored.cs",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("apiVersion: apps/v1\nkind: Deployment\n" if name.endswith("app.yaml") else "", encoding="utf-8")
            project = detect_project(root)
            self.assertEqual(project.technologies, [".NET", "Node.js", "pnpm", "Docker", "Terraform", "Kubernetes"])
            self.assertIn("pnpm-lock.yaml", project.lockfiles)
            self.assertNotIn("security-results/package-lock.json", project.artifacts)
            self.assertNotIn("obj/ignored.cs", project.artifacts)

    def test_detects_dotnet_node_docker_terraform_fixture_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("App.csproj", "package.json", "Dockerfile", "main.tf"):
                (root / name).write_text("{}", encoding="utf-8")
            self.assertEqual(detect_project(root).technologies, [".NET", "Node.js", "Docker", "Terraform"])

    def test_custom_nested_output_is_excluded_from_detection_and_scanners(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("print('app')", encoding="utf-8")
            generated = root / "custom-results" / "scan-123" / "Generated.csproj"
            generated.parent.mkdir(parents=True)
            generated.write_text("<Project />", encoding="utf-8")
            project = detect_project(root, {"custom-results"})
            self.assertNotIn(".NET", project.technologies)

            context = ScannerContext(root, root / "custom-results", root / "custom-results" / "raw", project, 5, ["custom-results"])
            trivy_command = TrivyScanner().command(context)
            self.assertIn("custom-results", trivy_command[trivy_command.index("--skip-dirs") + 1])
            self.assertIn("custom-results", SastScanner().command(context))


class NormalizationTests(unittest.TestCase):
    def test_trivy_normalization_severity_and_secret_scrubbing(self):
        raw = {
            "Results": [{"Target": "src/app.py", "Secrets": [{
                "RuleID": "generic-api-key", "Title": "Generic API Key", "Severity": "HIGH",
                "StartLine": 4, "Match": "token = 'ghp_FAKEcredentialvalue123456'",
            }]}],
        }
        finding = normalize("trivy", raw)[0]
        self.assertEqual(finding["category"], "secret")
        self.assertEqual(finding["severity"], "high")
        self.assertNotIn("ghp_FAKEcredentialvalue123456", json.dumps(finding))

    def test_semgrep_normalization_and_fingerprint_stability(self):
        raw = {"results": [{
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "src/app.py", "start": {"line": 8, "col": 3},
            "extra": {"severity": "ERROR", "message": "Unsafe SQL", "lines": "cursor.execute(query)",
                      "metadata": {"cwe": ["CWE-89: SQL Injection"]}},
        }]}
        first = normalize("semgrep", raw)[0]
        second = normalize("semgrep", raw)[0]
        self.assertEqual(first["severity"], "critical")
        self.assertEqual(first["security"]["cwe"], ["CWE-89"])
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_fingerprint_ignores_scan_metadata_and_impact_stays_conservative(self):
        base = {"results": [{
            "check_id": "python.test.dos",
            "path": "src/app.py",
            "start": {"line": 12, "col": 1},
            "extra": {"severity": "WARNING", "message": "Possible denial of service", "metadata": {"cwe": ["CWE-400"]}},
        }]}
        first = normalize("semgrep", base)[0]
        changed_metadata = {**base, "scanTimestamp": "2099-01-01T00:00:00Z", "executionId": "volatile-run-1"}
        second = normalize("semgrep", changed_metadata)[0]
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(first["impact"]["type"], "denial_of_service")
        self.assertEqual(first["reachability"], "unknown")
        self.assertEqual(first["remediationPriority"], "p2")

    def test_snake_case_credential_is_redacted_from_finding_evidence(self):
        raw = {"results": [{
            "check_id": "test.secret",
            "path": "src/app.py",
            "start": {"line": 2, "col": 1},
            "extra": {"severity": "WARNING", "message": "Credential assignment", "lines": "AWS_ACCESS_KEY_ID = 'AKIA1234567890ABCDEF'"},
        }]}
        serialized = json.dumps(normalize("semgrep", raw))
        self.assertNotIn("AKIA1234567890ABCDEF", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_conservative_duplicate_merges_scanner_evidence(self):
        trivy = normalize("trivy", {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2021-44228", "Aliases": [], "PkgName": "log4j-core",
            "InstalledVersion": "2.14.1", "Severity": "CRITICAL",
        }]}]})
        osv = normalize("osv-scanner", {"results": [{"source": {"path": "/workspace/package-lock.json"}, "packages": [{
            "package": {"name": "log4j-core", "version": "2.14.1"},
            "vulnerabilities": [{"id": "OSV-1", "aliases": ["CVE-2021-44228"], "summary": "Issue"}],
        }]}]})
        merged = deduplicate(trivy + osv)
        self.assertEqual(len(merged), 1)
        self.assertEqual({item["scanner"] for item in merged[0]["scannerEvidence"]}, {"trivy", "osv-scanner"})

    def test_cross_scanner_dedup_preserves_both_sources(self):
        trivy = normalize("trivy", {"Results": [{"Target": "packages.lock.json", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-12345", "Aliases": [], "PkgName": "Example.Package",
            "InstalledVersion": "1.0.0", "Severity": "HIGH",
            "PkgIdentifier": {"PURL": "pkg:nuget/Example.Package@1.0.0"},
        }]}]})
        osv = normalize("osv-scanner", {"results": [{"source": {"path": "/workspace/packages.lock.json"}, "packages": [{
            "package": {"name": "Example.Package", "version": "1.0.0", "ecosystem": "NuGet"},
            "vulnerabilities": [{"id": "GHSA-abcd-1234-efgh", "aliases": ["CVE-2024-12345"], "summary": "Issue"}],
        }]}]})
        merged = deduplicate(trivy + osv)
        self.assertEqual(len(merged), 1)
        self.assertEqual({entry["scanner"] for entry in merged[0]["scannerEvidence"]}, {"trivy", "osv-scanner"})
        self.assertEqual(merged[0]["package"]["ecosystem"], "nuget")

    def test_severity_aliases(self):
        self.assertEqual(normalize_severity("warning"), "medium")
        self.assertEqual(normalize_severity("n/a"), "unknown")


class PolicyTests(unittest.TestCase):
    def test_critical_fails_and_low_passes(self):
        policy = {"failOn": ["critical", "high"], "failOnSecrets": False, "maxHigh": None}
        self.assertEqual(evaluate([{"severity": "critical", "category": "sast"}], policy)["status"], "failed")
        self.assertEqual(evaluate([{"severity": "low", "category": "sast"}], policy)["status"], "passed")

    def test_secret_fails_when_configured(self):
        policy = {"failOn": [], "failOnSecrets": True, "maxHigh": None}
        result = evaluate([{"severity": "low", "category": "secret"}], policy)
        self.assertEqual(result["status"], "failed")

    def test_three_high_findings_report_three_blockers(self):
        findings = [
            {"id": f"finding-{index}", "severity": "high", "category": "dependency"}
            for index in range(3)
        ]
        remediations = [{"affectedFindings": [finding["id"]]} for finding in findings]
        result = evaluate(findings, {"failOn": ["high"], "failOnSecrets": False, "maxHigh": None}, remediations)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["blockingFindings"], 3)
        self.assertEqual(result["blockingRemediations"], 3)


class RemediationTests(unittest.TestCase):
    def test_three_dependency_cves_group_as_one_upgrade_action(self):
        vulnerabilities = [
            {"VulnerabilityID": f"CVE-2024-{index:05d}", "PkgName": "BouncyCastle.Cryptography",
             "InstalledVersion": "2.2.1", "FixedVersion": "2.3.1", "Severity": "MEDIUM"}
            for index in range(3)
        ]
        findings = normalize("trivy", {"Results": [{"Target": "Invoice/packages.config", "Vulnerabilities": vulnerabilities}]})
        remediations = build_remediations(findings)
        self.assertEqual(len(findings), 3)
        self.assertEqual(len(remediations), 1)
        self.assertEqual(remediations[0]["type"], "dependency_upgrade")
        self.assertEqual(remediations[0]["priority"], "p2")
        self.assertEqual(remediations[0]["package"]["targetVersion"], "2.3.1")
        self.assertEqual(remediations[0]["findingCount"], 3)

    def test_conflicting_fixed_versions_remain_one_reviewable_action(self):
        findings = []
        for cve, fixed in (("CVE-2024-10001", "2.3.1"), ("CVE-2024-10002", "2.4.0")):
            findings.extend(normalize("trivy", {"Results": [{"Target": "packages.config", "Vulnerabilities": [{
                "VulnerabilityID": cve, "PkgName": "Example.Package", "InstalledVersion": "2.2.1",
                "FixedVersion": fixed, "Severity": "MEDIUM",
            }]}]}))
        remediation = build_remediations(findings)[0]
        self.assertEqual(len(remediation["affectedFindings"]), 2)
        self.assertIsNone(remediation["package"]["targetVersion"])
        self.assertEqual(remediation["package"]["candidateFixedVersions"], ["2.3.1", "2.4.0"])
        self.assertIn("Confirm package constraints", remediation["summary"])

    def test_trivy_multiple_fixed_versions_are_candidates_not_one_target(self):
        finding = normalize("trivy", {"Results": [{"Target": "packages.config", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-10003", "PkgName": "Example.Package", "InstalledVersion": "2.2.1",
            "FixedVersion": "2.3.1, 0.2.4", "Severity": "MEDIUM",
        }]}]})[0]
        remediation = build_remediations([finding])[0]
        self.assertIsNone(remediation["package"]["targetVersion"])
        self.assertEqual(remediation["package"]["candidateFixedVersions"], ["0.2.4", "2.3.1"])

    def test_osv_cvss_numeric_scores_and_vectors(self):
        numeric = normalize("osv-scanner", {"results": [{"source": {"path": "requirements.txt"}, "packages": [{
            "package": {"name": "pkg", "version": "1"},
            "vulnerabilities": [{"id": "OSV-NUM", "severity": [{"type": "CVSS_V3", "score": 9.8}]}],
        }]}]})[0]
        self.assertEqual(numeric["security"]["cvss"], 9.8)
        self.assertEqual(numeric["severity"], "critical")

        numeric_string = normalize("osv-scanner", {"results": [{"source": {"path": "requirements.txt"}, "packages": [{
            "package": {"name": "pkg", "version": "1"},
            "vulnerabilities": [{"id": "OSV-STR", "severity": [{"type": "CVSS_V3", "score": "7.5"}]}],
        }]}]})[0]
        self.assertEqual(numeric_string["security"]["cvss"], 7.5)
        self.assertEqual(numeric_string["severity"], "high")

        for vulnerability_id, vector in (
            ("OSV-V31", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ("OSV-V30", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ("OSV-V2", "AV:N/AC:L/Au:N/C:C/I:C/A:C"),
            ("OSV-BAD", "CVSS:3.1/not-a-vector"),
        ):
            finding = normalize("osv-scanner", {"results": [{"source": {"path": "requirements.txt"}, "packages": [{
                "package": {"name": "pkg", "version": "1"},
                "vulnerabilities": [{"id": vulnerability_id, "severity": [{"type": "CVSS_V3", "score": vector}]}],
            }]}]})[0]
            self.assertEqual(finding["security"]["cvss"], None, vector)
            self.assertEqual(finding["severity"], "unknown", vector)
            self.assertEqual(finding["security"]["cvssVector"], vector)

        missing = normalize("osv-scanner", {"results": [{"source": {"path": "requirements.txt"}, "packages": [{
            "package": {"name": "pkg", "version": "1"}, "vulnerabilities": [{"id": "OSV-MISSING"}],
        }]}]})[0]
        self.assertEqual(missing["security"]["cvss"], None)
        self.assertEqual(missing["severity"], "unknown")

    def test_repeated_ds026_findings_group_without_dropping_locations(self):
        findings = normalize("trivy", {"Results": [
            {"Target": f"docker/service-{index}.Dockerfile", "Type": "dockerfile", "Misconfigurations": [
                {"ID": "DS026", "Title": "No HEALTHCHECK defined", "Severity": "LOW", "Message": "No HEALTHCHECK"}
            ]}
            for index in range(25)
        ]})
        remediations = build_remediations(findings)
        self.assertEqual(len(findings), 25)
        self.assertEqual(len({finding["fingerprint"] for finding in findings}), 25)
        self.assertEqual(len(remediations), 1)
        self.assertEqual(remediations[0]["title"], "Define container health-check strategy")
        self.assertEqual(len(remediations[0]["affectedFiles"]), 25)


class ScannerContinuationTests(unittest.TestCase):
    def test_parser_failure_isolated_and_run_marked_incomplete(self):
        class LaterCleanScanner:
            name = "later-clean"
            called = False

            def execute(self, context):
                self.called = True
                result = ScannerResult(
                    self.name, "test", "clean", datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(), 1, "raw/later-clean.json", finding_count=0,
                )
                return result, []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            output = Path(temporary) / "out"
            root.mkdir()
            (root / "app.py").write_text("print('safe')", encoding="utf-8")
            later = LaterCleanScanner()
            config = {"policy": {"failOn": ["critical", "high"], "failOnSecrets": True, "maxHigh": None}, "timeouts": {}}
            with patch("security_runner.scanners.Scanner._version", return_value="test"), patch(
                "security_runner.scanners._run_process", return_value=("not-json", "", 0)
            ):
                code, report = run_scan(root, output, config, [SastScanner(), later])
            self.assertTrue(later.called)
            self.assertEqual(code, 2)
            self.assertEqual(report["scanners"][0]["status"], "failed")
            self.assertEqual(report["scanners"][1]["status"], "clean")
            self.assertEqual(report["executionStatus"], "incomplete")
            self.assertEqual(report["securityGate"]["status"], "indeterminate")
    def test_scanner_schema_envelopes_and_versions_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("print(1)", encoding="utf-8")
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            output = root / "out"
            raw_dir = output / "raw"
            raw_dir.mkdir(parents=True)
            context = ScannerContext(root, output, raw_dir, detect_project(root), 5)
            supported = {
                "trivy": {
                    "SchemaVersion": 2, "ArtifactName": "workspace", "ArtifactType": "filesystem",
                    "CreatedAt": "2026-10-01T00:00:00Z", "Metadata": {}, "Results": [],
                },
                "osv-scanner": {"results": []},
                "semgrep": {"version": "1.99.0", "results": [], "errors": []},
            }
            for scanner in (TrivyScanner(), OsvScanner(), SastScanner()):
                with self.subTest(scanner=scanner.name), patch(
                    "security_runner.scanners.Scanner._version", return_value="test"
                ), patch(
                    "security_runner.scanners._run_process",
                    return_value=(json.dumps(supported[scanner.name]), "", 0),
                ):
                    result, findings = scanner.execute(context)
                self.assertEqual(result.status, "clean")
                self.assertEqual(findings, [])
                self.assertEqual(result.schema_version, {"trivy": "2", "osv-scanner": None, "semgrep": "1.99.0"}[scanner.name])

            with patch("security_runner.scanners.Scanner._version", return_value="test"), patch(
                "security_runner.scanners._run_process",
                return_value=(json.dumps({
                    "SchemaVersion": 2, "ArtifactName": "workspace", "ArtifactType": "filesystem",
                    "CreatedAt": "2026-10-01T00:00:00Z", "Metadata": {},
                }), "", 0),
            ):
                result, findings = TrivyScanner().execute(context)
            self.assertEqual(result.status, "clean")
            self.assertEqual(findings, [])

    def test_unsupported_scanner_envelopes_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("print(1)", encoding="utf-8")
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            output = root / "out"
            raw_dir = output / "raw"
            raw_dir.mkdir(parents=True)
            context = ScannerContext(root, output, raw_dir, detect_project(root), 5)
            cases = (
                (TrivyScanner(), {"SchemaVersion": 3, "Results": []}),
                (OsvScanner(), {"results": [{}]}),
                (SastScanner(), {"version": "1.99.0", "results": {}, "errors": []}),
            )
            for scanner, document in cases:
                with self.subTest(scanner=scanner.name), patch(
                    "security_runner.scanners.Scanner._version", return_value="test"
                ), patch(
                    "security_runner.scanners._run_process",
                    return_value=(json.dumps(document), "", 0),
                ):
                    result, findings = scanner.execute(context)
                self.assertEqual(result.status, "failed")
                self.assertIn("schema is unsupported", result.error)
                self.assertEqual(findings, [])

    def test_schema_failure_isolated_and_network_failure_is_not_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("print(1)", encoding="utf-8")
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            config = {"policy": {"failOn": [], "failOnSecrets": False, "maxHigh": None}, "timeouts": {}}

            def trivy_schema_failure(command, *_args):
                if command[0] == "trivy":
                    return json.dumps({"futureEnvelope": True}), "", 0
                if command[0] == "osv-scanner":
                    return json.dumps({"results": []}), "", 0
                return json.dumps({"version": "1.99.0", "results": [], "errors": []}), "", 0

            with patch("security_runner.scanners.Scanner._version", return_value="test"), patch(
                "security_runner.scanners._run_process", side_effect=trivy_schema_failure
            ):
                code, report = run_scan(root, Path(temporary) / "out-schema", config)
            self.assertEqual(code, 2)
            self.assertEqual([item["status"] for item in report["scanners"]], ["failed", "clean", "clean"])
            self.assertEqual(report["executionStatus"], "incomplete")
            self.assertEqual(report["securityGate"]["status"], "indeterminate")
            self.assertEqual(report["scanners"][2]["schemaVersion"], "1.99.0")

            def trivy_network_failure(command, *_args):
                if command[0] == "trivy":
                    return json.dumps({"SchemaVersion": 2, "Results": []}), "network unavailable", 2
                if command[0] == "osv-scanner":
                    return json.dumps({"results": []}), "", 0
                return json.dumps({"version": "1.99.0", "results": [], "errors": []}), "", 0

            with patch("security_runner.scanners.Scanner._version", return_value="test"), patch(
                "security_runner.scanners._run_process", side_effect=trivy_network_failure
            ):
                code, report = run_scan(root, Path(temporary) / "out-network", config)
            self.assertEqual(code, 2)
            self.assertEqual(report["scanners"][0]["status"], "failed")
            self.assertEqual(report["executionStatus"], "incomplete")
            self.assertEqual(report["securityGate"]["status"], "indeterminate")

    def test_all_applicable_scanners_clean_allows_gate_pass(self):
        class CleanScanner:
            name = "test-clean"

            def execute(self, context):
                result = ScannerResult(
                    self.name, "test", "clean", datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(), 1, "raw/test-clean.json", finding_count=0,
                )
                return result, []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("print('hello')", encoding="utf-8")
            config = {"policy": {"failOn": ["critical", "high"], "failOnSecrets": True, "maxHigh": None}, "timeouts": {}}
            code, report = run_scan(root, Path(temporary) / "out", config, [CleanScanner()])
            self.assertEqual(code, 0)
            self.assertEqual(report["executionStatus"], "completed")
            self.assertEqual(report["securityGate"]["status"], "passed")

    def test_all_applicable_scanners_failed_is_incomplete(self):
        class FailedScanner:
            name = "test-failed"

            def execute(self, context):
                result = ScannerResult(
                    self.name, "test", "failed", datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(), 1, "raw/test-failed.json", "failure",
                )
                return result, []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("print('hello')", encoding="utf-8")
            config = {"policy": {"failOn": [], "failOnSecrets": False, "maxHigh": None}, "timeouts": {}}
            code, report = run_scan(root, Path(temporary) / "out", config, [FailedScanner()])
            self.assertEqual(code, 2)
            self.assertEqual(report["executionStatus"], "incomplete")
            self.assertEqual(report["securityGate"]["status"], "indeterminate")

    def test_disabled_scanner_is_skipped_not_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = ScannerContext(root, root / "out", root / "out" / "raw", detect_project(root), 2)
            context.raw_dir.mkdir(parents=True)
            result, findings = OsvScanner(enabled=False).execute(context)
            self.assertEqual(result.status, "skipped")
            self.assertEqual(result.reason, "disabled by configuration")
            self.assertEqual(findings, [])

    def test_non_applicable_osv_is_not_reported_as_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = ScannerContext(root, root / "out", root / "out" / "raw", detect_project(root), 2)
            context.raw_dir.mkdir(parents=True)
            result, findings = OsvScanner().execute(context)
            self.assertEqual(result.status, "not_applicable")
            self.assertIsNotNone(result.reason)
            self.assertEqual(findings, [])

    def test_failed_scanner_does_not_prevent_later_scanners(self):
        class StubScanner:
            def __init__(self, name, status):
                self.name = name
                self.status = status
                self.called = False

            def execute(self, context):
                self.called = True
                result = ScannerResult(
                    self.name, "test", self.status, datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(), 1, f"raw/{self.name}.json",
                    "simulated error" if self.status == "failed" else None,
                )
                return result, []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            output = Path(temporary) / "output"
            root.mkdir()
            (root / "app.py").write_text("print('hello')", encoding="utf-8")
            scanners = [StubScanner("trivy", "failed"), StubScanner("osv-scanner", "skipped"), StubScanner("semgrep", "clean")]
            config = {"policy": {"failOn": [], "failOnSecrets": False, "maxHigh": None}, "timeouts": {}}
            scan_id = "a8f55dfc-a41a-4c28-9808-990706ef8a22"
            previous_scan_id = os.environ.get("SECURITY_SCAN_ID")
            os.environ["SECURITY_SCAN_ID"] = scan_id
            try:
                code, report = run_scan(root, output, config, scanners)
            finally:
                if previous_scan_id is None:
                    os.environ.pop("SECURITY_SCAN_ID", None)
                else:
                    os.environ["SECURITY_SCAN_ID"] = previous_scan_id
            self.assertEqual(code, 2)
            self.assertTrue(all(scanner.called for scanner in scanners))
            self.assertEqual([item["status"] for item in report["scanners"]], ["failed", "skipped", "clean"])
            self.assertEqual(report["scanId"], scan_id)
            self.assertEqual(report["executionStatus"], "incomplete")
            self.assertEqual(report["securityGate"]["status"], "indeterminate")
            self.assertEqual(report["generator"]["name"], "Vesper")
            self.assertEqual(report["generator"]["version"], "0.2.0")
            self.assertEqual(json.loads((output / "summary.json").read_text(encoding="utf-8"))["generator"]["name"], "Vesper")
            self.assertTrue((output / "remediations.json").is_file())

    def test_empty_workspace_with_no_applicable_scanners_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "empty"
            root.mkdir()
            output = Path(temporary) / "output"
            config = {"policy": {"failOn": ["critical", "high"], "failOnSecrets": True, "maxHigh": None}, "timeouts": {}}
            code, report = run_scan(root, output, config)
            self.assertEqual(code, 2)
            self.assertEqual(report["executionStatus"], "incomplete")
            self.assertEqual(report["securityGate"]["status"], "indeterminate")
            self.assertTrue(all(scanner["status"] == "not_applicable" for scanner in report["scanners"]))

    def test_invalid_json_and_unexpected_json_types_fail_scanner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("print(1)", encoding="utf-8")
            output = root / "out"
            raw = output / "raw"
            raw.mkdir(parents=True)
            context = ScannerContext(root, output, raw, detect_project(root), 5)
            for stdout in ("not-json", "[]", '{"results":[{"extra":"unexpected-string"}]}'):
                with self.subTest(stdout=stdout):
                    with patch("security_runner.scanners.Scanner._version", return_value="test"), patch(
                        "security_runner.scanners._run_process", return_value=(stdout, "", 0)
                    ):
                        result, findings = SastScanner().execute(context)
                    self.assertEqual(result.status, "failed")
                    self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
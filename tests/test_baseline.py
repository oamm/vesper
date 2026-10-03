import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from security_runner.baseline import BaselineError, create_baseline, load_baseline, normalize_target, validate_comparison
from security_runner.baseline_cli import main as baseline_cli_main
from security_runner.models import ScannerResult
from security_runner.normalization import normalize, normalize_api_behavior, normalize_grype
from security_runner.runner import run_scan
from security_runner.scanners import OsvScanner, SastScanner


POLICY = {
    "policy": {"failOn": [], "failOnSecrets": False, "maxHigh": None},
    "baseline": {"failOnNew": ["critical", "high"]},
    "timeouts": {},
}


class FixtureScanner:
    name = "trivy"

    def __init__(self, raw, status=None, coverage=None):
        self.raw = raw
        self.status = status
        self.coverage = coverage or {"assessment": "unknown"}

    def execute(self, context):
        findings = normalize(self.name, self.raw)
        status = self.status or ("completed_with_findings" if findings else "clean")
        result = ScannerResult(
            self.name, "0.58.2", status, datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(), 1, "raw/trivy.json",
            finding_count=len(findings), coverage=self.coverage,
        )
        return result, findings


def dependency_raw(vulnerability="CVE-2024-12345", severity="HIGH", version="1.0.0", fixed="1.0.1"):
    return {"Results": [{"Target": "packages.lock.json", "Vulnerabilities": [{
        "VulnerabilityID": vulnerability,
        "Aliases": ["GHSA-abcd-1234-efgh"],
        "PkgName": "Example.Package",
        "InstalledVersion": version,
        "FixedVersion": fixed,
        "PkgType": "nuget",
        "Severity": severity,
    }]}]}


def scan_config(fail_absolute=None):
    config = json.loads(json.dumps(POLICY))
    if fail_absolute is not None:
        config["policy"]["failOn"] = fail_absolute
    return config


class BaselineTests(unittest.TestCase):
    def _run_fixture(self, workspace, output, scanner, baseline=None, config=None):
        return run_scan(workspace, output, config or scan_config(), [scanner], baseline=baseline)

    def _create_dependency_baseline(self, root, scanner=None):
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "packages.lock.json").write_text("{}", encoding="utf-8")
        output = root / "initial"
        code, _ = self._run_fixture(workspace, output, scanner or FixtureScanner(dependency_raw()))
        self.assertEqual(code, 0)
        baseline_path = root / "baseline.json"
        baseline = create_baseline(output, baseline_path)
        self.assertEqual(load_baseline(baseline_path), baseline)
        return workspace, output, baseline

    def _api_fixture_scanners(self, root, events, state="exercised", validation=None, active=True, status="completed"):
        contract = {
            "schemaVersion": 1,
            "apiIdentityVersion": 1,
            "contract": {"contentDigest": "a" * 64},
            "coverage": {"contractCoverage": "complete"},
            "securitySchemes": [],
            "operations": [{
                "id": "POST /loans",
                "method": "POST",
                "path": "/loans",
                "responses": [{"status": "201"}, {"status": "400"}],
                "authentication": "public",
            }],
        }
        execution = {
            "schemaVersion": 1,
            "contract": {"digest": "a" * 64, "apiIdentityVersion": 1},
            "activeTesting": active,
            "status": status,
            "operations": [{
                "operation": "POST /loans",
                "state": state,
                "generatedCases": 1 if state != "not_attempted" else 0,
                "completedCases": 1 if state == "exercised" else 0,
                "candidateFailures": [],
                "validation": validation or {"statusValidation": True, "responseSchemaValidation": True},
            }],
            "events": events,
            "summary": {"known": 1, "attempted": state != "not_attempted", "exercised": state == "exercised", "authLimited": state == "auth_limited", "failed": state == "failed", "notAttempted": state == "not_attempted", "requests": 1 if state == "exercised" else 0},
            "coverage": {"assessment": "complete" if state == "exercised" else "partial", "runtimeOperationCoverage": "complete" if state == "exercised" else "partial"},
        }

        class ApiContractFixture:
            name = "api-contract"

            def execute(self, context):
                self.extra_artifacts = {"apiContract": contract}
                now = datetime.now(timezone.utc).isoformat()
                return ScannerResult(self.name, "builtin", "completed", now, now, 1, "raw/api-contract-source.yaml", coverage={"assessment": "complete", "contractCoverage": "complete"}), []

        class ApiExecutionFixture:
            name = "api-execution"

            def execute(self, context):
                self.extra_artifacts = {"apiExecution": execution}
                (context.raw_dir / "schemathesis.json").write_text(json.dumps({"schemaVersion": 1, "events": events}), encoding="utf-8")
                now = datetime.now(timezone.utc).isoformat()
                coverage = {**execution["coverage"], "operations": execution["operations"]}
                return ScannerResult(self.name, "3.39.16", status, now, now, 1, "raw/schemathesis.json", finding_count=len(events), coverage=coverage, schema_version="1"), []

        class CombinedApiFixture:
            def __init__(self):
                self.contract_scanner = ApiContractFixture()
                self.execution_scanner = ApiExecutionFixture()

            def execute(self, context):
                self.extra_artifacts = {}
                return ScannerResult("api-fixture", "test", "clean", datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), 1, "raw/fixture.json"), []

        contract_scanner = ApiContractFixture()
        execution_scanner = ApiExecutionFixture()
        return [contract_scanner, execution_scanner], contract, execution

    def _run_api_fixture(self, root, name, events, baseline=None, **kwargs):
        workspace = root / "workspace"
        workspace.mkdir(exist_ok=True)
        output = root / name
        scanners, contract, execution = self._api_fixture_scanners(root, events, **kwargs)
        # The runner's scanner boundary consumes scanner instances directly; both
        # adapters expose their own extra artifacts during execution.
        code, _ = run_scan(workspace, output, scan_config(), scanners, baseline=baseline)
        return code, output, contract, execution

    def test_api_behavior_baseline_states_and_positive_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = {"operation": "POST /loans", "method": "POST", "path": "/loans", "caseId": "case-a", "classification": "unexpected_5xx", "status": 500, "contentType": "application/json"}
            code, initial, _, _ = self._run_api_fixture(root, "initial", [event])
            self.assertEqual(code, 0)
            baseline = create_baseline(initial, root / "api-baseline.json")
            self.assertEqual(len(baseline["findings"]), 1)
            self.assertEqual(baseline["findings"][0]["category"], "api_behavior")

            code, unchanged, _, _ = self._run_api_fixture(root, "unchanged", [event], baseline=baseline)
            self.assertEqual(code, 0)
            comparison = json.loads((unchanged / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(comparison["summary"], {"new": 0, "existing": 1, "changed": 0, "resolved": 0, "unverified": 0})

            schema_event = {"operation": "POST /loans", "method": "POST", "path": "/loans", "caseId": "case-b", "classification": "response_schema_violation", "status": 201, "contentType": "application/json"}
            code, added, _, _ = self._run_api_fixture(root, "added", [event, schema_event], baseline=baseline)
            self.assertEqual(code, 0)
            added_comparison = json.loads((added / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(added_comparison["summary"]["existing"], 1)
            self.assertEqual(added_comparison["summary"]["new"], 1)

            code, changed, _, _ = self._run_api_fixture(root, "changed", [{**event, "status": 501}], baseline=baseline)
            self.assertEqual(code, 0)
            changed_comparison = json.loads((changed / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(changed_comparison["summary"]["changed"], 1)

            code, resolved, _, _ = self._run_api_fixture(root, "resolved", [], baseline=baseline, validation={"statusValidation": True, "responseSchemaValidation": True})
            self.assertEqual(code, 0)
            resolved_comparison = json.loads((resolved / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(resolved_comparison["summary"]["resolved"], 1)
            self.assertEqual(resolved_comparison["summary"]["unverified"], 0)
            invalid_resolution = json.loads(json.dumps(resolved_comparison))
            scan_report = json.loads((resolved / "scan.json").read_text(encoding="utf-8"))
            scan_report["apiExecution"]["operations"][0]["validation"]["statusValidation"] = False
            findings_report = json.loads((resolved / "findings.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(BaselineError, "positive runtime coverage"):
                validate_comparison(invalid_resolution, baseline, findings_report, scan_report)

            code, auth_limited, _, _ = self._run_api_fixture(root, "auth-limited", [], baseline=baseline, state="auth_limited", validation={"statusValidation": False, "responseSchemaValidation": False})
            auth_comparison = json.loads((auth_limited / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(auth_comparison["findings"]["unverified"][0]["reasonCode"], "auth_limited")

            code, passive, _, _ = self._run_api_fixture(root, "passive", [], baseline=baseline, active=False, status="not_applicable", state="not_attempted")
            passive_comparison = json.loads((passive / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(passive_comparison["findings"]["unverified"][0]["reasonCode"], "passive_scan")

            code, unavailable, _, _ = self._run_api_fixture(root, "validation-unavailable", [], baseline=baseline, validation={"statusValidation": False, "responseSchemaValidation": False})
            unavailable_comparison = json.loads((unavailable / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(unavailable_comparison["findings"]["unverified"][0]["reasonCode"], "validation_unavailable")

            code, failed, _, _ = self._run_api_fixture(root, "runtime-failed", [], baseline=baseline, state="failed", status="failed")
            failed_comparison = json.loads((failed / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(failed_comparison["findings"]["unverified"][0]["reasonCode"], "runtime_failed")

    def test_baseline_creation_is_deterministic_and_rejects_incomplete_or_corrupt_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, output, _ = self._create_dependency_baseline(root)
            first = create_baseline(output, root / "baseline-one.json")
            second = create_baseline(output, root / "baseline-two.json")
            self.assertEqual(first, second)
            self.assertEqual(first["schemaVersion"], 1)
            self.assertNotIn("raw", json.dumps(first))
            self.assertEqual(baseline_cli_main(["create", str(output), "--output", str(root / "baseline-cli.json")]), 0)

            incomplete = root / "incomplete"
            self._run_fixture(workspace, incomplete, FixtureScanner({}, status="failed"))
            with self.assertRaisesRegex(BaselineError, "completed scan"):
                create_baseline(incomplete, root / "invalid.json")

            scan_path = output / "scan.json"
            saved_scan = scan_path.read_text(encoding="utf-8")
            scan_path.write_text('{"schemaVersion":99}', encoding="utf-8")
            try:
                with self.assertRaisesRegex(BaselineError, "schema"):
                    create_baseline(output, root / "invalid-schema.json")
            finally:
                scan_path.write_text(saved_scan, encoding="utf-8")

            summary_path = output / "summary.json"
            saved_summary = summary_path.read_text(encoding="utf-8")
            summary_data = json.loads(saved_summary)
            summary_data["findings"] = []
            summary_path.write_text(json.dumps(summary_data), encoding="utf-8")
            try:
                with self.assertRaisesRegex(BaselineError, "finding counts"):
                    create_baseline(output, root / "malformed-summary.json")
            finally:
                summary_path.write_text(saved_summary, encoding="utf-8")

    def test_completed_failed_gate_scan_is_a_valid_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "packages.lock.json").write_text("{}", encoding="utf-8")
            output = root / "failed-gate"
            code, _ = self._run_fixture(workspace, output, FixtureScanner(dependency_raw()), config=scan_config(["high"]))
            self.assertEqual(code, 1)
            baseline = create_baseline(output, root / "accepted-baseline.json")
            self.assertEqual(len(baseline["findings"]), 1)

    def test_runner_environment_excludes_baseline_file_from_project_inventory(self):
        class ContextScanner:
            name = "trivy"
            context = None

            def execute(self, context):
                self.context = context
                now = datetime.now(timezone.utc).isoformat()
                return ScannerResult(self.name, "0.58.2", "clean", now, now, 1, "raw/trivy.json"), []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "app.py").write_text("print('app')", encoding="utf-8")
            (workspace / "baseline.json").write_text("{}", encoding="utf-8")
            scanner = ContextScanner()
            with patch.dict("os.environ", {"SECURITY_SCAN_BASELINE_RELATIVE_PATH": "baseline.json"}):
                code, _ = run_scan(workspace, root / "output", scan_config(), [scanner])
            project = json.loads((root / "output/project.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(scanner.context.exclude_files, ["baseline.json"])
            self.assertEqual(project["fileCount"], 1)
            self.assertIn({"path": "baseline.json", "reason": "baseline_input"}, project["exclusions"])

    def test_malformed_duplicate_baseline_and_absolute_targets_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, baseline = self._create_dependency_baseline(root)
            duplicate = json.loads(json.dumps(baseline))
            duplicate["findings"].append(dict(duplicate["findings"][0]))
            duplicate["baselineId"] = "baseline-" + "0" * 64
            with self.assertRaisesRegex(BaselineError, "duplicate"):
                from security_runner.baseline import validate_baseline
                validate_baseline(duplicate)
            tampered = json.loads(json.dumps(baseline))
            tampered["findings"][0]["title"] = "Tampered title"
            with self.assertRaisesRegex(BaselineError, "baseline ID"):
                validate_baseline(tampered)
        with self.assertRaises(BaselineError):
            normalize_target("C:/repo/src/Foo.cs")
        self.assertEqual(normalize_target("C:/repo/src/Foo.cs", "C:/repo"), "src/Foo.cs")
        self.assertEqual(normalize_target("/workspace/src/Foo.cs"), "src/Foo.cs")

    def test_existing_new_and_changed_states_and_new_only_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial_raw = dependency_raw()
            for vulnerability, package in (("CVE-2024-12346", "Second.Package"), ("CVE-2024-12347", "Third.Package")):
                initial_raw["Results"][0]["Vulnerabilities"].append({
                    "VulnerabilityID": vulnerability, "PkgName": package, "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1", "PkgType": "nuget", "Severity": "HIGH",
                })
            workspace, _, baseline = self._create_dependency_baseline(root, FixtureScanner(initial_raw))

            existing_output = root / "existing"
            code, _ = self._run_fixture(workspace, existing_output, FixtureScanner(initial_raw), baseline)
            existing = json.loads((existing_output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(existing["summary"], {"new": 0, "existing": 3, "changed": 0, "resolved": 0, "unverified": 0})
            self.assertEqual(json.loads((existing_output / "summary.json").read_text(encoding="utf-8"))["gate"]["status"], "passed")

            added_raw = json.loads(json.dumps(initial_raw))
            added_raw["Results"][0]["Vulnerabilities"].append({
                "VulnerabilityID": "CVE-2024-99999", "PkgName": "Another.Package", "InstalledVersion": "2.0.0",
                "FixedVersion": "2.0.1", "PkgType": "nuget", "Severity": "HIGH",
            })
            new_output = root / "new"
            code, _ = self._run_fixture(workspace, new_output, FixtureScanner(added_raw), baseline)
            new_comparison = json.loads((new_output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 1)
            self.assertEqual(new_comparison["summary"]["new"], 1)
            self.assertEqual(new_comparison["summary"]["existing"], 3)

            low_raw = json.loads(json.dumps(initial_raw))
            low_raw["Results"][0]["Vulnerabilities"].append({
                "VulnerabilityID": "CVE-2024-88888", "PkgName": "Low.Package", "InstalledVersion": "1.0.0",
                "PkgType": "nuget", "Severity": "LOW",
            })
            low_output = root / "new-low"
            code, _ = self._run_fixture(workspace, low_output, FixtureScanner(low_raw), baseline)
            low = json.loads((low_output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(low["summary"]["new"], 1)
            self.assertEqual(low["summary"]["existing"], 3)

            changed_raw = json.loads(json.dumps(initial_raw))
            changed_raw["Results"][0]["Vulnerabilities"][0]["Severity"] = "CRITICAL"
            changed_output = root / "changed"
            code, _ = self._run_fixture(workspace, changed_output, FixtureScanner(changed_raw), baseline)
            changed = json.loads((changed_output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(changed["summary"], {"new": 0, "existing": 2, "changed": 1, "resolved": 0, "unverified": 0})
            self.assertEqual(changed["findings"]["changed"][0]["semanticChanges"], ["severity"])

    def test_detector_and_alias_changes_do_not_change_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, _, baseline = self._create_dependency_baseline(root)
            raw = dependency_raw()
            raw["Results"][0]["Vulnerabilities"][0]["Aliases"] = ["GHSA-abcd-1234-efgh", "CVE-2024-77777"]
            scanner = FixtureScanner(raw)
            code, _ = self._run_fixture(workspace, root / "current", scanner, baseline)
            comparison = json.loads((root / "current" / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(comparison["summary"]["existing"], 1)

            raw["Results"][0]["Vulnerabilities"][0]["Aliases"] = ["GHSA-abcd-1234-efgh"]
            finding = normalize("trivy", raw)[0]
            finding["scannerEvidence"].append({"scanner": "osv-scanner", "ruleId": "OSV-1", "rawId": "OSV-1"})
            baseline_finding = baseline["findings"][0]
            from security_runner.baseline import _baseline_finding
            current_record = _baseline_finding(finding, None)
            self.assertEqual(current_record["identity"], baseline_finding["identity"])
            self.assertEqual(current_record["detectors"], ["osv-scanner", "trivy"])

    def test_added_ghsa_alias_does_not_change_existing_osv_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "packages.lock.json").write_text("{}", encoding="utf-8")
            initial_raw = {"results": [{
                "source": {"path": "/workspace/packages.lock.json"},
                "packages": [{"package": {"name": "Example.Package", "version": "1.0.0", "ecosystem": "NuGet"},
                              "vulnerabilities": [{"id": "OSV-2024-12345", "summary": "Original advisory"}]}],
            }]}
            with patch("security_runner.scanners.Scanner._version", return_value="osv-scanner version: 2.3.3"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(initial_raw), "", 0)
            ):
                initial_output = root / "initial"
                self._run_fixture(workspace, initial_output, OsvScanner())
            baseline = create_baseline(initial_output, root / "baseline.json")

            updated_raw = json.loads(json.dumps(initial_raw))
            updated_raw["results"][0]["packages"][0]["vulnerabilities"][0]["aliases"] = ["GHSA-abcd-1234-efgh"]
            with patch("security_runner.scanners.Scanner._version", return_value="osv-scanner version: 2.3.3"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(updated_raw), "", 0)
            ):
                output = root / "updated"
                code, _ = self._run_fixture(workspace, output, OsvScanner(), baseline)
            comparison = json.loads((output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(comparison["summary"], {"new": 0, "existing": 1, "changed": 0, "resolved": 0, "unverified": 0})

    def test_trivy_baseline_matches_osv_current_finding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "packages.lock.json").write_text("{}", encoding="utf-8")
            initial = FixtureScanner(dependency_raw(fixed=None))
            initial_output = root / "trivy-initial"
            self._run_fixture(workspace, initial_output, initial)
            baseline = create_baseline(initial_output, root / "trivy-baseline.json")

            osv_raw = {"results": [{
                "source": {"path": "/workspace/packages.lock.json"},
                "packages": [{
                    "package": {"name": "Example.Package", "version": "1.0.0", "ecosystem": "NuGet"},
                    "vulnerabilities": [{
                        "id": "OSV-2024-12345", "aliases": ["CVE-2024-12345"],
                        "database_specific": {"severity": "HIGH"},
                    }],
                }],
            }]}
            with patch("security_runner.scanners.Scanner._version", return_value="osv-scanner version: 2.3.3"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(osv_raw), "", 0)
            ):
                current_output = root / "osv-current"
                code, _ = self._run_fixture(workspace, current_output, OsvScanner(), baseline)

            comparison = json.loads((current_output / "comparison.json").read_text(encoding="utf-8"))
            existing = comparison["findings"]["existing"]
            self.assertEqual(code, 0)
            self.assertEqual(comparison["summary"], {"new": 0, "existing": 1, "changed": 0, "resolved": 0, "unverified": 0})
            self.assertEqual(existing[0]["detectorsAdded"], ["osv-scanner"])
            self.assertEqual(existing[0]["detectorsRemoved"], ["trivy"])

    def test_osv_completion_resolves_and_osv_failure_is_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "packages.lock.json").write_text("{}", encoding="utf-8")
            raw_vulnerable = {"results": [{
                "source": {"path": "/workspace/packages.lock.json"},
                "packages": [{"package": {"name": "Example.Package", "version": "1.0.0", "ecosystem": "NuGet"},
                              "vulnerabilities": [{"id": "OSV-123", "aliases": ["CVE-2024-12345"]}]}],
            }]}
            with patch("security_runner.scanners.Scanner._version", return_value="osv-scanner version: 2.3.3"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(raw_vulnerable), "", 0)
            ):
                initial_output = root / "osv-initial"
                self._run_fixture(workspace, initial_output, OsvScanner())
            baseline = create_baseline(initial_output, root / "osv-baseline.json")

            with patch("security_runner.scanners.Scanner._version", return_value="osv-scanner version: 2.3.3"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps({"results": []}), "", 0)
            ):
                resolved_output = root / "osv-resolved"
                code, _ = self._run_fixture(workspace, resolved_output, OsvScanner(), baseline)
            resolved = json.loads((resolved_output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(resolved["summary"]["resolved"], 1)

            with patch("security_runner.scanners.Scanner._version", return_value="osv-scanner version: 2.3.3"), patch(
                "security_runner.scanners._run_process", return_value=("", "network failure", 2)
            ):
                failed_output = root / "osv-failed"
                code, _ = self._run_fixture(workspace, failed_output, OsvScanner(), baseline)
            failed = json.loads((failed_output / "comparison.json").read_text(encoding="utf-8"))
            gate = json.loads((failed_output / "summary.json").read_text(encoding="utf-8"))["gate"]
            self.assertEqual(code, 2)
            self.assertEqual(failed["summary"]["unverified"], 1)
            self.assertEqual(failed["findings"]["unverified"][0]["reasonCode"], "scanner_failed")
            self.assertEqual(gate["status"], "indeterminate")

    def test_trivy_unknown_coverage_and_semgrep_parse_errors_are_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, _, dependency_baseline = self._create_dependency_baseline(root)
            clean_output = root / "trivy-clean"
            code, _ = self._run_fixture(workspace, clean_output, FixtureScanner({"Results": []}), dependency_baseline)
            clean = json.loads((clean_output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(clean["findings"]["unverified"][0]["reasonCode"], "coverage_unknown")

            sast_workspace = root / "sast-workspace"
            sast_workspace.mkdir()
            (sast_workspace / "App.py").write_text("print('example')", encoding="utf-8")
            initial = {"version": "1.99.0", "results": [{
                "check_id": "python.test.security", "path": "App.py", "start": {"line": 1},
                "extra": {"severity": "ERROR", "message": "Unsafe behavior", "metadata": {}},
            }], "errors": [], "paths": {"scanned": ["/workspace/App.py"], "skipped": {"paths": []}},
                "skipped_rules": [], "stats": {"rulesLoaded": 4}}
            with patch("security_runner.scanners.Scanner._version", return_value="1.99.0"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(initial), "", 0)
            ):
                sast_initial = root / "sast-initial"
                self._run_fixture(sast_workspace, sast_initial, SastScanner())
            sast_baseline = create_baseline(sast_initial, root / "sast-baseline.json")

            parsed = {"version": "1.99.0", "results": [], "errors": [],
                      "paths": {"scanned": ["/workspace/App.py"], "skipped": {"paths": []}},
                      "skipped_rules": [], "stats": {"rulesLoaded": 4}}
            with patch("security_runner.scanners.Scanner._version", return_value="1.99.0"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(parsed), "", 0)
            ):
                sast_resolved = root / "sast-resolved"
                code, _ = self._run_fixture(sast_workspace, sast_resolved, SastScanner(), sast_baseline)
            resolved = json.loads((sast_resolved / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(resolved["summary"]["resolved"], 1)

            parse_error = {**parsed, "errors": [{"type": ["PartialParsing", []], "path": "/workspace/App.py"}]}
            with patch("security_runner.scanners.Scanner._version", return_value="1.99.0"), patch(
                "security_runner.scanners._run_process", return_value=(json.dumps(parse_error), "", 0)
            ):
                sast_unverified = root / "sast-unverified"
                code, _ = self._run_fixture(sast_workspace, sast_unverified, SastScanner(), sast_baseline)
            unverified = json.loads((sast_unverified / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(unverified["findings"]["unverified"][0]["reasonCode"], "parse_error")

    def test_skipped_capability_is_unverified_not_resolved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, _, baseline = self._create_dependency_baseline(root)
            output = root / "skipped"
            code, _ = self._run_fixture(workspace, output, FixtureScanner({}, status="skipped"), baseline)
            comparison = json.loads((output / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 2)
            self.assertEqual(comparison["findings"]["unverified"][0]["reasonCode"], "capability_not_executed")

    def test_grype_coverage_loss_is_unverified_not_resolved(self):
        class GrypeFixtureScanner:
            name = "grype"

            def __init__(self, raw, inventory):
                self.raw = raw
                self.extra_artifacts = {"components": inventory}

            def execute(self, context):
                findings = normalize_grype(self.raw, self.extra_artifacts["components"])
                status = "completed_with_findings" if findings else "clean"
                now = datetime.now(timezone.utc).isoformat()
                result = ScannerResult(
                    self.name, "0.119.0", status, now, now, 1, "raw/grype.json",
                    finding_count=len(findings),
                    coverage={
                        "assessment": "unknown",
                        "input": "raw/syft.cdx.json",
                        "inputAssessment": "unknown",
                        "analysisStatus": "completed",
                    },
                )
                return result, findings

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "packages.lock.json").write_text("{}", encoding="utf-8")
            raw = {
                "descriptor": {"name": "grype", "version": "0.119.0"},
                "matches": [{
                    "vulnerability": {"id": "GHSA-test-1234-5678", "severity": "HIGH", "fix": {"versions": ["1.0.1"]}},
                    "artifact": {"name": "Example.Package", "version": "1.0.0", "purl": "pkg:nuget/Example.Package@1.0.0"},
                }],
            }
            inventory = {
                "schemaVersion": 1,
                "format": "CycloneDX",
                "specVersion": "1.7",
                "rawOutput": "raw/syft.cdx.json",
                "components": [{
                    "id": "component-example",
                    "type": "library",
                    "ecosystem": "nuget",
                    "name": "Example.Package",
                    "version": "1.0.0",
                    "purl": "pkg:nuget/Example.Package@1.0.0",
                    "occurrences": [{"path": "packages.lock.json"}],
                    "evidence": [],
                }],
            }
            initial = root / "initial"
            self._run_fixture(workspace, initial, GrypeFixtureScanner(raw, inventory))
            baseline = create_baseline(initial, root / "grype-baseline.json")
            current = root / "current"
            code, _ = self._run_fixture(workspace, current, GrypeFixtureScanner({"descriptor": raw["descriptor"], "matches": []}, inventory), baseline)
            comparison = json.loads((current / "comparison.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(comparison["summary"], {"new": 0, "existing": 0, "changed": 0, "resolved": 0, "unverified": 1})
            self.assertIn(comparison["findings"]["unverified"][0]["reasonCode"], {"coverage_unknown", "target_not_covered"})

    def test_completed_scan_comparison_is_deterministic_and_saved_gate_metadata_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, _, baseline = self._create_dependency_baseline(root)
            comparisons = []
            for name in ("one", "two"):
                output = root / name
                self._run_fixture(workspace, output, FixtureScanner(dependency_raw()), baseline)
                comparison = json.loads((output / "comparison.json").read_text(encoding="utf-8"))
                comparisons.append(comparison)
                summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["baselineComparison"]["baselineId"], baseline["baselineId"])
                self.assertEqual(summary["gate"]["baselineDelta"]["newFindings"], 0)
            self.assertEqual(comparisons[0]["summary"], comparisons[1]["summary"])
            self.assertEqual(comparisons[0]["findings"], comparisons[1]["findings"])


if __name__ == "__main__":
    unittest.main()

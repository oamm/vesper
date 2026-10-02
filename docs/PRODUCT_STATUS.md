# Vesper Product Status

**Last updated:** 2026-10-01
**Current version:** 0.2.0
**Current milestone:** M2 - Baseline and Finding Diff
**Overall status:** IN PROGRESS

## Product Goal

Vesper is a developer- and CI-oriented application security analysis and policy tool. It orchestrates open-source scanners inside an isolated Docker execution, normalizes and deduplicates their findings, groups findings into actionable remediations, and evaluates a security gate. It is not currently a hosted service or general AppSec platform.

## Current Architecture

```text
Developer / CI
    -> vesper (.NET 10 Native AOT host CLI)
       -> Docker CLI and selected context
          -> one ephemeral vesper-runner container per scan
             -> Python orchestration and project detection
             -> Trivy / OSV-Scanner / Semgrep
             -> normalization / deduplication / remediation groups / policy / reports
```

- The launcher owns Docker context selection, host paths, source/result transport, per-scan resources, process control, and exit-code forwarding.
- The Python runner owns project detection, scanner adapters, parsing, normalized findings, remediation grouping, policy evaluation, and reports.
- The runner contract is `/workspace` (read-only), `/output` (scan-specific writable volume), and `SECURITY_SCAN_ID`.
- Local mode uses bind mounts. Remote mode stages files through Docker stdin/stdout and uniquely named volumes using the digest-pinned Alpine tar helper.
- Every scan has one full GUID, one ephemeral runner container, one isolated source volume and output volume in volume mode, and one report directory under `<output-base>/YYYY-MM-DD/HH-mm-ss_<short-scan-id>` using the captured UTC start time.
- Scanner caches are per-container. No shared mutable cache, server, queue, database, or Kubernetes integration exists.

## Current Capabilities

- Scanner image: Trivy 0.58.2, OSV-Scanner 2.3.3, Semgrep 1.99.0; image default is `vesper-runner:0.2.0`.
- Host CLI: .NET 10 Native AOT; Windows `win-x64` and Linux `linux-x64` have been published and runtime-tested.
- Docker endpoint classification supports npipe, Unix socket, SSH, loopback and remote TCP/HTTP(S); Docker calls are pinned to the context/host selected at scan start.
- Local bind and remote volume workspace modes; source archives exclude common generated directories and enforce byte/file/per-file ceilings.
- Scan-specific report directories, labeled Docker resources, bounded Docker operation timeouts, runner limits, fail-closed execution completeness, and per-scan cleanup.
- Reports include `project.json`, `scan.json`, `findings.json`, `remediations.json`, `summary.json`, and raw scanner artifacts; `comparison.json` is reserved for requested baseline comparisons.
- Scanner execution status is separate from coverage assessment and policy gate; `unsupported_manifest` is explicit and cannot be treated as clean. Reports use schema v2 and validate internal totals/references before writing final JSON.

## Milestones

### M1 - Autonomous Security Runner

**Status:** COMPLETE

**Goal:** Run local security scanners against a read-only repository and emit normalized, policy-evaluated reports.

#### Scope

- Trivy filesystem, dependency, secret, IaC, and container configuration checks.
- OSV dependency analysis and Semgrep SAST behind isolated adapters.
- Normalized findings, scanner evidence, conservative deduplication, security policy, raw artifacts, and CLI summary.

#### Completed

- Python runner, project detection, Trivy/OSV/Semgrep adapters, normalized findings, fingerprints, policy, reports, and synthetic vulnerable fixture.
- Findings remain separately auditable; remediation groups are a separate artifact.

#### Verification

- 29 Python tests pass, including scanner failure continuation, schema compatibility, normalization, deduplication, policy, CVSS, remediation grouping, and scanner state.
- Remote vulnerable fixture runs all three scanners and exports reports. Current fixture run returned gate exit 1 as expected.
- Final current-tree self-scan completed all scanners and exported reports; it returned exit 1 with 38 findings / 36 remediations, including intentional vulnerable fixtures, so it is not a product-only baseline.

#### Remaining / deferred

- Exact Lynx baseline regression is unavailable because its raw scan outputs are not in this checkout.
- Database/rule caches and additional scanners are deferred.

#### Exit criteria

- [x] Container runner builds and scans the synthetic fixture.
- [x] Scanner failures are represented individually and do not stop later adapters.
- [x] Reports distinguish scan completeness and security gate outcome.

---

### M1.1 - Native AOT Launcher and Remote Transport

**Status:** COMPLETE

**Goal:** Provide a small host CLI that runs without a .NET runtime and can stage workspaces to remote Docker.

#### Completed

- .NET 10 Native AOT `vesper` CLI; Docker invocation uses `ProcessStartInfo.ArgumentList`, not a shell.
- Endpoint detection, pinned Docker context per scan, local bind mode, remote named-volume mode, PAX tar byte streaming, configuration staging, result export, exit preservation, and per-scan cleanup.
- Version/digest-pinned Alpine helper; helper containers use resource limits, read-only root, no network/capabilities, and a private tmpfs.
- Vesper command surface: `scan`, `inspect`, `report`, `gate`, and `version`; `--image` override remains supported.

#### Verification

- `win-x64` Native AOT publish succeeded with warnings-as-errors; published `vesper.exe` ran directly without `dotnet` for `version`, `inspect`, and scans.
- Remote SSH Docker fixture scan completed and exported reports. Custom pass policy returned 0; policy failure returned 1.
- Remote read-only integration probe confirmed a write to `/workspace` is rejected.
- Linux `linux-x64` Native AOT published and ran directly on an Ubuntu x86_64 SDK container attached to the remote Debian Docker daemon; `version`, `inspect`, and a real fixture scan passed expected outcomes.
- Final hardened image and AOT binary also passed remote empty-workspace, read-only, same-project, and different-project integration runs.

#### Remaining / deferred

- macOS RIDs remain unverified.
- Windows ACL behavior inherits the invoking user's temp/output ACL; Vesper does not rewrite ACLs.

#### Exit criteria

- [x] `win-x64` AOT publish and direct native execution pass.
- [x] Remote Docker transport, report export, and exit-code preservation pass.
- [x] Source mount is verified read-only in the remote test.

---

### M1.2 - Concurrent Isolated Scan Execution

**Status:** COMPLETE

**Goal:** Guarantee one isolated ephemeral execution and result location per invocation.

#### Completed

- Immutable `ScanExecutionContext` supplies one GUID to runner/container/volume labels and scan metadata.
- Unique container, source/output/config volumes, helper names, and scan-specific output directories.
- Resource labels include managed state, full scan ID, resource type, and sanitized project name. Cleanup verifies labels and removes only the current invocation's exact resources.
- Configurable per-scan CPU/memory/PID limits. No shared writable cache or worker container.

#### Verification

- 20 launcher tests pass, including creation of 256 contexts in parallel, identity/name uniqueness, resource ownership, output-path isolation, limits, deterministic timeout tests, and controlled daemon failure.
- Final `tests/test_concurrent_scans.ps1` runs passed remotely for same-project and different-project pairs using the current AOT binary and hardened image. Each pair observed distinct labeled runner containers, source/output volumes and IDs, separate report directories, and independent exits 1/0.
- Linux `test_linux_aot.ps1` cancelled scan A by SIGTERM while scan B retained its runner and source/output volumes, then completed with exit 0 and exported reports.
- No managed containers or volumes remained after the final runs.

#### Remaining / deferred

- There is no global concurrency scheduler; concurrent resource limits can exhaust the Docker host.

#### Exit criteria

- [x] Same-project and different-project remote concurrency verified.
- [x] Gate outcomes 0 and 1 were observed independently.
- [x] Cleanup is scoped by scan identity and no prune operation is used.

---

### M1.3 - Security and Reliability Hardening

**Status:** COMPLETE

**Goal:** Fail closed on incomplete security coverage and reduce exposure across scanner parsing, Docker, archive transfer, and build inputs.

#### Completed

- Empty/no-applicable and partial scanner failures now produce `executionStatus=incomplete`, `securityGate=indeterminate`, and exit 2; only a complete scan can return gate exit 0 or 1.
- Invalid JSON, unexpected root types, unsupported scanner-specific output envelopes, and normalization exceptions fail only that scanner and allow remaining adapters to run.
- OSV CVSS vectors are retained as vectors; only numeric scores are scored. Vector-only/malformed/missing scores remain unknown.
- Source/config/result archives are created mode `0600` on Unix; scan output and extraction staging directories are `0700`, report files are `0600`, and the runner uses restrictive umask.
- Archive extraction rejects traversal, absolute/drive-qualified paths, symlink/reparse-point parents and roots, and configured size/count limits. Output symlink/hardlink/special entries are ignored. Reports are validated in a private scan-specific staging directory before same-filesystem publish. Unix source filenames containing backslashes remain distinct from slash paths.
- Source and output transfers cap files, directories, every archive entry, bytes, per-file size, and derived PAX/header overhead. Result streams are bounded while being written to temporary files.
- Docker context is pinned for later commands; control, transfer, and runner operations have 60-second, 15-minute, and one-hour deadlines. Timeouts are injectable for deterministic process tests. POSIX SIGTERM requests per-invocation cancellation.
- Python versions and artifact hashes are locked and installed with pip `--require-hashes`; Python/Trivy/Alpine images are digest-pinned. OSV 2.3.3 is verified against official SHA256SUMS using its original release filename before rename. The runner Dockerfile has no apt installs. The default runner tag is versioned; digest-qualified `--image` overrides are accepted but digests are not enforced by default.
- Trivy, OSV-Scanner, and Semgrep each validate a minimal supported response envelope; available output schema/version metadata is preserved in scanner reports.
- Endpoint display removes URI userinfo/query/fragment. Cleanup inspection/removal failures are logged without printing source contents.
- Semgrep rules licensing restriction is documented; Vesper is not represented as hosted-ready.

#### Verification

- 29 Python tests pass, including supported/unsupported Trivy/OSV/Semgrep envelopes, Trivy's real v2 no-results envelope, schema version metadata, parser isolation, network failure, CVSS, policy, and incomplete execution.
- Launcher suite passes on Windows and on the remote Linux x86_64 test host. Linux executes live/dangling symlink-root/nested-parent/file cases, exact `0600`/`0700`, hardlink/FIFO ignore, and distinct `foo\\bar.txt` / `foo/bar.txt` cases; Windows skips symlink creation because the account lacks that capability.
- Deterministic stalling-child tests verify control and transfer deadlines terminate and classify timeout. A controlled Docker CLI disconnect preserves nonzero status/error text and maps failed export to exit 2; actual daemon disappearance after resource creation is UNVERIFIED because stopping the shared daemon is unsafe.
- Docker build passed with digest-pinned inputs, Python hash enforcement, no apt package installation, and OSV checksum verification. Built scanner versions were checked as Trivy 0.58.2, OSV-Scanner 2.3.3, and Semgrep 1.99.0.
- Windows `win-x64` Native AOT publish/direct execution passed. Linux `linux-x64` Native AOT published and ran directly on an Ubuntu x86_64 SDK container attached to the remote Debian Docker daemon; `version`, `inspect`, and a real vulnerable-fixture scan passed their expected outcomes.
- Linux AOT SIGTERM scan returned 2 and left no owned container/volumes. Concurrent real scans cancelled A while B retained its runner and unchanged volumes, then B completed with gate exit 0 and exported reports.
- `tests/test_linux_launcher.ps1` runs the full launcher test harness on Linux; `tests/test_linux_aot.ps1` reproduces Linux AOT, remote Docker scan, SIGTERM, and cancellation-isolation verification.
- Final remote empty-workspace run uploaded successfully, exported `incomplete`/`indeterminate` metadata, and returned exit 2.
- Final remote vulnerable fixture completed all three scanners, exported all expected artifacts, and returned exit 1; same- and different-project concurrency passed with independent `1`/`0` exits.
- Final Windows AOT remote verification: empty workspace returned 2 with incomplete/indeterminate reports; vulnerable fixture completed all scanners, exported reports, and returned 1; read-only source probe passed; no managed Docker resources remained.
- Final current-tree self-scan completed all three scanners and returned exit 1 with 38 findings / 36 remediations; the intentional vulnerable fixture is included, so this is not a clean product-only baseline.

#### Remaining Risks

- macOS runtime/AOT behavior remains unverified; M1.3's Unix filesystem acceptance is explicitly Linux-based. Windows ACLs continue to inherit from the invoking user and are not rewritten.
- Actual Docker daemon disappearance after volumes exist remains unverified; only the controlled DockerClient command-failure path is tested. Cleanup is best-effort and reports ownership/removal failures, but an unreachable daemon cannot be cleaned remotely until it returns.
- Scanner envelopes are intentionally minimal, not full schemas. Future output versions fail closed where version metadata exists; OSV 2.3.3 emits no distinct output-schema version field in the captured response.
- The default versioned runner tag is mutable. Digest-qualified `--image` overrides are supported; release automation must supply and record a digest. Runtime Trivy/OSV databases and Semgrep registry rules remain dynamic.
- Semgrep registry rules permit internal business use only under their current terms; hosted rule delivery is blocked pending licensing or a replacement ruleset.

#### Exit criteria

- [x] No scanner coverage or scanner/parser failures cannot produce a passed gate.
- [x] CVSS vectors cannot be misread as numeric scores.
- [x] Docker context, archive safety, resource limits, and report permissions have code/tests.
- [x] Linux filesystem tests pass on a real Linux runtime, including symlink and Unix filename cases; macOS is future platform verification and is not an M1.3 requirement.
- [x] POSIX SIGTERM and cancellation-isolation Docker integration pass; deterministic control/transfer timeout tests pass.
- [x] Scanner schema envelopes and build-time package/image/binary inputs are verified. Dynamic scanner databases/rules and the mutable default tag are explicitly accepted residual reproducibility risks; digest-qualified runner references are supported.

---

### M2 - Baseline and Finding Diff

**Status:** IN PROGRESS

**Goal:** Distinguish new, existing, changed, and resolved findings without losing raw findings or scanner evidence.

#### Scope

- Stable finding fingerprints, explicit baseline format, scan comparison, and CI gating on newly introduced policy violations.

#### Not in scope

- Database/history service, hosted orchestration, or automatic remediation.

#### In Progress

- New scan results are grouped by UTC execution date and time with a short scan-ID suffix. The full `scanId` remains authoritative in `scan.json`.
- One UTC `DateTimeOffset` is captured in `ScanExecutionContext` and reused for the result path, launcher/runner start logs, and `scan.json`; `finishedAt` and `durationMs` are persisted with it.
- `vesper report` and `vesper gate` read both date-grouped results and legacy `<scan-id>/` results without migrating old output.
- The Windows PowerShell wrapper uses the published Native AOT CLI only when it is no older than CLI source/build-property inputs; stale or absent binaries fall back to `dotnet run`.
- Baseline comparison and `comparison.json` generation are not implemented yet; ordinary scans do not create `comparison.json`. When added, comparison metadata must reuse `scanId` and `startedAt` from `scan.json`, not generate another timestamp.
- Report schema v2 marks `project.json`, `scan.json`, and `summary.json`; findings/remediations remain arrays with per-item schema markers and a schema manifest in `scan.json`. Finding totals, severity counts, and category counts appear only under `summary.json.findings`; redundant top-level aliases and the derived category/severity matrix are omitted.
- Project inventory reports artifact aggregates and excluded transient/output paths. Findings preserve native scanner titles/descriptions/IDs separately from package-aware normalized titles, confidence/applicability/reachability, finding nature, and contextual hardening metadata.
- Project descriptors, dependency manifests, scanner inputs, and project associations are separate. .NET projects associate only same-directory `packages.lock.json`/`packages.config` or matching descendant `<ProjectName>.deps.json`; solution files are project inventory, not dependency manifests.
- OSV invokes one process with repeated explicit `--lockfile` targets. `scan.json` records attempted/completed/failed targets and finding counts independently of vulnerability-result sources; `summary.json` carries only aggregate target counts. OSV 2.3.3's exact per-target failure granularity is process-wide, so a failed batched invocation marks every submitted target failed.
- Scanner-neutral capabilities aggregate detector assessments. OSV reports supported targets; Trivy coverage remains unknown when its JSON cannot prove zero-result targets or capability-specific coverage. Semgrep exposes attempted versus successfully parsed source files, parse-error paths/types, skipped paths when present, and rule counts only if emitted. Complete requires scanned/skipped lists, no reported errors/skipped rules, and a positive loaded-rule count; the pinned JSON omits that count.
- Coverage warnings are compact counts with details in `project.json`/`scan.json`, not hundreds of repeated paths in `summary.json`.
- Fixed-version recommendations are semantic-version checked, never downgrade, and select only a common compatible fix line that resolves every grouped advisory; all native candidates and the selection rationale remain in remediation output.
- Before writing final JSON artifacts, report invariants validate canonical finding counts, scanner provenance bounds, remediation references/files/identifiers, gate blocker references, and schema markers.

#### Audit Evidence

- The `Dast` self-scan has two `.csproj` descriptors and no associated NuGet lockfiles; it also contains a fixture `package-lock.json` with a sibling `package.json`. OSV 2.3.3 documents NuGet lockfiles/config/deps.json and npm package-lock; project descriptor association must not mistake a `.csproj` for the scanner input.
- Semgrep 1.99.0 reported 39 paths, including 12 C# files; Vesper matched 21 detected source candidates, observed one `PartialParsing` error for `Dockerfile`, and reported partial coverage. The nested Semgrep error type is normalized to its leading type name, and the bounded message is preserved. Skipped-path count was omitted because output did not provide it. Its JSON does not report rules loaded, so `rulesLoaded` remains unknown and clean execution is not presented as complete coverage.
- A no-cache runner image build completed and embedded-source SHA-256 values matched the workspace for `runner.py` and `scanners.py`. Remote self-scan `f47bd9ed-303e-4a34-8fbb-fb99d921c3d7` emitted schema-v2 reports, an 8-artifact inventory, 38 findings, and 36 remediations; all report invariants passed. OSV attempted and completed its one supported lockfile target and reported two unsupported .NET project descriptors. The configured gate returned 1 as expected. A synthetic regression preserves 25 DS026 findings individually and groups them into one contextual hardening remediation.
- That scan's 8 report files total 236,459 bytes; `summary.json` is 4,539 bytes. Reconstructing the removed aliases and category/severity matrix from the same data adds 552 bytes (16%) to compact-serialized summary JSON. No pre-change report bundle is retained in `security-results`, so an exact historical bundle-size comparison is unavailable.
- The Windows Native AOT publish could not be refreshed on this host because the Visual C++ desktop workload/linker is unavailable. The checked-in local executable is older than current CLI source; `vesper.ps1 report` and `vesper.ps1 gate` were verified through the source fallback against the fresh report. The published AOT artifact remains UNVERIFIED until rebuilt on a host with the required linker.
- The live minimist finding at 0.0.8 selects 0.2.4 as the highest common patch threshold on its 0.x minor line while preserving other candidates. Regression cases verify `System.Text.Json` 8.0.4 chooses 8.0.5 over 6.0.10, downgrade refusal, and no common target across disjoint branches.

#### Acceptance criteria

- [x] New scans use UTC `YYYY-MM-DD/HH-mm-ss_<short-scan-id>` directories, preserve the full scan ID in metadata, and retain read compatibility for legacy output directories.
- [x] Schema-v2 report metadata, measured scanner coverage, project inventory, native evidence, remediation rationale, and pre-write cross-artifact validation are deterministic and regression-tested.
- [x] Supported OSV manifests are distinguished from unsupported project descriptors; Semgrep coverage is based on observed file/error/rule metrics and never claims complete when loaded-rule count is unavailable.
- [x] Dependency scanners record submitted target states independently from findings; detailed target paths stay out of summary aggregates.
- [x] HEALTHCHECK and dependency reports preserve individual evidence while grouping shared fixes and documenting priority rationale.
- [ ] Baseline creation and comparison are deterministic.
- [ ] Findings retain audit evidence; status changes do not alter finding identity.
- [ ] New-finding gate behavior has focused tests.

---

### M3 - CI Distribution and Integration

**Status:** PLANNED

**Goal:** Make versioned Vesper image/CLI usage repeatable in CI providers and publish verified platform artifacts.

#### Acceptance criteria

- [ ] CI builds/tests/publishes pinned artifacts.
- [ ] At least one hosted CI workflow validates exit codes and report artifacts.
- [ ] Supported RIDs are published and runtime-smoke-tested on matching hosts.

---

### M4 - DAST and M5 - Centralized Orchestration

**Status:** DEFERRED

DAST (including ZAP/Nuclei), hosted APIs/UI, databases, queues, Kubernetes Jobs, distributed workers, SaaS execution, and shared caches are not implemented or scheduled in M1. Revisit only after M1.3 and CI readiness.

## Security Findings

| ID | Severity | Area | Status | Target | Summary |
|---|---|---|---|---|---|
| VSP-001 | High | Gate | RESOLVED | M1.3 | No applicable scanner or any applicable scanner failure yields an indeterminate gate and exit 2. |
| VSP-002 | High | Scanner parsing | RESOLVED | M1.3 | Empty/invalid JSON, unexpected root type, and normalization exceptions fail the adapter; later adapters continue. |
| VSP-003 | High | Severity/CVSS | RESOLVED | M1.3 | Only numeric CVSS scores are scored; v2/v3 vectors are preserved and vector-only scores remain unknown. |
| VSP-004 | High | Confidentiality | RESOLVED | M1.3 | Linux tests confirm archive/report files are `0600` and private output/staging directories are `0700`; Windows ACL inheritance remains documented. |
| VSP-005 | High | Supply chain | ACCEPTED | Before CI/release | Python package hashes, digest-pinned bases/helper, and OSV checksum are enforced. Residual: default versioned runner tag is mutable and runtime databases/rules are dynamic; digest-qualified override is supported and required for reproducible release use. |
| VSP-006 | Medium | Reliability | RESOLVED | M1.3 | Injected control/transfer deadlines terminate stalling processes; Linux SIGTERM and cancellation isolation pass against real Docker. Actual daemon loss remains a documented unknown. |
| VSP-007 | Medium | Workspace integrity | RESOLVED | M1.3 | Linux archive round-trip keeps literal backslash and slash filenames distinct; symlink source entries are skipped. |
| VSP-008 | Medium | Result extraction | RESOLVED | M1.3 | Linux rejects symlink roots and nested symlink parents; hardlink/FIFO/symlink archive entries are ignored; extraction is staged before publish. |
| VSP-009 | Medium | Parser resilience | RESOLVED | M1.3 | Scanner-specific envelope/version checks reject unsupported valid JSON and fail closed while independent adapters continue. |
| VSP-010 | Medium | Resource exhaustion | RESOLVED | M1.3 | Source/output file, byte, per-file, total-entry, and derived tar/PAX byte limits are enforced, including streaming Docker output. |
| VSP-011 | Medium | Docker context | RESOLVED | M1.3 | Context/host is pinned for Docker operations in a scan; remote inspect/scan verified. |
| VSP-012 | High | Licensing | ACCEPTED | Before hosted use | Semgrep registry rules are internal-use-only under current terms; hosted Vesper must replace rules or obtain rights. |
| VSP-013 | Medium | Remote transport | RESOLVED | M1.3 | Empty workspace now uploads a valid root-entry tar and returns incomplete/indeterminate rather than failing before runner. |
| VSP-014 | Medium | CLI gate | RESOLVED | M1.3 | Saved `vesper gate` returns 2 for indeterminate/unknown status, never 0. |

### Resolved Finding Evidence

- **VSP-001:** `test_empty_workspace_with_no_applicable_scanners_is_incomplete`, `test_all_applicable_scanners_failed_is_incomplete`, and `test_parser_failure_isolated_and_run_marked_incomplete`; remote empty-workspace scan returned 2 and exported incomplete/indeterminate reports.
- **VSP-002:** `test_invalid_json_and_unexpected_json_types_fail_scanner` and the parser-orchestration test prove a later clean adapter runs while overall execution stays incomplete.
- **VSP-003:** `test_osv_cvss_numeric_scores_and_vectors` covers numeric score, CVSS v2/v3.0/v3.1, malformed, and missing values. A vector never becomes a score.
- **VSP-011:** Docker target pinning unit test and remote AOT `inspect`, empty, fixture, and concurrent scans.
- **VSP-013:** Empty-workspace remote upload reached the runner and exported reports after the root-entry tar fix.
- **VSP-014:** `test_saved_gate_exit_semantics` checks passed=0, failed=1, indeterminate/unknown=2.
- **VSP-004:** Linux `PrivateArchivePermissions` and `ArchiveRoundTrip` assert exact `0600` archive/report and `0700` extraction-root modes; `test_linux_launcher.ps1` runs them on the remote Linux x86_64 host.
- **VSP-005:** Docker build passes `pip install --require-hashes`; Python base and Trivy source are digest-pinned; `LauncherImages.ArchiveHelper` contains Alpine version+digest; OSV official `SHA256SUMS` is checked against the original `osv-scanner_linux_<arch>` filename before rename. Mutable default runner tag and dynamic scan data are accepted as documented residuals.
- **VSP-006:** Launcher `Docker control timeout`, `Docker transfer timeout`, and `Docker daemon disconnect classification` tests pass. `test_linux_aot.ps1` observed POSIX SIGTERM exit 2, current-scan cleanup, and an independent concurrent scan B completion/exit 0. Real daemon disappearance is UNVERIFIED.
- **VSP-007:** Linux `PreserveUnixBackslashFilename` archives/extracts `foo\\bar.txt` and `foo/bar.txt` as distinct files; `test_linux_aot.ps1` additionally uploaded the Vesper-generated archive through the pinned helper into a Docker volume and verified both exact filenames and contents.
- **VSP-008:** Linux `RejectSymlinkOutputParent` checks direct/nested live and dangling symlink parents/roots, direct symlink files, and outside-file integrity; `IgnoreSpecialArchiveEntries` confirms symlink/hardlink/FIFO entries are not created. Linux AOT integration also exercised staged remote report publication.
- **VSP-009:** Python `test_scanner_schema_envelopes_and_versions_are_preserved`, `test_unsupported_scanner_envelopes_fail_closed`, and `test_schema_failure_isolated_and_network_failure_is_not_clean`; captured pinned-tool raw reports anchored Trivy 2, OSV results/source/packages, and Semgrep version/results/errors envelopes.
- **VSP-010:** Launcher `workspace transfer limit validation` tests aggregate bytes, per-file bytes, files, directory-only entries, and rejected tar entry counts; Docker download applies a streaming derived archive-byte ceiling.

## Architectural Decisions

- **ADR-001:** Keep the scanner engine in Python; do not migrate it to the host CLI.
- **ADR-002:** Use a small .NET 10 Native AOT host launcher; `win-x64` and `linux-x64` are verified, while macOS remains unverified.
- **ADR-003:** Keep Docker CLI as the transport/runtime boundary; no Docker SDK or shell intermediary.
- **ADR-004:** One invocation owns one ephemeral runner and unique scan resources.
- **ADR-005:** Remote workspaces/results move as binary tar streams through Docker stdin/stdout and temporary volumes.
- **ADR-006:** `/workspace` is read-only; `/output` is scan-specific writable storage; `/tmp` is private tmpfs.
- **ADR-007:** Launcher does not parse scanner findings; runner does not manage Docker resources.
- **ADR-008:** Do not share mutable scanner caches between scans in M1.
- **ADR-009:** Gate pass requires complete applicable scanner coverage; execution and security assessment are separate.
- **ADR-010:** Semgrep engine and registry-rule rights are separate; current registry rules preclude hosted delivery.

## Technical Debt

- No CI pipeline, standard .NET test framework, or automated cross-platform AOT matrix exists.
- Actual daemon loss after resource creation is unverified; cleanup remains best-effort while the endpoint is unreachable.
- macOS Native AOT/filesystem behavior and local Docker Desktop bind-mode acceptance are unverified.
- The true Lynx raw scan report is absent; its stated 31 findings / 5 remediations remains UNVERIFIED.

## Known Limitations

- The Docker daemon is a privileged host trust boundary; remote Docker operators can inspect staged source and results.
- Container isolation is not equivalent to a VM; scanners need outbound network access for vulnerability data and Semgrep rules.
- Linux x64 AOT is published and runtime-tested; macOS has not been tested. Windows output ACLs inherit from the invoking user and are not rewritten by Vesper.
- Semgrep registry rules may change independently of the pinned engine and are not available for hosted service distribution under their current license.
- There is no global scheduler; concurrent per-scan limits can exhaust host memory/CPU/disk.

## Deferred Work

- Baseline/diff (M2), CI-provider workflows (M3), DAST, additional scanners, SBOM product features, shared scanner caches, orphan cleanup command, Kubernetes Jobs, centralized workers, SaaS/API/UI, and AI remediation.
- A Vesper release-image SBOM may be added as supply-chain metadata; no SBOM ingestion platform is planned here.

## Not Implemented Yet

- DAST, OWASP ZAP, Nuclei, web UI, REST API, PostgreSQL, Redis/queues, Kubernetes Jobs, hosted multi-user service, GitHub/GitLab integrations, baseline/diff, AI remediation, and distributed workers.

## Product Readiness

| Scenario | Status | Notes |
|---|---|---|
| Local developer use | CONDITIONAL | Windows and Linux x64 AOT plus remote Docker are tested; local Docker Desktop bind-mode acceptance and macOS runtime remain unverified. |
| Internal trusted repositories | READY | Fail-closed coverage, pinned build inputs, Linux filesystem tests, remote scan, and cancellation isolation are verified; Semgrep registry rules remain internal-use-only. |
| CI security gate | CONDITIONAL | Core exit/report behavior is verified, but M3 CI workflows, published artifacts, digest stamping, and provider-specific acceptance remain out of scope. |
| Untrusted repositories | CONDITIONAL | Archive/schema defenses and cancellation isolation are tested; Docker host trust, dynamic scanner egress, daemon-loss cleanup, and global concurrency capacity remain constraints. |
| Hosted multi-user service | NOT READY | Semgrep rule license restricts service use; remote Docker is host-privileged; no tenancy/scheduler exists. |

## Next Recommended Work

1. Keep macOS runtime/AOT and actual daemon-disappearance verification as explicit platform/environment validation work.
2. Make M3 publish the runner manifest digest and CLI together; the default local development tag remains versioned for usability.
3. Run the real Lynx reports as a non-hardcoded regression fixture before planning M2 baseline/diff.

## Future Development Workflow

1. Read `docs/PRODUCT_STATUS.md` before substantial work.
2. Inspect implementation relevant to the requested milestone; PLANNED scope is not existing capability.
3. Preserve architectural decisions unless explicitly revisiting them.
4. Implement only the requested scope and run its acceptance tests.
5. Update milestone status, findings, and limitations in this file in the same change when product state materially changes.
6. Mark a milestone COMPLETE only with concrete test/build/integration evidence; state unverified platform behavior explicitly.

## Product Status Change Log

### 2026-10-01

- Established Vesper M1/M1.1/M1.2 status from source, tests, AOT publish, and remote Docker runs; Git history contains only the initial repository snapshot, so earlier dates/order are not inferred.
- Recorded M1.3 as IN PROGRESS and security findings VSP-001 through VSP-014 with statuses and verification.
- Documented M2 baseline/diff as the next product milestone and recorded CI, DAST, and hosted execution as later/not implemented.
- Reverified the empty-scan indeterminate exit, read-only workspace, same/different-project concurrency, and current-tree self-scan with the final AOT binary/image.
- Completed M1.3 after Linux filesystem/AOT/signal integration, scanner-envelope and network-failure tests, archive-entry/metadata bounds, and hash-enforced runner build verification. A final dangling-symlink review added direct attribute checks and Linux regression cases before completion. macOS and real daemon-loss behavior remain explicitly UNVERIFIED; runner digest enforcement is accepted for M3 release work.
- Started the M2 result-organization slice: new results use one captured UTC timestamp for date/time grouping and scan metadata; legacy report lookup remains supported. Baseline comparison is still unimplemented.

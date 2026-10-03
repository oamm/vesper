# Vesper Product Status

**Last updated:** 2026-10-02
**Current version:** 0.2.0
**Current milestone:** M5 - DAST and Runtime Security (PLANNED)
**Overall status:** M4 COMPLETE; M5 PLANNED

## Product Goal

Vesper is a developer- and CI-oriented application security analysis and policy tool. It orchestrates open-source scanners inside an isolated Docker execution, normalizes and deduplicates their findings, groups findings into actionable remediations, and evaluates a security gate. It is not currently a hosted service or general AppSec platform.

## Current Architecture

```text
Developer / CI
    -> vesper (.NET 10 Native AOT host CLI)
       -> Docker CLI and selected context
          -> one ephemeral vesper-runner container per scan
             -> Python orchestration and project detection
             -> Trivy / OSV-Scanner / Semgrep / Syft / Grype / Gitleaks / Scorecard
             -> normalization / posture evidence / deduplication / remediation groups / policy / reports
```

- The launcher owns Docker context selection, host paths, source/result transport, per-scan resources, process control, and exit-code forwarding.
- The Python runner owns project detection, scanner adapters, parsing, normalized findings, remediation grouping, policy evaluation, and reports.
- The runner contract is `/workspace` (read-only), `/output` (scan-specific writable volume), and `SECURITY_SCAN_ID`.
- Local mode uses bind mounts. Remote mode stages files through Docker stdin/stdout and uniquely named volumes using the digest-pinned Alpine tar helper.
- Every scan has one full GUID, one ephemeral runner container, one isolated source volume and output volume in volume mode, and one report directory under `<output-base>/YYYY-MM-DD/HH-mm-ss_<short-scan-id>` using the captured UTC start time.
- Scanner caches are per-container. No shared mutable cache, server, queue, database, or Kubernetes integration exists.

## Current Capabilities

- Scanner image: Trivy 0.58.2, OSV-Scanner 2.3.3, Semgrep 1.99.0, Syft 1.52.0, Grype 0.119.0, Gitleaks 8.30.1, and OpenSSF Scorecard 5.5.0; image default is `vesper-runner:0.2.0`.
- Host CLI: .NET 10 Native AOT; Windows `win-x64` and Linux `linux-x64` have been published and runtime-tested.
- Docker endpoint classification supports npipe, Unix socket, SSH, loopback and remote TCP/HTTP(S); Docker calls are pinned to the context/host selected at scan start.
- Local bind and remote volume workspace modes; source archives exclude common generated directories and enforce byte/file/per-file ceilings.
- Scan-specific report directories, labeled Docker resources, bounded Docker operation timeouts, runner limits, fail-closed execution completeness, and per-scan cleanup.
- Reports include `project.json`, `scan.json`, `findings.json`, `remediations.json`, `summary.json`, and raw scanner artifacts. M3.1 additionally emits a versioned `components.json` inventory and compact component summary; M3.4 emits a separate versioned `posture.json` artifact when Scorecard is applicable; M4.1 emits a versioned `api-contract.json` artifact for an available local OpenAPI contract. A completed scan can create a versioned `baseline.json`; scans with a baseline emit a separate `comparison.json` without mutating current findings.
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

- Empty/no-applicable and partial scanner failures now produce `executionStatus=incomplete` and exit 2; scans with no known policy blocker retain `securityGate=indeterminate`, while known policy blockers remain `failed` and carry the execution limitation separately. Only a complete scan can return gate exit 0 or 1.
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

**Status:** COMPLETE

**Goal:** Distinguish new, existing, changed, and resolved findings without losing raw findings or scanner evidence.

#### Scope

- Stable finding fingerprints, explicit baseline format, scan comparison, and CI gating on newly introduced policy violations.

#### Not in scope

- Database/history service, hosted orchestration, or automatic remediation.

#### Completed

- New scans use UTC date/time result directories and saved reports remain readable across legacy and date-grouped layouts.
- Baseline schema v1 is created only from completed schema-v2 report sets; a failed security gate does not disqualify existing security debt. Baselines validate their metadata, identity version, duplicate identities, target paths, coverage structure, and deterministic content digest.
- Existing finding fingerprints remain `fingerprintVersion: 2`. Baseline `identityVersion: 1` is scanner-neutral and matches by semantic identifier candidates. Dependency identity uses capability, project-relative target, ecosystem, package, and canonical vulnerability ID; SAST/config identity uses capability, target, rule, and line. Severity, installed version, and recommended version are material state fields; detector set, added aliases, native prose, timestamps, and execution order are not.
- `comparison.json` is emitted only with `--baseline` and reports `new`, `existing`, `changed`, `resolved`, and `unverified` without mutating `findings.json`. Output ordering is deterministic and resolved/unverified entries preserve minimal baseline evidence.
- Resolution requires positive capability/target evidence. Completed OSV targets and fully evidenced Semgrep target/rule coverage can prove resolution. Failed/uncovered OSV targets, Semgrep parse errors or unknown rule coverage, and Trivy's current unknown zero-result coverage remain `unverified`.
- `baseline.failOnNew` defaults to critical/high and combines with the existing absolute policy. Baseline creation uses `python -m security_runner.baseline_cli create <scan-result-dir> --output baseline.json`; `vesper scan --baseline` stages the artifact read-only, and `vesper report`/`vesper gate` validate saved comparison artifacts.
- The Windows PowerShell wrapper uses Native AOT only when the binary is at least as recent as CLI source/build inputs; a stale or absent publish falls back to `dotnet run`.
- Report schema v2 keeps finding totals only under `summary.json.findings`; redundant aliases and the derived matrix are omitted. Project inventory, OSV explicit target states, Semgrep analyzed files/parse errors, Trivy unknown assessments, capability coverage, multi-scanner provenance, and cross-artifact validation remain intact.
- Project descriptors, dependency manifests, and scanner inputs remain separate; fixed-version selection never downgrades and recommends only a common compatible fix line.

#### Audit Evidence

- The `Dast` self-scan has two `.csproj` descriptors and no associated NuGet lockfiles; it also contains a fixture `package-lock.json` with a sibling `package.json`. OSV 2.3.3 documents NuGet lockfiles/config/deps.json and npm package-lock; project descriptor association must not mistake a `.csproj` for the scanner input.
- Semgrep 1.99.0 reported 39 paths, including 12 C# files; Vesper matched 21 detected source candidates, observed one `PartialParsing` error for `Dockerfile`, and reported partial coverage. The nested Semgrep error type is normalized to its leading type name, and the bounded message is preserved. Skipped-path count was omitted because output did not provide it. Its JSON does not report rules loaded, so `rulesLoaded` remains unknown and clean execution is not presented as complete coverage.
- Synthetic tests cover deterministic baseline creation, malformed/incomplete rejection, all five states, alias/detector stability, Windows/Linux path normalization, OSV success/failure, Semgrep successful/parse-error coverage, Trivy unknown coverage, existing-debt pass, new-high fail, new-low pass, changed severity, saved gate reproduction, and corrupted artifacts failing with exit 2.
- Real Lynx unchanged-baseline regression: initial completed scan had 31 findings / 5 remediations; final scan `f02d0198-2ac2-4505-a2e1-1f8c2b46564c` also had 31 / 5. `comparison.json` recorded `new=0`, `existing=31`, `changed=0`, `resolved=0`, `unverified=0`; baseline-aware gate passed. The exported saved report displayed the counts, and saved `vesper gate` reproduced PASS. Lynx remained unmodified.
- The final runner image was built without cache and embedded-source SHA-256 values matched the workspace for all seven changed Python modules. The final Lynx scan used 3 scanners; OSV coverage completed, Semgrep reported 24 parse errors (so its coverage remains partial), and Trivy coverage remains unknown. No resolution was inferred from those partial/unknown assessments.
- That scan's 8 report files total 236,459 bytes; `summary.json` is 4,539 bytes. Reconstructing the removed aliases and category/severity matrix from the same data adds 552 bytes (16%) to compact-serialized summary JSON. No pre-change report bundle is retained in `security-results`, so an exact historical bundle-size comparison is unavailable.
- The Windows Native AOT publish could not be refreshed on this host because the Visual C++ desktop workload/linker is unavailable. The checked-in local executable is older than current CLI source; source fallback for `report`/`gate` and source-built .NET tests pass. The published AOT artifact remains UNVERIFIED; this does not block the Python baseline runner or M2 acceptance.
- The live minimist finding at 0.0.8 selects 0.2.4 as the highest common patch threshold on its 0.x minor line while preserving other candidates. Regression cases verify `System.Text.Json` 8.0.4 chooses 8.0.5 over 6.0.10, downgrade refusal, and no common target across disjoint branches.
- Fresh current-schema Lynx acceptance completed through the trusted remote Docker endpoint using the PowerShell source fallback. Scan A `858314fb-92c1-4a02-979c-cb046853b19e` and Scan B `c028d89a-6ccf-4ef5-bcc9-afa9a4ac271c` each completed with 31 findings / 5 remediations. Baseline `baseline-44e97e0952684215e79ce4740d58c71d7d73ac07b8126686d6b5428964801eeb` validated with schema v1, identity version 1, fingerprint version 2, source metadata, coverage, and content digest. Comparison recorded `NEW=0`, `EXISTING=31`, `CHANGED=0`, `RESOLVED=0`, `UNVERIFIED=0`; the absolute gate failed on the existing three HIGH findings, while the baseline delta passed. Saved `vesper report` exited 0, saved `vesper gate` reproduced exit 1, and a corrupted comparison returned exit 2. OSV coverage was complete; Semgrep remained partial with 24 parse errors; Trivy coverage remained unknown. No dynamic-data difference appeared between the two scans.
- Final acceptance verification ran 62 Python tests and the .NET launcher acceptance suite; the launcher used source fallback because the Windows Visual C++ linker remains unavailable for a fresh Native AOT publish. The verified remote ECDSA host fingerprint was `SHA256:O4IV7/BSipd4ZxR0X0yoLIkgvhRlC2eUaRXM0/YoMcw`, matching the independently inspected host key; no Vesper endpoint defect was found.

#### Acceptance criteria

- [x] New scans use UTC `YYYY-MM-DD/HH-mm-ss_<short-scan-id>` directories, preserve the full scan ID in metadata, and retain read compatibility for legacy output directories.
- [x] Schema-v2 report metadata, measured scanner coverage, project inventory, native evidence, remediation rationale, and pre-write cross-artifact validation are deterministic and regression-tested.
- [x] Supported OSV manifests are distinguished from unsupported project descriptors; Semgrep coverage is based on observed file/error/rule metrics and never claims complete when loaded-rule count is unavailable.
- [x] Dependency scanners record submitted target states independently from findings; detailed target paths stay out of summary aggregates.
- [x] HEALTHCHECK and dependency reports preserve individual evidence while grouping shared fixes and documenting priority rationale.
- [x] Versioned deterministic baseline creation rejects incomplete/corrupt/unsupported reports; a completed failed-gate scan remains eligible.
- [x] Versioned scanner-neutral finding identity preserves `fingerprintVersion: 2`; identity/status changes retain current evidence.
- [x] Deterministic `NEW`/`EXISTING`/`CHANGED`/`RESOLVED`/`UNVERIFIED` comparisons preserve separate `comparison.json` and `findings.json` artifacts.
- [x] Coverage-aware resolution requires capability/target success; OSV, Semgrep parse failures, Trivy unknown coverage, unsupported coverage, and incomplete executions are conservative.
- [x] New-only gate, saved `vesper report`/`vesper gate`, fail-closed comparison validation, and report consistency have regression coverage.
- [x] Synthetic integration matrix and real Lynx unchanged-baseline regression passed with `NEW=0`, `EXISTING=31`, `CHANGED=0`, `RESOLVED=0`, `UNVERIFIED=0`.

---

### M3 - Artifact and Supply Chain Security

**Status:** COMPLETE

**Goal:** Extend Vesper beyond source-tree findings into software artifacts, dependency inventory, SBOMs, Git history, and deterministic supply-chain evidence.

**Candidate engines:** Syft, Grype, Gitleaks, and OpenSSF Scorecard.

**Potential scope:** SBOM generation; CycloneDX / SPDX; container/image component inventory; SBOM vulnerability analysis; Git-history secret scanning; open-source supply-chain posture; and license/component metadata.

Do not add tools simply to increase scanner count. Each engine must add a distinct security capability or meaningfully improve evidence quality.

#### M3.1 - SBOM Foundation

**Status:** COMPLETE

Syft 1.52.0 is pinned to its official release archive and verified against the release checksum during the runner image build. Vesper invokes it as an isolated scanner and retains the native CycloneDX JSON artifact at `raw/syft.cdx.json`.

The normalized `components.json` schema v1 separates semantic components from occurrence locations. Component identity uses a normalized PURL when available and otherwise `ecosystem + name + version`; Syft-native references and discovery properties remain provenance evidence. Occurrence paths are repository-relative, deduplicated, and deterministically ordered. File entries without package versions use the explicit `unknown` version rather than being silently discarded.

Syft execution status, attempted target, coverage assessment, and component count are recorded independently in `scan.json`. A zero-component inventory is `limited`, not proof of complete coverage. Summary output contains only deterministic component totals, occurrence totals, and ecosystem counts; component presence does not affect the security gate.

Focused normalization, PURL/fallback identity, duplicate occurrence, schema rejection, malformed-output, process-failure, raw-retention, and deterministic-order tests pass. The real Lynx regression completed with 596 normalized components, 17,431 occurrences, 445 NuGet components, 151 unknown/file components, 12.44 seconds Syft duration, a 23,437,505-byte raw SBOM, and a 6,168,089-byte normalized artifact. The report marked the attempted workspace target complete; that does not establish package-manager completeness beyond the target and evidence Syft provided. An observational comparison found the four vulnerable packages reported by OSV/Trivy were absent from this Syft inventory because those findings target `Invoice/packages.config`, while Syft cataloged the repository's lockfile/package sources; this is not correlation logic. M3.2 consumes this inventory but does not fill its gaps with independent vulnerability evidence.

M3 decomposition remains:

```text
M3.1 SBOM Foundation                    COMPLETE
     Syft
M3.2 Artifact Vulnerability Analysis    COMPLETE
     Grype
M3.3 Repository Secret History          COMPLETE
     Gitleaks
M3.4 Supply Chain Posture                COMPLETE
     OpenSSF Scorecard
M3.5 M3 Integration and Acceptance      COMPLETE
```

#### M3.2 - Artifact Vulnerability Analysis

**Status:** COMPLETE

Grype 0.119.0 is pinned to the official Linux amd64 release archive and verified against the published checksum during the runner image build. The release is Apache-2.0 licensed. Grype consumes the retained `raw/syft.cdx.json` CycloneDX artifact rather than independently rescanning the workspace. Native output is retained at `raw/grype.json` and normalized into the existing dependency finding model.

Grype findings use the existing `fingerprintVersion: 2` semantic identity: dependency capability, project-relative target, ecosystem, package, and canonical vulnerability identifier. Component IDs, PURLs, occurrence locations, native match metadata, native severity, and fixed-version candidates remain evidence; they do not become a second identity system. Grype is included in dependency coverage and detector corroboration, so agreement with OSV or Trivy deduplicates to one finding without changing severity or gate policy.

Grype coverage is explicitly derived from the Syft input assessment. `scan.json` records the SBOM input, input coverage, analysis status, match count, and database metadata when Grype emits it. Component presence does not affect the gate, and a missing Grype result cannot prove resolution.

Synthetic tests cover valid and malformed Grype envelopes, process failure, component linkage, PURL identity, fixed-version propagation, Grype/Trivy deduplication, scanner-neutral fingerprints, database metadata retention, report invariants, and coverage-loss baseline behavior. The first real Lynx attempt failed with exit `-9`; host kernel logs classified this as `CONSTRAINT_MEMCG` OOM in the runner container, with Grype as the killed process. This was a container memory-limit failure, not disk exhaustion: the Docker host reported a 32 GB filesystem with 19 GB available and 4% inode use, while the runner was limited to 4 GiB. A focused Grype run succeeded under the same 4 GiB isolation constraints, establishing that the full pipeline's aggregate memory pressure triggered the failure. The unchanged full scan reproduced the OOM at 4 GiB and completed at an explicitly raised 6 GiB per-scan limit. The selected policy keeps the bounded 4 GiB default for safer concurrency and documents `--memory 6g` as an explicit override for larger artifact/SBOM workloads; no scanner-specific exception or unlimited memory was added.

The final database-backed Lynx scan used source fallback through the trusted remote SSH Docker endpoint with `--cpus 2 --memory 6g --pids-limit 512`. Scan `3575fa9a-e723-4c09-a7b2-8fa81cf2e7be` completed with 31 findings, 5 remediations, and the existing absolute gate failed on three HIGH findings. Syft produced 596 normalized components and 17,431 occurrences in 12.2 seconds; the raw CycloneDX artifact was 23,437,505 bytes and `components.json` was 6,168,089 bytes. Grype initialized database schema `v6.1.9`, built `2026-10-02T06:31:53Z`, with a valid database URL/checksum identity, and retained a 9,000-byte `raw/grype.json` artifact. It completed in 90.3 seconds with zero matches and therefore contributed no normalized findings or detector corroboration on Lynx.

The four OSV/Trivy-vulnerable packages associated with `Invoice/packages.config` remain absent from the Syft SBOM and consequently absent from Grype's input. This is consistent with Syft cataloging the repository's lockfile/package sources rather than that legacy packages.config input. Grype cannot claim coverage for those packages; its report records `analysisStatus: completed` but `inputAssessment: unknown` and overall coverage `unknown`. The finding set remains the independent OSV/Trivy evidence, not a claim of SBOM completeness.

The real vulnerable fixture acceptance used the existing npm `minimist@0.0.8` fixture with the live Syft and Grype engines under the explicit 6 GiB limit. Scan `ab6650a1-9bf6-49b2-97fd-f9fd53872a77` emitted the component `pkg:npm/minimist@0.0.8` at `package-lock.json`; Grype produced `GHSA-xvch-5gv4-984h` (CRITICAL, fixed `0.2.4`) and `GHSA-vh95-rmgr-6w4m` (MEDIUM, fixed `0.2.1`). Each normalized finding retained its component ID, PURL, occurrence, native Grype evidence, database metadata, and existing remediation selection. OSV and Trivy corroborated both findings, producing one semantic finding per vulnerability with detector sets `grype`, `osv-scanner`, and `trivy`. The fixture scan completed with 39 findings and 38 remediations; baseline `baseline-5ffffdf8e8f05961615f6120ea571999073d0dc790ac3b6e4e735ab5bd2f8ac7` and unchanged scan `0c18c2e6-be56-4479-bdec-59edf905da86` recorded `NEW=0`, `EXISTING=39`, `CHANGED=0`, `RESOLVED=0`, and `UNVERIFIED=0`. The four-package Lynx `packages.config` gap remains a documented input-coverage limitation.

#### M3.3 - Repository Secret History

**Status:** COMPLETE

Gitleaks 8.30.1 is pinned to the official Linux x64 release archive and verified against the published checksum during image build. The release is MIT licensed. The isolated adapter uses Gitleaks `git` history mode with `--redact`, `--log-opts=--all`, JSON output, and an explicit exit code. It does not silently use working-tree scanning as a substitute for history scanning. The runner image includes the Git executable required by Gitleaks and passes a process-scoped `safe.directory=/workspace` setting because staged remote volumes are owned by a different transport user.

Git history scanning is opt-in through `--include-git`. Remote volume transport includes `.git` only for that option; default archive exclusions remain unchanged. The representative fixture transferred 46 files, including approximately 40 KB of Git metadata, and Gitleaks completed in about 0.9 seconds. Local bind mode still exposes the workspace normally, but the runner receives the same explicit capability flag, so a mounted `.git` directory is not traversed accidentally.

Gitleaks native JSON is retained at `raw/gitleaks.json` after redacting `Match`, `Secret`, line-content/fragments, diffs, and fingerprints. Normalized findings record only rule, repository-relative file, line, commit, date, and a generic rotation/removal message. Historical scope is explicit (`currentPresence: unknown`); plaintext secrets, author/email metadata, and native secret values are not copied into normalized reports, logs, summaries, baselines, comparisons, or HTML.

Coverage records whether Git metadata was requested and available, whether history is complete or shallow, and whether traversal completed. Missing `.git` or omitted `--include-git` is `not_applicable`; shallow history is `partial`. Neither condition is clean-history evidence. A history-only baseline finding cannot become `RESOLVED` when history is unavailable. Gitleaks failures preserve independent scanner evidence and make execution incomplete/assessment indeterminate under existing fail-closed rules.

The remote acceptance fixture contained deleted AWS/private-key material in reachable commits while the current working tree was clean. Scan `6237e7ee-06b2-4571-bfce-3b7828f00421` completed with two historical-only findings, two remediations, and a failed secret policy gate; raw output contained redacted native fields only. An unchanged rerun with baseline `baseline-a721fe240b2314d8ccc3e59be1cd92ab4836c2dd5e350477d23e33de3f0670eb` recorded `NEW=0`, `EXISTING=2`, `CHANGED=0`, `RESOLVED=0`, and `UNVERIFIED=0`. The generated HTML report contained neither the fixture secret nor a raw secret value. This is representative acceptance evidence; Lynx is a separate regression and is not required to contain secrets.

Focused tests cover explicit applicability, redacted native output, commit-stable identity, history provenance, and list-shaped Gitleaks output. The runner image build and remote volume scan passed. Current limitations are conservative current-vs-historical correlation, no recursive nested-repository traversal, and no claim of complete history for shallow or unavailable Git metadata.

#### M3.4 - Supply Chain Posture

**Status:** COMPLETE

OpenSSF Scorecard `v5.5.0` is pinned to the official Linux amd64 release archive and verified against `scorecard_checksums.txt` during the runner image build. The release is Apache-2.0 licensed. Vesper invokes Scorecard's explicit local mode only when `--include-git` is requested and Git metadata is present; it does not silently require or perform provider API access.

Scorecard native JSON is retained at `raw/scorecard.json`. The normalized `posture.json` schema v1 keeps repository identity, native aggregate/check scores, check-specific reason/documentation/evidence, evidence source, and explicit states (`PASS`, `FAIL`, `WARN`, `UNKNOWN`, `NOT_APPLICABLE`, `ERROR`). Scorecard's native `-1` check result is `NOT_APPLICABLE`, not a posture failure. Posture evidence is separate from `findings.json`, severity, baseline comparison, and the security gate.

Repository origin normalization strips credentials and normalizes common GitHub HTTPS/SSH forms. Local-only repositories remain usable: without explicit Git transport Scorecard is `not_applicable`, never clean or PASS. Local mode reports partial posture coverage because provider-backed checks were not evaluated; missing provider evidence is not treated as success. Scorecard failures remain scanner failures under the existing fail-closed execution behavior while independent findings are preserved.

The real acceptance used a controlled Git fixture through the remote Docker volume path with `--include-git`, runner image `vesper-runner:m34`, and the live Scorecard binary. Final scan `362740ca-2642-42b4-bd2a-8d8ffb17f354` completed in approximately 0.6 seconds with a 4,474-byte raw Scorecard artifact, native aggregate score `3.8`, and 11 normalized checks: 2 PASS, 5 FAIL, and 4 NOT_APPLICABLE. The fixture was local-only, so provider-backed checks were not evaluated and posture coverage was `partial`.

The HTML report includes a posture section with repository identity, aggregate score, coverage, check state, score, reason, evidence source, and a `posture.json` artifact link. Scorecard scores are displayed as posture metadata only; they do not fail the gate. No provider credentials or unnecessary personal metadata are persisted. Deterministic tests cover valid/invalid envelopes, URL credential sanitization, ordering, state counts, report invariants, and posture HTML rendering. Posture comparison or policy projection remains outside M3 and is deferred to later policy work.

#### M3.5 - M3 Integration and Acceptance

**Status:** COMPLETE

M3.5 validated the complete seven-engine M3 pipeline without adding a scanner: Trivy, OSV-Scanner, Semgrep, Syft, Grype, Gitleaks, and OpenSSF Scorecard. The integrated fixture scan `2e40dc31-690d-41f8-b346-b1393f4bb654` and unchanged baseline rerun `579bd4aa-5219-424d-a061-fee629212ec0` completed through remote Docker volume transport with `--include-git` and an explicit `--memory 6g` limit. The rerun produced 39 findings and 38 remediations; the comparison was `NEW=0`, `EXISTING=39`, `CHANGED=0`, `RESOLVED=0`, `UNVERIFIED=0`. Components, findings, remediations, posture, scanner metadata, raw artifacts, and summary totals passed cross-artifact validation. The baseline ID was `baseline-fb89eeefbbe1fa34a8422b53e47157f5538f4ea52ef654c8b6d9f318f245847b`.

The integrated fixture's compact inventory, raw evidence, normalized findings, remediations, posture, and HTML were independently validated. The real Lynx acceptance scan `7465adc4-bc2b-4539-8cd7-4ab14900ba6a` completed all seven scanners in 163.3 seconds with 49 findings, 23 remediations, 596 components, and 17,431 occurrences. Syft completed in 12.2 seconds; Grype completed in 91.0 seconds with valid database-backed metadata and no Lynx matches; Gitleaks produced 18 historical-scope findings; Scorecard produced 11 local checks with partial coverage. Semgrep completed with partial coverage and 24 parse errors; Trivy coverage remained unknown; OSV coverage completed. The existing policy gate failed on three HIGH findings and 18 secret findings while execution remained `completed`.

The report set uses versioned schemas: report artifacts v2, baseline v1, comparison v1, components v1, and posture v1. `vesper report`, `vesper report --html`, and saved `vesper gate` reproduced the Lynx result; saved report returned 0 and saved gate returned 1. Corrupting `posture.json` in a temporary copy caused saved gate validation to fail closed with exit 2. HTML exposed separate execution, gate, coverage, findings, remediations, components/SBOM, historical-secret, posture, and artifact sections. Secret values were not present in the Lynx HTML, and links were report-relative without `file://` or parent traversal.

Failure isolation remained explicit: Syft failure prevents normal Grype execution rather than producing a clean result; Grype failure preserves Syft and independent findings; Gitleaks failure preserves dependency evidence; and Scorecard failure preserves security findings. The existing 4 GiB bounded default and explicit 6 GiB override remain intentional; the large Lynx workload used 6 GiB after the documented 4 GiB memcg OOM evidence. The known `Invoice/packages.config` limitation remains unchanged: OSV/Trivy can detect packages absent from Syft, so Grype coverage cannot exceed the Syft inventory.

M3 exit criteria are complete: each M3 slice has accepted evidence; the integrated fixture and unchanged baseline pass; coverage loss remains conservative; scanner dependency/failure behavior is fail-closed; all M3 evidence renders safely in HTML; saved report/gate reproduction works; 81 Python tests pass; launcher acceptance passes; and a fresh `vesper-runner:m35` image build succeeds. Dynamic Trivy, OSV, Grype, Semgrep, and provider/posture intelligence remain external reproducibility inputs rather than normalization nondeterminism.

### M4 - API Security and Fuzzing

**Status:** COMPLETE

**Goal:** Use API contracts to deterministically exercise application behavior.

**Candidate engine:** Schemathesis.

**Potential scope:** OpenAPI discovery; REST API test generation; negative testing; boundary-value testing; schema validation; unexpected response detection; and unexpected 5xx detection.

Active testing is implemented only through M4.2's explicit authorization and runtime-target boundary. M4.3 normalizes deterministic runtime contract failures; M4.4 extends the existing baseline model with coverage-aware API comparison.

M4 decomposition:

```text
M4.1 API Contract Foundation           COMPLETE
     OpenAPI import/discovery, normalized API model,
     operation identity, security requirements, contract coverage
M4.2 Schemathesis Execution             COMPLETE
     explicit runtime target, bounded active execution,
     authentication, request generation
M4.3 Behavioral Evidence                COMPLETE
     schema violations, unexpected status codes, 5xx,
     reproducible cases, evidence redaction
M4.4 API Coverage and Baseline          COMPLETE
     attempted/exercised operations, auth-limited coverage,
     comparison semantics
M4.5 M4 Integration and Acceptance      COMPLETE
     integrated fixtures, HTML, policy interaction, real test API
```

#### M4.1 - API Contract Foundation

**Status:** COMPLETE

M4.1 is passive. Vesper imports local OpenAPI 3.x JSON/YAML contracts and never sends HTTP requests. Sources are selected by explicit `--api-contract PATH` or bounded root-level discovery of `openapi.json`, `openapi.yaml`, `openapi.yml`, `swagger.json`, `swagger.yaml`, and `swagger.yml`. Remote discovery and remote `$ref` retrieval are not implemented.

The normalized `api-contract.json` schema v1 uses `apiIdentityVersion: 1`. Operation identity is normalized `METHOD + path template`; `operationId` is preserved as evidence and is not identity. Parameters, request bodies, response status/content metadata, global and operation security, security schemes, bounded server metadata, local references, and explicit public/authenticated/unknown authentication state are represented deterministically. Contract server URLs never authorize runtime targets.

Contract coverage is separate from future runtime operation coverage. A valid local OpenAPI 3 document receives `complete` contract coverage; absent contracts are `not_applicable`; malformed or unsupported contracts fail the API capability; external references remain unresolved rather than causing network access. Explicit contract paths are constrained to the workspace. Input size, path count, operation count, and normalized text are bounded.

`scan.json` records the passive `api-contract` capability and raw source artifact, while `summary.json` contains only contract/operation/authentication aggregates. The host HTML report includes a compact API contract section and report-relative `api-contract.json` link; operation-controlled text is escaped. Saved report validation checks the artifact schema, operation array, and report schema manifest. API contract inventory does not create findings, alter M2 comparison, or affect the security gate.

Acceptance used the local YAML fixture `tests/fixtures/api-contract/openapi.yaml` with a network-free contract-only runner path. It normalized three operations (`GET /health`, `GET /loans/{id}`, `POST /loans`), one public operation, two authenticated operations, path/query parameters, a request body, multiple responses, global security with an operation-level public override, local `$ref` values, and a production-looking server URL without contacting it. The generated HTML contained the API section and safe artifact link. Python tests passed at 84, launcher acceptance passed, and the rebuilt `vesper-runner:m41` image completed successfully.

M4.2 adds Schemathesis 3.39.16 behind an explicit active-testing boundary. HTTP execution requires both `--enable-api-testing` and a sanitized explicit `--api-target`; contract `servers[]` values, discovery, and contract presence never authorize requests. Execution is bounded by per-operation examples, a global request ceiling, per-request timeout, global timeout, single-worker concurrency, read-only/all mode, and disabled automatic redirects. Bearer and API-key credentials are supplied through environment-variable names and are redacted from saved evidence.

The versioned `api-execution.json` artifact links to the M4.1 contract digest and operation identities, and keeps runtime coverage separate from contract coverage. It records exercised, auth-limited, failed, and not-attempted operation states plus bounded candidate runtime evidence (`unexpected_5xx`, response-schema violations, timeouts, and connection failures); M4.3 promotes only deterministic contract mismatches into findings. Native runtime evidence is retained in `raw/schemathesis.json` without request credentials or full request/response bodies. Passive contract-only scans remain network-free and do not emit runtime execution artifacts.

The M4.2 fixture acceptance covered public and bearer-protected operations, missing and configured authentication, deterministic 5xx and response-schema evidence, target URL validation, cross-origin redirect containment, credential redaction, and real Schemathesis execution. Python tests passed 90; launcher parsing/build acceptance passed; the rebuilt runner image `vesper-runner:m42` installed the pinned hash-locked dependency set and completed successfully. M4.2 did not add API baseline states or advanced policy; M4.4 now owns API baseline comparison and M8 remains future advanced policy work.

#### M4.3 - Behavioral Evidence

**Status:** COMPLETE

M4.3 promotes only `unexpected_5xx`, `response_schema_violation`, and `unexpected_status` execution events into the existing finding model. Transport failures, timeouts, authentication limitations, and unavailable targets remain execution/coverage evidence. Behavioral findings use category/capability `api_behavior`, finding nature `api_behavior`, and deterministic medium severity for 5xx/schema violations or low severity for unexpected status. They do not receive API-specific gate rules.

Behavioral identity is based on the contract operation identity, behavior type, and sorted expected response statuses. Target origin, concrete generated values, case IDs, timestamps, response bodies, and execution order are excluded. Multiple cases are deduplicated into one finding with at most three sorted, redacted reproduction examples. Findings retain the contract digest, `apiIdentityVersion`, operation reference, observed statuses, candidate/retained counts, and bounded validation text; no raw credentials or full bodies are persisted.

Behavioral findings generate normal remediation groups and are rendered separately from API contract and active execution sections in HTML. Cross-artifact validation checks operation and execution-event references. M4.4 now includes these findings in the existing baseline model without changing M2 schema v1: semantic identity is operation/behavior/expectation based, generated values and targets are excluded, and API resolution requires positive operation and behavior-validation coverage. The representative fixture produced two deterministic unexpected-5xx findings, two remediations, saved report/HTML/gate reproduction, and no credential leakage.

#### M4.4 - API Coverage and Baseline

**Status:** COMPLETE

API behavioral findings now participate in `baseline.json` and `comparison.json` using the existing M2 schema and five comparison states. API identity is scanner-neutral and target-independent: operation identity, behavior type, and stable expected-response metadata define the baseline identity; detector, target, generated values, timestamps, and case IDs do not.

Resolution is conservative and requires positive evidence from the current active execution. The same operation must be exercised and the relevant validation must be available: status validation for `unexpected_5xx`/`unexpected_status`, or response-schema validation for `response_schema_violation`. Auth-limited, not-attempted, failed, passive, missing-operation, and unavailable-validation cases become `UNVERIFIED`; absence alone never becomes `RESOLVED`. Resolved entries preserve bounded baseline evidence and resolution coverage, and saved comparison validation rejects impossible API resolutions.

Old baselines remain readable, non-API findings retain M2 behavior, and API findings are excluded only from no baseline-era artifacts because they did not exist there. API baseline states are rendered in the existing HTML comparison section. API-specific policy and advanced gating remain out of scope for M4.4.

#### M4.5 - M4 Integration and Acceptance

**Status:** COMPLETE

The controlled API fixture acceptance exercised the complete M4 path: passive OpenAPI ingestion, explicit active authorization and target selection, real Schemathesis execution, runtime coverage, behavioral normalization, remediation grouping, baseline creation, unchanged comparison, saved report/gate reproduction, and HTML rendering. The fixture included `GET /health`, authenticated `GET /loans/{id}`, mutating `POST /loans`, global and operation-level security, local references, response schemas, and a production-looking server URL that was never used as an execution target.

Passive scans remained network-free and emitted no behavioral findings. Active unauthenticated runs classified protected operations as `auth_limited`; authenticated credentials were supplied through environment variables and were absent from persisted artifacts, logs, and HTML. Redirects remained contained, and read-only execution left mutating operations unattempted. Deterministic 5xx and schema failures produced bounded, deduplicated `api_behavior` findings and separate remediations.

The integrated runner acceptance used Scan A `230b348c-578e-48f4-8cdc-748ae04c1c5c` and unchanged Scan B `3c548ead-c184-4e3f-8422-1adf7ac56ab0`, with baseline `baseline-1e9935b42808bca5f59cf1c3bfee9621d5d07fc04d80a7e066ee8ba6caf617ae`. It emitted two behavioral findings and two remediations from four total fixture requests; the rerun produced `NEW=0`, `EXISTING=2`, `CHANGED=0`, `RESOLVED=0`, `UNVERIFIED=0`. M4.4 matrix tests covered new, changed, resolved, passive, auth-limited, runtime-failed, validation-unavailable, and impossible-resolution cases. Saved comparison validation rejects API `RESOLVED` entries without positive operation and validation coverage. M4.5 adds no API-specific policy, no new scanner, and no M7 correlation.

### M5 - DAST and Runtime Security

**Status:** PLANNED

**Goal:** Analyze running applications and produce deterministic runtime security evidence.

**Candidate engines:** OWASP ZAP and Nuclei.

**Potential scope:**

- **PASSIVE:** passive HTTP analysis.
- **ACTIVE:** active DAST, API DAST, known-exposure templates, and runtime misconfiguration detection.

Active scanning requires explicit authorization/configuration.

### M6 - Infrastructure and Kubernetes Security

**Status:** PLANNED

**Goal:** Extend Vesper into deployment and infrastructure security while keeping static and live infrastructure evidence separate.

**Candidate engines:** Trivy IaC and kube-bench.

**Potential scope:** Kubernetes configuration analysis; CIS Kubernetes checks; static IaC findings; live cluster posture; and deployment configuration.

Live-cluster access must remain explicit and authorized.

### M7 - Deterministic Evidence Correlation

**Status:** PLANNED

**Goal:** Correlate findings and evidence from independent deterministic engines without mutating or replacing original findings.

**Potential evidence sources:** Semgrep, Trivy, OSV-Scanner, Grype, Schemathesis, OWASP ZAP, Nuclei, Gitleaks, Syft, and OpenSSF Scorecard.

**Core invariant:**

```text
original scanner findings
=
immutable evidence

correlation
=
references between evidence
```

Never irreversibly merge or destroy original findings.

**Future deterministic correlation may use:** canonical vulnerability identifiers; package identity; endpoint identity; source location; security capability; target identity; and runtime evidence.

Do not use probabilistic correlation or generated severity/gate decisions. Possible explainable states include `STATIC_EVIDENCE`, `BEHAVIORAL_EVIDENCE`, `RUNTIME_CONFIRMED`, and `MULTI_ENGINE_CONFIRMED`; each must be grounded in concrete evidence.

### M8 - Security Policy and Advanced Gating

**Status:** PLANNED

**Goal:** Build richer deterministic policy evaluation on top of baseline comparison, capabilities, and evidence correlation.

**Potential future policies:**

```text
new HIGH finding
-> fail

existing HIGH finding
-> allow under baseline policy

new CRITICAL finding
-> fail

MEDIUM finding with runtime confirmation
-> fail

LOW hardening finding
-> warn
```

Potential policy inputs are severity, new/existing/changed state, finding nature, security capability, deterministic corroboration, runtime confirmation, and fix availability. Probabilistic scores are excluded.

### M9 - CI/CD Distribution and Ecosystem Integration

**Status:** PLANNED

**Goal:** Make Vesper easy to distribute, version, integrate, and operate inside CI/CD environments after the core security engine is mature.

M9 is not what makes Vesper technically capable of running in CI. Vesper is already developer- and CI-oriented; M9 focuses on supported distribution and ecosystem integration.

**Potential scope:** versioned releases; runner image digest publication; release manifests; `win-x64` and `linux-x64` artifacts; macOS artifacts when verified; GitHub Actions integration; GitLab CI templates; Azure DevOps integration/examples; CircleCI integration/examples; Jenkins examples; report artifact conventions; SARIF export if appropriate; JUnit-style output if appropriate; and release provenance.

Vesper can run in CI before M9. M9 makes CI usage repeatable, supported, packaged, documented, versioned, and integrated. CI distribution is packaging/ecosystem work, not the core security engine.

### M10 - Centralized Orchestration

**Status:** DEFERRED

**Goal:** Introduce centralized multi-user execution only after the local/CI engine and deterministic security capabilities are mature.

**Potential future scope:** REST API; persistent database; queue; workers; Kubernetes Jobs; scan scheduling; central history; multi-user execution; RBAC; tenancy; and centralized policies.

Do not implement this now.

### Roadmap Principle

```text
Detect
  ↓
Prove coverage
  ↓
Compare against baseline
  ↓
Expand deterministic detection
  ↓
Correlate evidence
  ↓
Apply advanced policy
  ↓
Distribute into CI/CD ecosystems
  ↓
Centralize execution
```

Vesper should first mature its deterministic security capabilities, coverage model, baseline comparison, evidence correlation, and policy model. CI/CD integration is primarily distribution and ecosystem packaging, so it is intentionally scheduled after the core security engine.

Vesper is not differentiated by scanner count. Its architectural value is deterministic evidence, coverage transparency, normalization, baseline comparison, correlation, policy enforcement, and auditability.

## Security Findings

| ID | Severity | Area | Status | Target | Summary |
|---|---|---|---|---|---|
| VSP-001 | High | Gate | RESOLVED | M1.3 | No applicable scanner or an applicable scanner failure yields an indeterminate gate when no known policy blocker exists, and exit 2. |
| VSP-002 | High | Scanner parsing | RESOLVED | M1.3 | Empty/invalid JSON, unexpected root type, and normalization exceptions fail the adapter; later adapters continue. |
| VSP-003 | High | Severity/CVSS | RESOLVED | M1.3 | Only numeric CVSS scores are scored; v2/v3 vectors are preserved and vector-only scores remain unknown. |
| VSP-004 | High | Confidentiality | RESOLVED | M1.3 | Linux tests confirm archive/report files are `0600` and private output/staging directories are `0700`; Windows ACL inheritance remains documented. |
| VSP-005 | High | Supply chain | ACCEPTED | M9 / before official release distribution | Python package hashes, digest-pinned bases/helper, and OSV checksum are enforced. Residual: default versioned runner tag is mutable and runtime databases/rules are dynamic; digest-qualified override is supported and required for reproducible release use. |
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

- **VSP-001:** `test_empty_workspace_with_no_applicable_scanners_is_incomplete`, `test_all_applicable_scanners_failed_is_incomplete`, `test_known_policy_blockers_remain_failed_when_execution_is_incomplete`, and `test_parser_failure_isolated_and_run_marked_incomplete`; remote empty-workspace scan returned 2 and exported incomplete/indeterminate reports, while the blocker regression preserved a failed policy decision with exit 2.
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

## Known Limitations

- The Docker daemon is a privileged host trust boundary; remote Docker operators can inspect staged source and results.
- Container isolation is not equivalent to a VM; scanners need outbound network access for vulnerability data and Semgrep rules.
- Linux x64 AOT is published and runtime-tested; macOS has not been tested. Windows output ACLs inherit from the invoking user and are not rewritten by Vesper.
- Semgrep registry rules may change independently of the pinned engine and are not available for hosted service distribution under their current license.
- There is no global scheduler; concurrent per-scan limits can exhaust host memory/CPU/disk.

## Deferred Work

- M5-M9 DAST, infrastructure, correlation, policy, and CI/CD distribution milestones remain future work; M10 centralized orchestration is deferred. Large artifact/SBOM scans may require an explicit memory override above the bounded 4 GiB default.
- Additional scanners, shared scanner caches, and an orphan cleanup command remain future work.

## Not Implemented Yet

- OWASP ZAP, Nuclei, kube-bench, deterministic evidence correlation, advanced gating, official CI/CD integrations, central API, database, queues, distributed workers, and hosted multi-user service remain unimplemented.

## Product Readiness

| Scenario | Status | Notes |
|---|---|---|
| Local developer use | CONDITIONAL | Windows and Linux x64 AOT plus remote Docker are tested; local Docker Desktop bind-mode acceptance and macOS runtime remain unverified. |
| Internal trusted repositories | READY | Fail-closed coverage, pinned build inputs, Linux filesystem tests, remote scan, and cancellation isolation are verified; Semgrep registry rules remain internal-use-only. |
| CI security gate | CONDITIONAL | Core execution and exit/report behavior are CI-compatible and verified; supported distribution, published artifacts, digest stamping, and provider-specific integrations remain M9 work. |
| Untrusted repositories | CONDITIONAL | Archive/schema defenses and cancellation isolation are tested; Docker host trust, dynamic scanner egress, daemon-loss cleanup, and global concurrency capacity remain constraints. |
| Hosted multi-user service | NOT READY | Semgrep rule license restricts service use; remote Docker is host-privileged; no tenancy/scheduler exists. |

## Next Recommended Work

1. Preserve the completed M2 baseline/diff and new-finding gate evidence while monitoring dynamic scanner data changes.
2. Keep macOS runtime/AOT and real Docker daemon-disappearance verification as explicit environment/platform validation work.
3. Preserve the completed M4 API contract, bounded execution, behavioral evidence, and conservative baseline acceptance; scope M5 DAST separately before implementation and keep active testing explicitly authorized.
4. Do not begin CI/CD ecosystem packaging until M9 unless a small CI smoke test is required to validate an earlier product invariant.

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
- Completed M1.3 after Linux filesystem/AOT/signal integration, scanner-envelope and network-failure tests, archive-entry/metadata bounds, and hash-enforced runner build verification. A final dangling-symlink review added direct attribute checks and Linux regression cases before completion. macOS and real daemon-loss behavior remain explicitly UNVERIFIED; runner digest enforcement is accepted for M9 release work.

### 2026-10-02

- Completed M2 baseline creation, semantic identity, all five comparison states, coverage-aware resolution, new-only gate, saved-report reproduction, 58 passing Python tests, passing launcher tests, and the real Lynx unchanged-baseline regression (`NEW=0`, `EXISTING=31`, `CHANGED=0`, `RESOLVED=0`, `UNVERIFIED=0`). The M2 milestone remains active for acceptance follow-through; M9 CI/CD distribution remains planned and has not started.
- Closed M2 after fresh current-schema Lynx Scan A/Scan B acceptance through the verified SSH Docker endpoint. The unchanged comparison was `NEW=0`, `EXISTING=31`, `CHANGED=0`, `RESOLVED=0`, `UNVERIFIED=0`; the existing absolute HIGH gate remained failed, the baseline delta passed, saved gate reproduction matched, and corrupted comparison handling returned exit 2. Began and completed M3.1 SBOM Foundation with pinned Syft 1.52.0, retained CycloneDX evidence, normalized `components.json`, and the Lynx component regression. M3.2 Grype and later milestones remain untouched.
- Started M3.2 Artifact Vulnerability Analysis with pinned, checksum-verified Grype 0.119.0 consuming the Syft CycloneDX artifact. Synthetic normalization and deduplication tests pass, but real Lynx Grype acceptance remains IN PROGRESS because the remote Docker filesystem killed Grype during database initialization with exit `-9`; OSV/Trivy/Syft evidence remained preserved and M3.3 was not started.
- Reproduced and classified the Lynx Grype failure as a runner-container memory-cgroup OOM (`--memory 4g`), not Docker disk exhaustion. A focused Grype run succeeded under the same isolation limits; the full pipeline completed with an explicit 6 GiB limit. Corrected Grype DB metadata extraction from the native descriptor, preserved the four-package `Invoice/packages.config` SBOM gap as an unknown-coverage limitation, and verified 67 Python tests, launcher acceptance, and the rebuilt runner image. M3.2 remains IN PROGRESS pending an operational decision on the default memory limit and real Grype vulnerability corroboration; M3.3 was not started.
- Completed M3.2 with the existing vulnerable npm fixture: live Syft-to-Grype DB-backed matching, component linkage, Grype/OSV/Trivy corroboration, remediation preservation, unchanged baseline comparison, and conservative coverage-loss behavior. Kept the bounded 4 GiB default and documented explicit 6 GiB guidance for larger artifact workloads. M3.3 remains planned and was not started.
- Added `vesper report --html [file]`, a self-contained HTML export rendered by the host CLI from validated saved report artifacts. It presents gate and execution status, scanner coverage, findings, remediation actions, and baseline comparison counts. Launcher acceptance now verifies the export and its key sections; PDF generation remains out of scope.
- Hardened the HTML export for schema-v2 scanner coverage objects and structured coverage warnings after validating it against the Lynx report with 31 findings and 5 remediations; the export now completes without an unhandled exception.
- Expanded the HTML report with independent execution/gate/coverage assessments, effective policy metadata, prioritized remediations, scanner scope and diagnostics, safe artifact links, escaped expandable finding evidence, offline filters, and reproducibility metadata. Added additive schema-v2 `coverage.assessment`, `effectivePolicy`, project identity, and optional launcher-captured Git metadata. Known policy blockers now remain a failed decision when execution is incomplete, while scan and saved-gate exit code `2` semantics remain intact.
- Removed the obsolete legacy Docker image tag from the documented build surface; `vesper-runner` is the only supported runner image name. The `security_runner` Python package and `security-scan` script aliases remain unchanged.
- Completed M3.3 Repository Secret History with pinned/checksum-verified Gitleaks 8.30.1, explicit `--include-git` transport, process-scoped Git ownership trust, redacted native evidence, historical-only fixture acceptance, unchanged baseline comparison, and HTML redaction verification. The Git executable is now an explicit runner dependency; M3.4 remains planned.
- Completed M3.4 Supply Chain Posture with pinned/checksum-verified OpenSSF Scorecard v5.5.0, explicit local Git mode, versioned `posture.json`, provider-limited coverage semantics, sanitized repository identity, raw evidence retention, posture HTML rendering, and live remote-volume fixture acceptance. Scorecard posture remains separate from findings and the security gate; M3.5 remains planned.
- Completed M3.5 M3 Integration and Acceptance with the seven-engine integrated fixture, unchanged baseline comparison, real Lynx regression, cross-artifact validation, scanner failure-isolation checks, safe components/secrets/posture HTML sections, saved report/gate reproduction, corrupt-artifact exit-2 handling, 81 Python tests, launcher acceptance, and a rebuilt `vesper-runner:m35` image. M3 is complete; M4 remains planned and was not started.
- Completed M4.1 API Contract Foundation with passive local OpenAPI 3 JSON/YAML ingestion, bounded deterministic operation/security normalization, explicit contract coverage, safe local-reference handling, no network access, versioned `api-contract.json`, summary/HTML integration, saved-artifact validation, 84 Python tests, launcher acceptance, and a rebuilt `vesper-runner:m41` image. M4.2 Schemathesis execution and all HTTP behavior remain planned and were not started.
- Completed M4.2 Schemathesis Execution with pinned hash-locked Schemathesis 3.39.16, explicit opt-in plus runtime-target authorization, bounded read-only/all execution, secure bearer/API-key environment inputs, target/redirect scope controls, versioned `api-execution.json`, credential-safe raw runtime evidence, contract-linked operation/runtime coverage, candidate 5xx/schema evidence, 90 Python tests, launcher acceptance, and a rebuilt `vesper-runner:m42` image. M4.3 behavioral finding normalization and M4.4 API baseline semantics remain planned.
- Completed M4.3 Behavioral Evidence with deterministic `api_behavior` normalization for unexpected 5xx, response-schema violation, and unexpected-status evidence; target-independent operation fingerprints; multi-case deduplication with bounded redacted reproductions; generic severity/remediation integration; cross-artifact validation; HTML behavioral reporting; explicit exclusion from M2 baseline comparison until M4.4; 93 Python tests; launcher acceptance/build; saved report/HTML/gate reproduction; and a representative real Schemathesis fixture.
- Completed M4.4 API Coverage and Baseline with additive M2-schema API behavioral baseline entries, target- and generated-value-independent identity, positive operation/behavior-validation resolution evidence, conservative `UNVERIFIED` handling for passive/auth-limited/not-attempted/failed coverage, old-baseline compatibility, mixed finding comparison, saved comparison validation, API baseline HTML details, and 94 passing Python tests. M4.5 remains planned and was not started.
- Completed M4.5 M4 Integration and Acceptance with the real controlled API fixture, passive/active authorization regressions, runtime coverage and credential-safety checks, deterministic behavioral findings/remediations, integrated baseline rerun, saved report/HTML/gate validation, impossible-resolution rejection, launcher acceptance, runner build, and 95 passing Python tests. M4 is complete; M5 remains planned and was not started.

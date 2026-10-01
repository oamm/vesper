# Vesper

Vesper is a security analysis and policy tool for software repositories. It orchestrates specialized scanners, normalizes and deduplicates their findings, groups findings into actionable remediations, and evaluates a configurable security gate. The native host CLI transports the repository; the isolated Python engine performs scanning and reporting.

## Build

```sh
docker build -t vesper-runner:latest -t security-runner:latest .
```

Pinned tools in this image:

- Trivy `0.58.2` (Apache-2.0)
- OSV-Scanner `2.3.3` (Apache-2.0)
- Semgrep `1.99.0` (engine under LGPL-2.1; see the upstream license and notices)

Semgrep's `p/security-audit` ruleset is fetched from the Semgrep registry. Rule content and registry terms are separate from the engine license; remote rules can change independently of the pinned binary. Trivy and OSV vulnerability data also update remotely at scan time.

## Run

Create the output directory before starting the non-root container:

```sh
mkdir -p security-results
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/security-results:/output" \
  vesper-runner:latest
```

Hardened invocation:

```sh
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --cpus=2 \
  --memory=4g \
  --pids-limit=512 \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/security-results:/output" \
  vesper-runner:latest
```

The process runs as non-root UID 1000, requires neither privileged mode nor Docker socket access, and uses `/tmp` for scanner caches. `/workspace` is treated as read-only. The output directory must be writable by the container user. On Linux hosts using a different UID, add `--user "$(id -u):$(id -g)"` to the command so the report files are owned by the invoking user.

## Architecture

`vesper` is the host-side .NET 10 Native AOT CLI. It detects Docker endpoints, stages source, manages isolated resources, retrieves reports, and preserves exit codes. `vesper-runner` is the Python container-side analysis engine; Trivy, OSV-Scanner, Semgrep, normalization, remediation grouping, and policy remain inside the image. This uses .NET for a small runtime-independent process/filesystem/streaming CLI and Python for scanner integration and security analysis. The runner only sees `/workspace` and `/output` and does not know which Docker transport supplied them.

The old `security-scan` script names remain compatibility aliases. The `security-runner` image tag is also emitted as a legacy alias by the documented build command. The Python package remains `security_runner` for import compatibility; its reports identify the product as Vesper.

## Host Launcher

The host-side launcher supports local and remote Docker daemons. Running from source or building requires the .NET 10 SDK and Docker CLI. A published Native AOT executable does not require an installed .NET runtime:

```powershell
\.\vesper.ps1 scan .
\.\vesper.ps1 scan C:\Git\MyProject --output .\security-results --verbose
artifacts\cli\win-x64\vesper.exe scan . --cpus 2 --memory 4g --pids-limit 512
```

```sh
sh ./vesper.sh scan .
sh ./vesper.sh scan . --workspace-mode volume --keep-volumes
```

The CLI also provides `vesper inspect`, `vesper report [output-directory]`, `vesper gate [output-directory]`, and `vesper version`.

The launcher inspects the active Docker endpoint, not its context name. `npipe://`, `unix://`, and loopback TCP endpoints use local bind mounts in `auto` mode. SSH and non-loopback TCP/HTTP(S) endpoints use temporary named volumes. Explicit `--workspace-mode bind` against a remote endpoint fails early with the workspace and endpoint in the error; `volume` can also be forced for local daemons.

Remote mode builds a local PAX tar archive and streams its bytes through Docker stdin into a uniquely named volume. The pinned `alpine:3.21.3` helper supplies BusyBox tar on the daemon host for import/export; it stays separate from the Python scanner image and is centrally versioned in the launcher. It excludes generated directories by default (`.git`, `node_modules`, `bin`, `obj`, `dist`, `build`, `coverage`, `security-results`, virtual environments, and Terraform cache); use `--include-git` only when rules need repository history. The source volume is mounted read-only at `/workspace`, and a separate output volume is streamed back through Docker stdout and safely extracted locally. Transfer preserves JSON, SARIF, UTF-8 paths, empty files, and arbitrary binary content. Symlinks and reparse points are skipped instead of followed.

Each invocation creates one ephemeral runner container with a unique full scan ID and short `vesper-*` resource names. In volume mode it also creates unique source/output (and optional config) volumes. Runner containers and volumes carry `securityscan.managed`, `securityscan.scan-id`, `securityscan.resource`, and sanitized project labels; these label keys remain stable for cleanup tooling compatibility. Cleanup verifies managed/full-ID labels and removes only resources owned by that invocation; no prune operations are used. Container `/tmp` is a private tmpfs, and scanner caches are not shared between scans.

The default output base is `<workspace>/security-results`; the launcher writes each report set under `<base>/<full-scan-id>/`. An explicit `--output PATH` is also treated as a base and gets its own full-ID child directory, so overlapping scans of the same project cannot overwrite each other. A custom output base nested in the workspace is excluded from project detection, Trivy, and Semgrep scanning. Verbose output prints the full scan ID, container/volume names, and resource limits.

Each scan defaults to `--cpus 2 --memory 4g --pids-limit 512`. These may be overridden per invocation and are validated before Docker starts. Concurrent scans do not share mutable scanner caches or other writable mounts. The Docker host must still have enough capacity for the sum of all per-scan limits; for example, ten simultaneous scans at 4 GB each can require up to 40 GB of memory. Global scheduling/concurrency limits are not part of this MVP.

Optional `--config PATH` is bind-mounted read-only in local mode and copied into a temporary `/security-config` volume in remote mode, keeping the image's default `/config/default.yaml` visible. Reports are exported even when the scanner exits `1`; codes `0` through `4` are preserved after successful export. Docker/transfer failures map to `2`, as does an export failure because local reports are unavailable. Temporary volumes and helper containers are cleaned up after gate failure, scanner errors, and Ctrl+C. `--keep-volumes` retains and prints volume names for troubleshooting.

Run the dependency-free launcher tests with:

```sh
dotnet run --project launcher/SecurityScan.Tests/SecurityScan.Tests.csproj
```

Run the remote same-project concurrency acceptance test from PowerShell after publishing the CLI and building the scanner image:

```powershell
./tests/test_concurrent_scans.ps1 `
  -CliPath ./artifacts/cli/win-x64/vesper.exe `
  -Workspace ./tests/fixtures/vulnerable-app `
  -PassConfig ./tests/fixtures/launcher-policy-pass.yaml
```

To exercise different repositories, add `-WorkspaceB .` (or another source tree) to that command.

## Native AOT Builds

The CLI targets `net10.0` with `PublishAot`, `StripSymbols`, nullable checks, and warnings-as-errors. Invariant globalization is enabled because the CLI does not perform culture-sensitive parsing; it handles paths, endpoint strings, integer exit codes, and invariant formatted sizes only. The launcher uses BCL process, JSON DOM, filesystem, and `System.Formats.Tar` APIs, with no runtime reflection-based serializer or third-party runtime dependency.

Windows PowerShell publishes the primary target to `artifacts/cli/win-x64/vesper.exe`:

```powershell
\.\build-cli.ps1 win-x64
artifacts\cli\win-x64\vesper.exe --help
artifacts\cli\win-x64\vesper.exe version
artifacts\cli\win-x64\vesper.exe scan .
```

On matching native build hosts, the shell script publishes Linux x64, Linux arm64, or macOS arm64:

```sh
sh ./build-cli.sh linux-x64
sh ./build-cli.sh linux-arm64
sh ./build-cli.sh osx-arm64
```

These are .NET 10 Native AOT-supported RIDs, but cross-publishing is toolchain-dependent. Windows Native AOT requires the Windows native compiler toolchain; Linux and macOS builds require their corresponding native toolchains. Only `win-x64` was published and executed in the current environment. Published binaries are ignored under `artifacts/` and should be produced by the build pipeline rather than committed.

## Configuration

The image contains `/config/default.yaml`. An optional `/config/security.yaml` is merged over defaults:

```yaml
policy:
  failOn:
    - critical
  failOnSecrets: true
  maxHigh: 5

timeouts:
  default: 300
  trivy: 600
  osv: 300
  sast: 600
```

Mount it read-only at `/config/security.yaml`. The CLI also supports `--config /path/to/security.yaml`, `--workspace`, and `--output` for local development.

## Scanners and detection

- Trivy scans filesystem vulnerabilities, secrets, and misconfigurations, including IaC and Docker-related configuration.
- OSV-Scanner runs when recognized dependency manifests/lockfiles are detected; unsupported or malformed projects are recorded as scanner failures without stopping other adapters.
- Semgrep runs its registry `p/security-audit` rules when source files are present. The scanner interface is isolated from normalization and policy evaluation.
- Detection recognizes .NET, Node.js/npm/pnpm/yarn, Python, Java, Go, Rust, Docker, Terraform, and Kubernetes manifests.

Scanner binaries are pinned at image build time. Internet access is needed for Trivy database updates, OSV vulnerability queries, and Semgrep registry rules. An initial scan may take longer while Trivy populates its cache. Offline database/cache configuration is not implemented.

## Output

Each scan output directory receives `project.json`, `scan.json`, `findings.json`, `remediations.json`, `summary.json`, and `raw/` scanner artifacts. Findings remain individual and auditable; remediations answer which engineering action resolves one or more findings. Dependency remediation keys use ecosystem, package, installed/fixed versions, and artifact. Repeated container/IaC rules group by scanner and rule; SAST findings remain separate. Cross-scanner vulnerability matches merge when canonical vulnerability ID, package/version, and location align, retaining all scanner evidence.

Findings include normalized severity and separate remediation priority, stable fingerprints, location, package/security metadata, conservative impact, and `reachability: unknown` unless evidence supports more. Summary retains legacy top-level totals and adds Vesper generator metadata, nested finding/remediation counts, and blocking finding/remediation counts. `scan.json` distinguishes execution status from security-gate status. Scanner coverage distinguishes `clean`, `completed_with_findings`, `not_applicable`, `skipped`, `failed`, and `timeout`; a skipped scanner is never described as clean.

The Lynx raw scan outputs described in the product brief were not present in this checkout, so exact 31-finding/5-remediation regression totals could not be verified here. Synthetic tests cover the underlying grouping rules without hardcoding Lynx counts.

Known secret-shaped values are scrubbed from normalized findings, logs, and raw JSON. Raw scanner output is treated as sensitive and scrubbed before persistence. Redaction is heuristic and cannot guarantee removal of every proprietary scanner-specific representation; protect the output volume accordingly and review new scanner formats before enabling them.

## Exit codes

- `0`: scan completed and policy passed
- `1`: scan completed and policy failed
- `2`: no applicable scanner could complete, or the runner could not meaningfully execute
- `3`: invalid or unreadable configuration
- `4`: unexpected internal error

Individual scanner outcomes (`completed`, `completed_with_findings`, `skipped`, `failed`, `timeout`) are reported in `scan.json`; one adapter failure does not prevent later adapters from running. `SECURITY_SCAN_ID` from the launcher is authoritative in `scan.json`, which records `executionStatus` separately from `securityGate`. A timeout is enforced per scanner process.

## Tests and fixture

Run unit tests from the repository root:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

`tests/fixtures/vulnerable-app` contains synthetic SQL, fake-credential, dependency, Docker, Terraform, and Kubernetes examples. The credential is deliberately fake. The fixture's Dockerfile and dependency are intentionally unsafe and must not be used as application dependencies.

## Limitations and next milestone

Detection is filename/content based rather than a full build-system model. Scanner support varies by ecosystem and may change with remote vulnerability data/rules. Secret redaction is best-effort. This MVP does not build container images, require Docker, clone repositories, or provide offline mirrors. A useful next milestone is immutable/pinned rule bundles and database cache support, followed by integration tests against the actual image and output schema versioning.
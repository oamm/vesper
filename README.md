# Vesper

Vesper is a security analysis and policy tool for software repositories. It orchestrates specialized scanners, normalizes and deduplicates their findings, groups findings into actionable remediations, and evaluates a configurable security gate. The native host CLI transports the repository; the isolated Python engine performs scanning and reporting.

## Build

```sh
docker build -t vesper-runner:0.2.0 -t vesper-runner:latest -t security-runner:latest .
```

Pinned tools in this image:

- Trivy `0.58.2` (Apache-2.0)
- OSV-Scanner `2.3.3` (Apache-2.0)
- Semgrep `1.99.0` (engine under LGPL-2.1; see the upstream license and notices)

Semgrep's `p/security-audit` ruleset is fetched from the Semgrep registry. The Semgrep engine is LGPL-2.1, but the registry rules are separately licensed for internal business use and are not licensed for distribution or making them available as a service. Treat hosted/commercial rule delivery as blocked until Vesper switches to suitably licensed rules or obtains rights. Remote rule content can change independently of the pinned binary. Trivy and OSV vulnerability data also update remotely at scan time.

The CLI defaults to the compatible `vesper-runner:0.2.0` tag; `--image` overrides it and accepts digest-qualified references such as `registry.example/vesper-runner:0.2.0@sha256:<manifest-digest>`. Tags are mutable names; digest-qualified references select immutable image content. Release/CI use should pass a digest after publishing and resolving the image manifest. The floating `latest` tags are build-time compatibility aliases, not a fallback or the CLI default.

## Run

Create the output directory before starting the non-root container:

```sh
mkdir -p security-results
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/security-results:/output" \
  vesper-runner:0.2.0
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
  vesper-runner:0.2.0
```

The process runs as non-root UID 1000, requires neither privileged mode nor Docker socket access, and uses `/tmp` for scanner caches. `/workspace` is treated as read-only. The output directory must be writable by the container user. On Linux hosts using a different UID, add `--user "$(id -u):$(id -g)"` to the command so the report files are owned by the invoking user.

## Architecture

`vesper` is the host-side .NET 10 Native AOT CLI. It detects Docker endpoints, stages source, manages isolated resources, retrieves reports, and preserves exit codes. `vesper-runner` is the Python container-side analysis engine; Trivy, OSV-Scanner, Semgrep, normalization, remediation grouping, and policy remain inside the image. This uses .NET for a small runtime-independent process/filesystem/streaming CLI and Python for scanner integration and security analysis. The runner only sees `/workspace` and `/output` and does not know which Docker transport supplied them.

The old `security-scan` script names remain compatibility aliases. The `security-runner` image tag is also emitted as a legacy alias by the documented build command. The Python package remains `security_runner` for import compatibility; its reports identify the product as Vesper.

## Host Launcher

The host-side launcher supports local and remote Docker daemons. Running from source or building requires the .NET 10 SDK and Docker CLI. A published Native AOT executable does not require an installed .NET runtime:

```powershell
.\vesper.ps1 scan .
.\vesper.ps1 scan C:\Git\MyProject --output .\security-results --verbose
artifacts\cli\win-x64\vesper.exe scan . --cpus 2 --memory 4g --pids-limit 512
```

```sh
sh ./vesper.sh scan .
sh ./vesper.sh scan . --workspace-mode volume --keep-volumes
```

The CLI also provides `vesper inspect`, `vesper report [output-directory]`, `vesper gate [output-directory]`, and `vesper version`.

The launcher inspects the active Docker endpoint, not its context name. `npipe://`, `unix://`, and loopback TCP endpoints use local bind mounts in `auto` mode. SSH and non-loopback TCP/HTTP(S) endpoints use temporary named volumes. Explicit `--workspace-mode bind` against a remote endpoint fails early with the workspace and endpoint in the error; `volume` can also be forced for local daemons.

Remote mode builds a local PAX tar archive and streams its bytes through Docker stdin into a uniquely named volume. The pinned `alpine:3.21.3` helper supplies BusyBox tar on the daemon host for import/export; it stays separate from the Python scanner image and is centrally versioned in the launcher. It excludes generated directories by default (`.git`, `node_modules`, `bin`, `obj`, `dist`, `build`, `coverage`, `security-results`, virtual environments, and Terraform cache); use `--include-git` only when rules need repository history. The source volume is mounted read-only at `/workspace`, and a separate output volume is streamed back through Docker stdout. Reports are validated and extracted to a private scan-specific staging directory; only after the complete archive validates is that directory published at the final path. Output symlink/hardlink and special entries are ignored, never created. Symlinks and reparse points in source workspaces are skipped instead of followed. On Unix, literal backslash filenames remain distinct from slash-separated paths.

Source staging defaults to a 20 GiB total, 500,000-file, and 2 GiB per-file ceiling. Result extraction defaults to 4 GiB, 100,000 regular files, and the same per-file ceiling. Both sides also enforce a 600,000-entry limit counting directories and non-regular tar entries; archive byte ceilings include bounded PAX/header overhead. Override with `--max-workspace-bytes`, `--max-files`, `--max-file-bytes`, `--max-output-bytes`, `--max-output-files`, and `--max-entries` (integer byte/count values). Temporary source/config/result archives are created mode `0600` on Unix. Private extraction/staging directories use `0700`, extracted report files use `0600`, and runner output uses a restrictive Unix umask. Linux x86_64 behavior is exercised on a real Linux host; macOS has not been runtime-tested. Windows uses the ACL inherited from the user temp/output directories; Vesper does not rewrite Windows ACLs. Failed temporary archive deletion is logged without printing source contents or credentials.

The transfer helper is pinned by digest in `LauncherImages`. The scanner checks that the source mount is read-only in its isolation integration probe:

```powershell
./tests/test_workspace_readonly.ps1
```

Each invocation creates one ephemeral runner container with a unique full scan ID and short `vesper-*` resource names. In volume mode it also creates unique source/output (and optional config) volumes. Runner containers and volumes carry `securityscan.managed`, `securityscan.scan-id`, `securityscan.resource`, and sanitized project labels; these label keys remain stable for cleanup tooling compatibility. Cleanup verifies managed/full-ID labels and removes only resources owned by that invocation; no prune operations are used. Container `/tmp` is a private tmpfs, and scanner caches are not shared between scans.

The default output base is `<workspace>/security-results`; the launcher writes each report set under `<base>/<full-scan-id>/`. An explicit `--output PATH` is also treated as a base and gets its own full-ID child directory, so overlapping scans of the same project cannot overwrite each other. A custom output base nested in the workspace is excluded from project detection, Trivy, and Semgrep scanning. Verbose output prints the full scan ID, container/volume names, and resource limits.

Each scan defaults to `--cpus 2 --memory 4g --pids-limit 512`. These may be overridden per invocation and are validated before Docker starts. Tar helpers also run with a read-only root, no network, dropped capabilities, no-new-privileges, a private tmpfs, and 1 CPU/128 MiB/128 PIDs. The upload helper remains root because a fresh Docker volume is root-owned; it has no Linux capabilities. Concurrent scans do not share mutable scanner caches or other writable mounts. The Docker host must still have enough capacity for the sum of all per-scan limits; for example, ten scans at 4 GB each can require up to 40 GB of memory. Global scheduling/concurrency limits are not part of this MVP.

Optional `--config PATH` is bind-mounted read-only in local mode and copied into a temporary `/security-config` volume in remote mode, keeping the image's default `/config/default.yaml` visible. Docker context/host selection is resolved once and explicitly attached to every later Docker CLI command. Docker control operations time out after 60 seconds, transfers after 15 minutes, and runner execution after one hour; scanner-specific timeouts remain independently configured inside the runner. Reports are exported on security-gate exit `1`; incomplete scans return `2`. Temporary volumes and helper containers are cleaned after gate failure, scanner errors, Ctrl+C, and POSIX SIGTERM where supported. `--keep-volumes` retains and prints volume names.

Run the dependency-free launcher tests with:

```sh
dotnet run --project launcher/SecurityScan.Tests/SecurityScan.Tests.csproj
```

On a machine with a Linux Docker host, `./tests/test_linux_launcher.ps1` runs the filesystem/timeout launcher suite on Linux. `./tests/test_linux_aot.ps1` publishes Linux x64 Native AOT, runs direct `version`/`inspect` and a real scan, then exercises SIGTERM and cancellation isolation through the mounted Docker socket. The latter installs an ephemeral build/test toolchain in a disposable container and requires permission to mount the Docker host socket.

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
.\build-cli.ps1 win-x64
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

These are .NET 10 Native AOT-supported RIDs, but cross-publishing is toolchain-dependent. Windows Native AOT requires the Windows native compiler toolchain; Linux and macOS builds require their corresponding native toolchains. `win-x64` and `linux-x64` were published and executed; macOS remains unverified. Published binaries are ignored under `artifacts/` and should be produced by the build pipeline rather than committed.

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
- Semgrep engine `1.99.0` runs its registry `p/security-audit` rules when source files are present. The engine binary, Python dependencies, and remotely fetched rule content are separate inputs; only the engine/dependencies are pinned. Registry rule changes are not reproducibly pinned.
- Detection recognizes .NET, Node.js/npm/pnpm/yarn, Python, Java, Go, Rust, Docker, Terraform, and Kubernetes manifests.

Scanner binaries are pinned at image build time: Trivy is copied from a digest-pinned image and OSV is downloaded using its official release filename, verified against that filename in upstream `SHA256SUMS`, then renamed into place. `requirements.in` pins package versions; `requirements.lock` pins versions and accepted artifact SHA-256 hashes, and Docker installs with `--require-hashes`. The Python base image is digest-pinned. The runner Dockerfile installs no apt packages; it uses the pinned Debian base's certificates/core utilities. Apt snapshot/version drift therefore does not affect this image build, but inherited base contents change only when its digest is intentionally updated.

Network access is used at scan time for Trivy vulnerability database updates, OSV vulnerability queries, and Semgrep registry rules. A scanner process error (including a reported network error) fails that adapter; the overall scan is incomplete/indeterminate rather than clean. A controlled test covers this exit path. An initial scan may take longer while Trivy populates its cache. Offline database/cache configuration is not implemented. Vulnerability databases and Semgrep registry rule content are dynamic scan inputs and are not reproducibly pinned. Docker images default to the versioned tag; `--image` accepts a digest-qualified reference, but Vesper does not resolve/enforce an image digest itself. Use a published digest for release/CI reproducibility.

## Output

Each scan output directory receives `project.json`, `scan.json`, `findings.json`, `remediations.json`, `summary.json`, and `raw/` scanner artifacts. Findings remain individual and auditable; remediations answer which engineering action resolves one or more findings. Dependency remediation keys use ecosystem, package, installed/fixed versions, and artifact. Repeated container/IaC rules group by scanner and rule; SAST findings remain separate. Cross-scanner vulnerability matches merge when canonical vulnerability ID, package/version, and location align, retaining all scanner evidence.

Findings include normalized severity and separate remediation priority, stable fingerprints, location, package/security metadata, conservative impact, and `reachability: unknown` unless evidence supports more. Summary retains legacy top-level totals and adds Vesper generator metadata, nested finding/remediation counts, and blocking finding/remediation counts. `scan.json` distinguishes execution status from security-gate status. Scanner coverage distinguishes `clean`, `completed_with_findings`, `not_applicable`, `skipped`, `failed`, and `timeout`; a skipped scanner is never described as clean.

The Lynx raw scan outputs described in the product brief were not present in this checkout, so exact 31-finding/5-remediation regression totals could not be verified here. Synthetic tests cover the underlying grouping rules without hardcoding Lynx counts.

Known secret-shaped values are scrubbed from normalized findings, logs, and raw JSON. Raw scanner output is treated as sensitive and scrubbed before persistence. Redaction is heuristic and cannot guarantee removal of every proprietary scanner-specific representation; protect the output volume accordingly and review new scanner formats before enabling them.

## Exit codes

- `0`: at least one applicable scanner ran; all applicable enabled scanners completed; policy passed
- `1`: all applicable enabled scanners completed; policy failed because findings violated policy
- `2`: incomplete scan (no meaningful coverage or any applicable scanner/process/parser failure), Docker/transfer failure, or result export failure
- `3`: invalid or unreadable configuration
- `4`: unexpected internal error

Scan execution status and security assessment are separate. `scan.json` reports `completed` or `incomplete`; incomplete scans have `securityGate.status=indeterminate`, never `passed`. Scanner states are `clean`, `completed_with_findings`, `not_applicable`, `skipped`, `failed`, and `timeout`. `not_applicable` and explicitly disabled `skipped` scanners are not described as clean. At least one applicable scanner must return valid structured data, and every applicable enabled scanner must complete before the policy gate can pass. A scanner/parser failure does not stop independent adapters; partial results are retained but the overall exit is `2`. `SECURITY_SCAN_ID` from the launcher is authoritative in `scan.json`. Docker access is a privileged host trust boundary; remote daemon operators can access staged source and results. Outbound network is used for vulnerability data and Semgrep rules. Vesper does not expose scanner ports or mount the Docker socket in the runner.

## Tests and fixture

Run unit tests from the repository root:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

`tests/fixtures/vulnerable-app` contains synthetic SQL, fake-credential, dependency, Docker, Terraform, and Kubernetes examples. The credential is deliberately fake. The fixture's Dockerfile and dependency are intentionally unsafe and must not be used as application dependencies.

## Limitations and next milestone

Detection is filename/content based rather than a full build-system model. Scanner support varies by ecosystem and may change with remote vulnerability data/rules. Secret redaction is best-effort. This MVP does not build container images, require Docker, clone repositories, or provide offline mirrors. Future reproducibility work can bundle immutable scanner rules and vulnerability data; provider-specific CI distribution remains a later milestone.
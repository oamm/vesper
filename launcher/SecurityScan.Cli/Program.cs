using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Vesper.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0)
        {
            var command = args[0].ToLowerInvariant();
            if (command == "version")
            {
                PrintVersion();
                return 0;
            }
            if (command == "inspect")
            {
                return await InspectDockerAsync();
            }
            if (command is "report" or "gate")
            {
                return RunReportCommand(command, args[1..]);
            }
            if (command == "scan")
            {
                args = args[1..];
            }
        }

        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            PrintHelp();
            return 0;
        }
        if (args.Contains("--version", StringComparer.Ordinal))
        {
            PrintVersion();
            return 0;
        }

        LaunchOptions options;
        try
        {
            options = ParseArguments(args);
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"[usage] {exception.Message}");
            PrintHelp();
            return 3;
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        using var sigtermRegistration = OperatingSystem.IsWindows()
            ? null
            : PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
            {
                context.Cancel = true;
                cancellation.Cancel();
            });

        try
        {
            return await new ScanLauncher(options).RunAsync(cancellation.Token);
        }
        catch (BaselineInputException exception)
        {
            Console.Error.WriteLine($"[baseline] {exception.Message}");
            return 2;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("[launcher] Interrupted.");
            return 2;
        }
        catch (FileNotFoundException exception)
        {
            Console.Error.WriteLine($"[config] {exception.Message}");
            return 3;
        }
        catch (WorkspaceModeException exception)
        {
            Console.Error.WriteLine($"[workspace-mode] {exception.Message}");
            return 3;
        }
        catch (DirectoryNotFoundException exception)
        {
            Console.Error.WriteLine($"[config] {exception.Message}");
            return 3;
        }
        catch (DockerCommandException exception)
        {
            Console.Error.WriteLine($"[docker] {exception.Message}");
            return 2;
        }
        catch (DockerOperationTimeoutException exception)
        {
            Console.Error.WriteLine($"[docker] {exception.Message}");
            return 2;
        }
        catch (Win32Exception exception)
        {
            Console.Error.WriteLine($"[docker] Unable to start Docker CLI: {exception.Message}");
            return 2;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[launcher] {exception.Message}");
            return 4;
        }
    }

    private static LaunchOptions ParseArguments(string[] args)
    {
        string? workspace = null;
        string? output = null;
        var requestedMode = WorkspaceMode.Auto;
        var includeGit = false;
        var keepVolumes = false;
        var verbose = false;
        var image = LauncherImages.DefaultRunner;
        string? config = null;
        string? baseline = null;
        var cpus = ScanResourceLimits.Default.Cpus;
        var memory = ScanResourceLimits.Default.Memory;
        var pidsLimit = ScanResourceLimits.Default.PidsLimit.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var maxWorkspaceBytes = WorkspaceTransferLimits.Default.MaxWorkspaceBytes.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var maxFiles = WorkspaceTransferLimits.Default.MaxFiles.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var maxFileBytes = WorkspaceTransferLimits.Default.MaxFileBytes.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var maxOutputBytes = WorkspaceTransferLimits.Default.MaxOutputBytes.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var maxOutputFiles = WorkspaceTransferLimits.Default.MaxOutputFiles.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var maxEntries = WorkspaceTransferLimits.Default.MaxEntries.ToString(System.Globalization.CultureInfo.InvariantCulture);

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            string Value()
            {
                if (++index >= args.Length)
                {
                    throw new ArgumentException($"{argument} requires a value.");
                }
                return args[index];
            }

            switch (argument)
            {
                case "--output": output = Value(); break;
                case "--workspace-mode":
                    requestedMode = Value().ToLowerInvariant() switch
                    {
                        "auto" => WorkspaceMode.Auto,
                        "bind" => WorkspaceMode.Bind,
                        "volume" => WorkspaceMode.Volume,
                        _ => throw new ArgumentException("--workspace-mode must be auto, bind, or volume."),
                    };
                    break;
                case "--config": config = Value(); break;
                case "--baseline": baseline = Value(); break;
                case "--image": image = Value(); break;
                case "--cpus": cpus = Value(); break;
                case "--memory": memory = Value(); break;
                case "--pids-limit": pidsLimit = Value(); break;
                case "--max-workspace-bytes": maxWorkspaceBytes = Value(); break;
                case "--max-files": maxFiles = Value(); break;
                case "--max-file-bytes": maxFileBytes = Value(); break;
                case "--max-output-bytes": maxOutputBytes = Value(); break;
                case "--max-output-files": maxOutputFiles = Value(); break;
                case "--max-entries": maxEntries = Value(); break;
                case "--include-git": includeGit = true; break;
                case "--keep-volumes": keepVolumes = true; break;
                case "--verbose": verbose = true; break;
                default:
                    if (argument.StartsWith("-", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"Unknown option: {argument}");
                    }
                    if (workspace is not null)
                    {
                        throw new ArgumentException("Specify only one workspace directory.");
                    }
                    workspace = argument;
                    break;
            }
        }

        return new LaunchOptions(
            Path.GetFullPath(workspace ?? "."),
            output is null ? null : Path.GetFullPath(output),
            requestedMode,
            includeGit,
            keepVolumes,
            verbose,
            image,
            config,
            baseline,
            ScanResourceLimits.Parse(cpus, memory, pidsLimit),
            WorkspaceTransferLimits.Parse(maxWorkspaceBytes, maxFiles, maxFileBytes, maxOutputBytes, maxOutputFiles, maxEntries));
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Vesper Security Scan");
        Console.WriteLine("Usage: vesper <command> [arguments]");
        Console.WriteLine("  scan [workspace] [options]  Analyze a repository");
        Console.WriteLine("  inspect                     Inspect the active Docker endpoint");
        Console.WriteLine("  report [output-directory]   Summarize a completed scan");
        Console.WriteLine("       --html [file]          Write a self-contained human-readable HTML report");
        Console.WriteLine("  gate [output-directory]     Return the saved security gate status");
        Console.WriteLine("  version                     Print Vesper and default image versions");
        Console.WriteLine("Scan options:");
        Console.WriteLine("  --output PATH             Output base; each scan writes to a unique child directory");
        Console.WriteLine("  --workspace-mode MODE     auto, bind, or volume (default: auto)");
        Console.WriteLine("  --config PATH             Optional local scanner YAML configuration");
        Console.WriteLine("  --baseline PATH           Compare against a versioned baseline artifact");
        Console.WriteLine("  --include-git             Include .git history in volume staging");
        Console.WriteLine("  --keep-volumes            Keep temporary Docker volumes and print their names");
        Console.WriteLine($"  --image IMAGE             Scanner image (default: {LauncherImages.DefaultRunner})");
        Console.WriteLine("  --cpus NUMBER             CPU limit (default: 2)");
        Console.WriteLine("  --memory SIZE             Memory limit (default: 4g)");
        Console.WriteLine("  --pids-limit NUMBER       PID limit (default: 512)");
        Console.WriteLine("  --max-workspace-bytes N   Source byte limit (default: 20 GiB)");
        Console.WriteLine("  --max-files N             Source file count limit (default: 500000)");
        Console.WriteLine("  --max-file-bytes N        Single source/output file limit (default: 2 GiB)");
        Console.WriteLine("  --max-output-bytes N      Extracted report byte limit (default: 4 GiB)");
        Console.WriteLine("  --max-output-files N      Extracted report count limit (default: 100000)");
        Console.WriteLine("  --max-entries N           Source/output archive entry limit (default: 600000)");
        Console.WriteLine("  --verbose                 Print resolved paths and extra context");
        Console.WriteLine("Commands: scan, inspect, report, gate, version");
    }

    private static void PrintVersion()
    {
        var version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "unknown";
        Console.WriteLine($"Vesper {version}");
        Console.WriteLine($"Default scanner image: {LauncherImages.DefaultRunner}");
    }

    private static async Task<int> InspectDockerAsync()
    {
        try
        {
            var environment = await DockerEnvironmentDetector.DetectAsync(new DockerClient(), CancellationToken.None);
            Console.WriteLine("Vesper Docker Environment");
            Console.WriteLine($"Context: {environment.Context}");
            Console.WriteLine($"Endpoint: {DockerEndpointClassifier.SanitizeForDisplay(environment.Endpoint)}");
            Console.WriteLine($"Daemon: {(environment.IsRemote ? "remote" : "local")}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[docker] {exception.Message}");
            return 2;
        }
    }

    private static int RunReportCommand(string command, string[] arguments)
    {
        var requestedPath = (string?)null;
        var htmlPath = (string?)null;
        var writeHtml = false;
        for (var index = 0; index < arguments.Length; index++)
        {
            var argument = arguments[index];
            if (argument.Equals("--html", StringComparison.OrdinalIgnoreCase))
            {
                writeHtml = true;
                if (index + 1 < arguments.Length && !arguments[index + 1].StartsWith("-", StringComparison.Ordinal))
                {
                    htmlPath = arguments[++index];
                }
            }
            else if (requestedPath is null)
            {
                requestedPath = argument;
            }
            else
            {
                Console.Error.WriteLine($"[report] Unexpected argument: {argument}");
                return 3;
            }
        }

        if (command == "gate" && writeHtml)
        {
            Console.Error.WriteLine("[gate] --html is only supported by the report command.");
            return 3;
        }

        var reportDirectory = ScanReportLocator.FindLatest(requestedPath ?? "security-results");
        if (reportDirectory is null)
        {
            Console.Error.WriteLine("[report] No completed Vesper scan was found. Provide an output directory.");
            return 3;
        }

        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(reportDirectory, "summary.json")));
        using var scanDocument = JsonDocument.Parse(File.ReadAllText(Path.Combine(reportDirectory, "scan.json")));
        var root = document.RootElement;
        var scanRoot = scanDocument.RootElement;
        var gate = root.GetProperty("gate");
        var gateStatus = gate.GetProperty("status").GetString() ?? "unknown";
        var hasBaselineDelta = gate.TryGetProperty("baselineDelta", out _);
        var hasBaselineMetadata = root.TryGetProperty("baselineComparison", out _);
        Dictionary<string, int>? comparisonCounts = null;
        if (hasBaselineDelta != hasBaselineMetadata
            || (hasBaselineMetadata && !TryReadComparisonSummary(reportDirectory, root, out comparisonCounts)))
        {
            Console.Error.WriteLine("[report] Baseline comparison artifacts are missing or inconsistent.");
            return 2;
        }
        if (!ValidateSavedArtifacts(reportDirectory, scanRoot, root))
        {
            Console.Error.WriteLine("[report] Saved report artifacts are missing, malformed, or inconsistent.");
            return 2;
        }
        if (command == "gate")
        {
            Console.WriteLine("Vesper Security Gate");
            Console.WriteLine(gateStatus.ToUpperInvariant());
            if (gate.TryGetProperty("reason", out var reason))
            {
                Console.WriteLine(reason.GetString());
            }
            if (TextProperty(scanRoot, "executionStatus") is "incomplete" or "cancelled")
            {
                return 2;
            }
            return SecurityGateExitPolicy.FromStatus(gateStatus);
        }

        Console.WriteLine("Vesper Security Report");
        Console.WriteLine($"Directory: {reportDirectory}");
        var findingsTotal = root.TryGetProperty("findings", out var findingsSummary)
            && findingsSummary.TryGetProperty("total", out var canonicalTotal)
                ? canonicalTotal.GetInt32()
                : root.GetProperty("total").GetInt32();
        Console.WriteLine($"Findings: {findingsTotal}");
        Console.WriteLine($"Remediations: {root.GetProperty("remediations").GetProperty("total").GetInt32()}");
        Console.WriteLine($"Security Gate: {gateStatus.ToUpperInvariant()}");
        if (comparisonCounts is not null)
        {
            Console.WriteLine("Baseline comparison");
            foreach (var state in new[] { "new", "existing", "changed", "resolved", "unverified" })
            {
                Console.WriteLine($"  {state.ToUpperInvariant(),-12}{comparisonCounts[state]}");
            }
        }
        var remediationPath = Path.Combine(reportDirectory, "remediations.json");
        if (File.Exists(remediationPath))
        {
            using var remediationDocument = JsonDocument.Parse(File.ReadAllText(remediationPath));
            foreach (var remediation in remediationDocument.RootElement.EnumerateArray())
            {
                var priority = remediation.GetProperty("priority").GetString()?.ToUpperInvariant();
                Console.WriteLine($"[{priority}] {remediation.GetProperty("title").GetString()}");
                Console.WriteLine($"    {remediation.GetProperty("summary").GetString()}");
            }
        }
        if (writeHtml)
        {
            var outputPath = htmlPath is null
                ? Path.Combine(reportDirectory, "report.html")
                : Path.GetFullPath(htmlPath);
            try
            {
                ReportHtmlWriter.Write(reportDirectory, outputPath, root, comparisonCounts);
                Console.WriteLine($"HTML report: {outputPath}");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
            {
                Console.Error.WriteLine($"[report] Unable to write HTML report: {exception.Message}");
                return 2;
            }
        }
        return 0;
    }

    private static bool TryReadComparisonSummary(
        string reportDirectory,
        JsonElement summary,
        out Dictionary<string, int>? counts)
    {
        counts = null;
        try
        {
            using var comparisonDocument = JsonDocument.Parse(File.ReadAllText(Path.Combine(reportDirectory, "comparison.json")));
            using var scanDocument = JsonDocument.Parse(File.ReadAllText(Path.Combine(reportDirectory, "scan.json")));
            var comparison = comparisonDocument.RootElement;
            var scan = scanDocument.RootElement;
            var baselineMetadata = summary.GetProperty("baselineComparison");
            var baseline = comparison.GetProperty("baseline");
            var current = comparison.GetProperty("current");
            var reportSchemas = scan.GetProperty("reportSchemas");
            if (comparison.GetProperty("schemaVersion").GetInt32() != 1
                || reportSchemas.GetProperty("comparison").GetInt32() != 1
                || baseline.GetProperty("baselineId").GetString() != baselineMetadata.GetProperty("baselineId").GetString()
                || scan.GetProperty("baselineId").GetString() != baseline.GetProperty("baselineId").GetString()
                || current.GetProperty("scanId").GetString() != scan.GetProperty("scanId").GetString()
                || current.GetProperty("startedAt").GetString() != scan.GetProperty("startedAt").GetString()
                || summary.GetProperty("status").GetString() != scan.GetProperty("executionStatus").GetString()
                || !GateArtifactsMatch(summary.GetProperty("gate"), scan.GetProperty("securityGate")))
            {
                return false;
            }

            var summaryCounts = comparison.GetProperty("summary");
            var groups = comparison.GetProperty("findings");
            var parsedCounts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var state in new[] { "new", "existing", "changed", "resolved", "unverified" })
            {
                var records = groups.GetProperty(state);
                var count = summaryCounts.GetProperty(state).GetInt32();
                if (records.ValueKind != JsonValueKind.Array || records.GetArrayLength() != count)
                {
                    return false;
                }
                parsedCounts.Add(state, count);
            }
            counts = parsedCounts;
            return true;
        }
        catch (Exception exception) when (exception is IOException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool GateArtifactsMatch(JsonElement summaryGate, JsonElement scanGate)
    {
        foreach (var property in new[] { "status", "reason", "blockingFindings", "blockingRemediations", "policyStatus" })
        {
            var hasSummaryValue = summaryGate.TryGetProperty(property, out var summaryValue);
            var hasScanValue = scanGate.TryGetProperty(property, out var scanValue);
            if (hasSummaryValue != hasScanValue
                || (hasSummaryValue && summaryValue.GetRawText() != scanValue.GetRawText()))
            {
                return false;
            }
        }

        if (!summaryGate.TryGetProperty("blockingFindingIds", out var summaryIds)
            || !scanGate.TryGetProperty("blockingFindingIds", out var scanIds)
            || !summaryIds.EnumerateArray().Select(item => item.GetString()).SequenceEqual(scanIds.EnumerateArray().Select(item => item.GetString())))
        {
            return false;
        }

        var hasSummaryDelta = summaryGate.TryGetProperty("baselineDelta", out var summaryDelta);
        var hasScanDelta = scanGate.TryGetProperty("baselineDelta", out var scanDelta);
        if (hasSummaryDelta != hasScanDelta)
        {
            return false;
        }
        if (!hasSummaryDelta)
        {
            return true;
        }

        return summaryDelta.GetProperty("newFindings").GetInt32() == scanDelta.GetProperty("newFindings").GetInt32()
            && summaryDelta.GetProperty("failOnNew").EnumerateArray().Select(item => item.GetString())
                .SequenceEqual(scanDelta.GetProperty("failOnNew").EnumerateArray().Select(item => item.GetString()))
            && summaryDelta.GetProperty("blockingFindingIds").EnumerateArray().Select(item => item.GetString())
                .SequenceEqual(scanDelta.GetProperty("blockingFindingIds").EnumerateArray().Select(item => item.GetString()));
    }

    private static bool ValidateSavedArtifacts(string reportDirectory, JsonElement scan, JsonElement summary)
    {
        try
        {
            if (!scan.TryGetProperty("reportSchemas", out var schemas) || schemas.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (var schema in schemas.EnumerateObject())
            {
                var required = schema.Name is "project" or "scan" or "findings" or "remediations" or "summary"
                    || schema.Name is "components" or "posture" or "comparison";
                if (!required) continue;
                var file = Path.Combine(reportDirectory, schema.Name + ".json");
                if (!File.Exists(file)) return false;
                using var document = JsonDocument.Parse(File.ReadAllText(file));
                if (schema.Name == "components" && (!document.RootElement.TryGetProperty("schemaVersion", out var componentVersion) || componentVersion.GetInt32() != 1 || !document.RootElement.TryGetProperty("components", out var components) || components.ValueKind != JsonValueKind.Array)) return false;
                if (schema.Name == "posture" && (!document.RootElement.TryGetProperty("schemaVersion", out var postureVersion) || postureVersion.GetInt32() != 1 || !document.RootElement.TryGetProperty("checks", out var checks) || checks.ValueKind != JsonValueKind.Array)) return false;
            }

            if (scan.TryGetProperty("scanners", out var scanners))
            {
                if (scanners.ValueKind != JsonValueKind.Array) return false;
                foreach (var scanner in scanners.EnumerateArray())
                {
                    if (!scanner.TryGetProperty("rawOutput", out var raw) || raw.ValueKind != JsonValueKind.String) return false;
                    var relative = raw.GetString() ?? "";
                    if (!relative.StartsWith("raw/", StringComparison.Ordinal) || relative.Contains("..", StringComparison.Ordinal) || Path.IsPathRooted(relative)) return false;
                    var root = Path.GetFullPath(reportDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    var path = Path.GetFullPath(Path.Combine(reportDirectory, relative.Replace('/', Path.DirectorySeparatorChar)));
                    if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) return false;
                }
            }

            var findingsPath = Path.Combine(reportDirectory, "findings.json");
            using var findingsDocument = JsonDocument.Parse(File.ReadAllText(findingsPath));
            if (findingsDocument.RootElement.ValueKind != JsonValueKind.Array) return false;
            if (summary.TryGetProperty("findings", out var findingSummary) && findingSummary.TryGetProperty("total", out var total) && total.GetInt32() != findingsDocument.RootElement.GetArrayLength()) return false;
            return true;
        }
        catch (Exception exception) when (exception is IOException or JsonException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    private static string? TextProperty(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

}

using System.ComponentModel;
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
                return RunReportCommand(command, args.Length > 1 ? args[1] : null);
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

        try
        {
            return await new ScanLauncher(options).RunAsync(cancellation.Token);
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
        var image = "vesper-runner:latest";
        string? config = null;
        var cpus = ScanResourceLimits.Default.Cpus;
        var memory = ScanResourceLimits.Default.Memory;
        var pidsLimit = ScanResourceLimits.Default.PidsLimit.ToString(System.Globalization.CultureInfo.InvariantCulture);

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
                case "--image": image = Value(); break;
                case "--cpus": cpus = Value(); break;
                case "--memory": memory = Value(); break;
                case "--pids-limit": pidsLimit = Value(); break;
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
            ScanResourceLimits.Parse(cpus, memory, pidsLimit));
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Vesper Security Scan");
        Console.WriteLine("Usage: vesper <command> [arguments]");
        Console.WriteLine("  scan [workspace] [options]  Analyze a repository");
        Console.WriteLine("  inspect                     Inspect the active Docker endpoint");
        Console.WriteLine("  report [output-directory]   Summarize a completed scan");
        Console.WriteLine("  gate [output-directory]     Return the saved security gate status");
        Console.WriteLine("  version                     Print Vesper and default image versions");
        Console.WriteLine("Scan options:");
        Console.WriteLine("  --output PATH             Output base; each scan writes to a unique child directory");
        Console.WriteLine("  --workspace-mode MODE     auto, bind, or volume (default: auto)");
        Console.WriteLine("  --config PATH             Optional local scanner YAML configuration");
        Console.WriteLine("  --include-git             Include .git history in volume staging");
        Console.WriteLine("  --keep-volumes            Keep temporary Docker volumes and print their names");
        Console.WriteLine("  --image IMAGE             Scanner image (default: vesper-runner:latest)");
        Console.WriteLine("  --cpus NUMBER             CPU limit (default: 2)");
        Console.WriteLine("  --memory SIZE             Memory limit (default: 4g)");
        Console.WriteLine("  --pids-limit NUMBER       PID limit (default: 512)");
        Console.WriteLine("  --verbose                 Print resolved paths and extra context");
        Console.WriteLine("Commands: scan, inspect, report, gate, version");
    }

    private static void PrintVersion()
    {
        var version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "unknown";
        Console.WriteLine($"Vesper {version}");
        Console.WriteLine("Default scanner image: vesper-runner:latest");
    }

    private static async Task<int> InspectDockerAsync()
    {
        try
        {
            var environment = await DockerEnvironmentDetector.DetectAsync(new DockerClient(), CancellationToken.None);
            Console.WriteLine("Vesper Docker Environment");
            Console.WriteLine($"Context: {environment.Context}");
            Console.WriteLine($"Endpoint: {environment.Endpoint}");
            Console.WriteLine($"Daemon: {(environment.IsRemote ? "remote" : "local")}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[docker] {exception.Message}");
            return 2;
        }
    }

    private static int RunReportCommand(string command, string? requestedPath)
    {
        var reportDirectory = FindReportDirectory(requestedPath ?? "security-results");
        if (reportDirectory is null)
        {
            Console.Error.WriteLine("[report] No completed Vesper scan was found. Provide an output directory.");
            return 3;
        }

        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(reportDirectory, "summary.json")));
        var root = document.RootElement;
        var gate = root.GetProperty("gate");
        var gateStatus = gate.GetProperty("status").GetString() ?? "unknown";
        if (command == "gate")
        {
            Console.WriteLine("Vesper Security Gate");
            Console.WriteLine(gateStatus.ToUpperInvariant());
            if (gate.TryGetProperty("reason", out var reason))
            {
                Console.WriteLine(reason.GetString());
            }
            return gateStatus == "failed" ? 1 : 0;
        }

        Console.WriteLine("Vesper Security Report");
        Console.WriteLine($"Directory: {reportDirectory}");
        Console.WriteLine($"Findings: {root.GetProperty("total").GetInt32()}");
        Console.WriteLine($"Remediations: {root.GetProperty("remediations").GetProperty("total").GetInt32()}");
        Console.WriteLine($"Security Gate: {gateStatus.ToUpperInvariant()}");
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
        return 0;
    }

    private static string? FindReportDirectory(string requestedPath)
    {
        var path = Path.GetFullPath(requestedPath);
        if (File.Exists(Path.Combine(path, "summary.json")))
        {
            return path;
        }
        if (!Directory.Exists(path))
        {
            return null;
        }
        return Directory.EnumerateDirectories(path)
            .Where(directory => File.Exists(Path.Combine(directory, "summary.json")))
            .OrderByDescending(directory => Directory.GetLastWriteTimeUtc(directory))
            .FirstOrDefault();
    }
}
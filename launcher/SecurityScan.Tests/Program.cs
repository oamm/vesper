using System.Formats.Tar;
using Vesper.Cli;

var tests = new (string Name, Action Run)[]
{
    ("endpoint classification", EndpointClassification),
    ("workspace mode selection", WorkspaceModeSelection),
    ("unique scan execution identities", UniqueScanExecutionIdentities),
    ("resource limit validation", ResourceLimitValidation),
    ("Windows mount arguments", WindowsMountArguments),
    ("scanner exit preservation", ExitCodePreservation),
    ("temporary volume cleanup", VolumeCleanup),
    ("workspace archive round trip", ArchiveRoundTrip),
};

var failed = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception exception)
    {
        failed++;
        Console.Error.WriteLine($"FAIL {test.Name}: {exception.Message}");
    }
}

return failed == 0 ? 0 : 1;

static void EndpointClassification()
{
    Check(!DockerEndpointClassifier.IsRemote("npipe:////./pipe/docker_engine"), "npipe should be local");
    Check(!DockerEndpointClassifier.IsRemote("unix:///var/run/docker.sock"), "unix socket should be local");
    Check(DockerEndpointClassifier.IsRemote("ssh://root@192.168.0.211"), "ssh should be remote");
    Check(DockerEndpointClassifier.IsRemote("tcp://192.168.1.8:2376"), "non-loopback TCP should be remote");
    Check(!DockerEndpointClassifier.IsRemote("tcp://127.0.0.1:2375"), "IPv4 loopback TCP should be local");
    Check(!DockerEndpointClassifier.IsRemote("tcp://[::1]:2375"), "IPv6 loopback TCP should be local");
}

static void WorkspaceModeSelection()
{
    Check(WorkspaceModeResolver.Resolve(WorkspaceMode.Auto, daemonIsRemote: false) == WorkspaceMode.Bind, "local auto should bind");
    Check(WorkspaceModeResolver.Resolve(WorkspaceMode.Auto, daemonIsRemote: true) == WorkspaceMode.Volume, "remote auto should stage volumes");
    Check(WorkspaceModeResolver.Resolve(WorkspaceMode.Volume, daemonIsRemote: false) == WorkspaceMode.Volume, "forced volume should be honored locally");
    Check(WorkspaceModeResolver.Resolve(WorkspaceMode.Volume, daemonIsRemote: true) == WorkspaceMode.Volume, "forced volume should be honored remotely");
    try
    {
        WorkspaceModeResolver.Resolve(WorkspaceMode.Bind, daemonIsRemote: true);
        throw new InvalidOperationException("remote bind should fail early");
    }
    catch (InvalidOperationException exception) when (exception.Message.Contains("remote", StringComparison.OrdinalIgnoreCase))
    {
    }
}

static void ExitCodePreservation()
{
    for (var code = 0; code <= 4; code++)
    {
        Check(ScannerExitPolicy.AfterExport(code, exportSucceeded: true) == code, $"exit {code} should be preserved");
    }
    Check(ScannerExitPolicy.AfterExport(1, exportSucceeded: false) == 2, "failed export should report infrastructure failure");
    Check(ScannerExitPolicy.AfterExport(125, exportSucceeded: true) == 2, "Docker CLI failure should map to runner failure");
}

static void VolumeCleanup()
{
    var volumes = new[] { "source-a", "output-a", "config-a" };
    Check(TemporaryVolumeCleanup.VolumesToRemove(volumes, keepVolumes: false).SequenceEqual(volumes), "normal cleanup should remove all volumes");
    Check(TemporaryVolumeCleanup.VolumesToRemove(volumes, keepVolumes: true).Count == 0, "keep-volumes should retain all volumes");
}

static void ArchiveRoundTrip()
{
    var root = Path.Combine(Path.GetTempPath(), $"securityscan-test-{Guid.NewGuid():N}");
    var output = Path.Combine(root, "security-results");
    var destination = Path.Combine(Path.GetTempPath(), $"securityscan-extract-{Guid.NewGuid():N}");
    Directory.CreateDirectory(Path.Combine(root, "nested space", "utf-8-å"));
    Directory.CreateDirectory(Path.Combine(root, "node_modules", "large"));
    Directory.CreateDirectory(Path.Combine(root, "artifacts", "cli"));
    Directory.CreateDirectory(Path.Combine(root, ".git", "objects"));
    File.WriteAllText(Path.Combine(root, "package-lock.json"), "{}", System.Text.Encoding.UTF8);
    File.WriteAllText(Path.Combine(root, "Dockerfile"), "FROM scratch\n", System.Text.Encoding.UTF8);
    File.WriteAllText(Path.Combine(root, "results.sarif"), "{\"version\":\"2.1.0\"}", System.Text.Encoding.UTF8);
    File.WriteAllText(Path.Combine(root, "deploy.yaml"), "apiVersion: v1\nkind: Pod\n", System.Text.Encoding.UTF8);
    File.WriteAllText(Path.Combine(root, "nested space", "utf-8-å", "empty file.json"), "", System.Text.Encoding.UTF8);
    var bytes = new byte[] { 0, 255, 17, 128, 10 };
    File.WriteAllBytes(Path.Combine(root, "nested space", "binary.bin"), bytes);
    File.WriteAllText(Path.Combine(root, "node_modules", "large", "ignored.js"), "ignored");
    File.WriteAllText(Path.Combine(root, "artifacts", "cli", "vesper.exe"), "not source");
    File.WriteAllText(Path.Combine(root, ".git", "objects", "history"), "excluded");
    Directory.CreateDirectory(output);

    var archive = WorkspaceArchive.Create(root, output, configPath: null, includeGit: false);
    try
    {
        using (var stream = File.OpenRead(archive.ArchivePath))
        using (var reader = new TarReader(stream))
        {
            var names = new List<string>();
            TarEntry? entry;
            while ((entry = reader.GetNextEntry(copyData: false)) is not null)
            {
                names.Add(entry.Name);
            }
            Check(names.Any(name => name.Contains("package-lock.json", StringComparison.Ordinal)), "lockfile should be included");
            Check(names.Any(name => name.Contains("Dockerfile", StringComparison.Ordinal)), "Dockerfile should be included");
            Check(names.Any(name => name.Contains("results.sarif", StringComparison.Ordinal)), "SARIF should be included");
            Check(names.Any(name => name.Contains("deploy.yaml", StringComparison.Ordinal)), "YAML should be included");
            Check(names.Any(name => name.Contains("utf-8-å", StringComparison.Ordinal)), "UTF-8 path should be included");
            Check(!names.Any(name => name.Contains("node_modules", StringComparison.Ordinal)), "generated dependencies should be excluded");
            Check(!names.Any(name => name.Contains("artifacts", StringComparison.Ordinal)), "compiled artifacts should be excluded");
            Check(!names.Any(name => name.StartsWith(".git/", StringComparison.Ordinal)), "git history should be excluded by default");
        }

        WorkspaceArchive.Extract(archive.ArchivePath, destination);
        Check(File.Exists(Path.Combine(destination, "nested space", "utf-8-å", "empty file.json")), "empty file should round-trip");
        Check(File.ReadAllBytes(Path.Combine(destination, "nested space", "binary.bin")).SequenceEqual(bytes), "binary file must remain unchanged");
    }
    finally
    {
        File.Delete(archive.ArchivePath);
        Directory.Delete(root, recursive: true);
        if (Directory.Exists(destination))
        {
            Directory.Delete(destination, recursive: true);
        }
    }
}

static void Check(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void WindowsMountArguments()
{
    const string workspace = @"C:\Users\Ada Lovelace\Dast (λ)";
    var mount = DockerMountArguments.Bind(workspace, "/workspace", readOnly: true);
    Check(mount == $"type=bind,source={workspace},target=/workspace,readonly", "path must remain one unquoted mount argument");
}

static void UniqueScanExecutionIdentities()
{
    var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "same-project-output"));
    var contexts = Enumerable.Range(0, 256)
        .AsParallel()
        .Select(_ => ScanExecutionContext.Create("C:\\Project A", root, useVolumes: true, hasConfig: true))
        .ToArray();
    Check(contexts.Select(context => context.ScanId).Distinct().Count() == contexts.Length, "scan IDs must be unique");
    Check(contexts.Select(context => context.ContainerName).Distinct().Count() == contexts.Length, "container names must be unique");
    Check(contexts.Select(context => context.SourceVolumeName).Distinct().Count() == contexts.Length, "source volumes must be unique");
    Check(contexts.Select(context => context.OutputVolumeName).Distinct().Count() == contexts.Length, "output volumes must be unique");
    Check(contexts.Select(context => context.OutputPath).Distinct().Count() == contexts.Length, "same-project output paths must be unique");
    Check(contexts.All(context => context.ContainerName.Length <= 63 && context.ContainerName.StartsWith("vesper-", StringComparison.Ordinal)), "Docker names should be valid and concise");
    Check(contexts.All(context => context.Labels("runner").Contains($"securityscan.scan-id={context.ScanIdText}")), "Docker labels must carry the full scan ID");
    Check(contexts.All(context => context.OwnsResourceLabels($"true|{context.ScanIdText}")), "current scan resource labels should be recognized");
    Check(contexts.All(context => !context.OwnsResourceLabels($"true|{Guid.NewGuid():D}")), "resources from another scan must not be owned");
    Check(contexts.All(context => context.ProjectName == "Project-A"), "project label should be sanitized");
    Check(contexts.All(context => context.SourceVolumeName != context.OutputVolumeName), "source and output volumes must be distinct");
}

static void ResourceLimitValidation()
{
    var defaults = ScanResourceLimits.Default;
    Check(defaults.Cpus == "2" && defaults.Memory == "4g" && defaults.PidsLimit == 512, "resource defaults should be sane");
    var custom = ScanResourceLimits.Parse("1.5", "2048m", "256");
    Check(custom.Cpus == "1.5" && custom.Memory == "2048m" && custom.PidsLimit == 256, "valid custom limits should round-trip");
    ExpectArgumentError(() => ScanResourceLimits.Parse("0", "4g", "512"));
    ExpectArgumentError(() => ScanResourceLimits.Parse("2", "0g", "512"));
    ExpectArgumentError(() => ScanResourceLimits.Parse("2", "4g", "0"));
}

static void ExpectArgumentError(Action action)
{
    try
    {
        action();
        throw new InvalidOperationException("invalid resource values must be rejected");
    }
    catch (ArgumentException)
    {
    }
}
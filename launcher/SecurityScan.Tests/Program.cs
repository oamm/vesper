using System.Formats.Tar;
using System.Reflection;
using Vesper.Cli;

if (args.Length > 0 && args[0] == "--test-fake-docker")
{
    Thread.Sleep(TimeSpan.FromSeconds(30));
    return 0;
}
if (args.Length > 0 && args[0] == "--test-docker-disconnect")
{
    Console.Error.WriteLine("Cannot connect to the Docker daemon: controlled disconnect");
    return 125;
}
if (args.Length == 3 && args[0] == "--test-create-source-archive")
{
    var source = Path.GetFullPath(args[1]);
    var archive = WorkspaceArchive.Create(source, Path.Combine(source, "security-results"), null, includeGit: false);
    try
    {
        File.Copy(archive.ArchivePath, args[2], overwrite: true);
    }
    finally
    {
        File.Delete(archive.ArchivePath);
    }
    return 0;
}

var tests = new (string Name, Action Run)[]
{
    ("endpoint classification", EndpointClassification),
    ("Docker target pinning", DockerTargetPinning),
    ("Docker control timeout", DockerControlTimeout),
    ("Docker transfer timeout", DockerTransferTimeout),
    ("Docker daemon disconnect classification", DockerDaemonDisconnectClassification),
    ("workspace mode selection", WorkspaceModeSelection),
    ("unique scan execution identities", UniqueScanExecutionIdentities),
    ("date-grouped scan output paths", DateGroupedOutputPaths),
    ("legacy and date-grouped report lookup", LegacyAndDateGroupedReportLookup),
    ("resource limit validation", ResourceLimitValidation),
    ("workspace transfer limit validation", WorkspaceTransferLimitValidation),
    ("Windows mount arguments", WindowsMountArguments),
    ("scanner exit preservation", ExitCodePreservation),
    ("saved gate exit semantics", SavedGateExitSemantics),
    ("temporary volume cleanup", VolumeCleanup),
    ("workspace archive round trip", ArchiveRoundTrip),
    ("empty workspace archive is valid", EmptyWorkspaceArchive),
    ("private temporary archive permissions", PrivateArchivePermissions),
    ("reject archive traversal and absolute paths", RejectArchiveTraversal),
    ("ignore special archive entries", IgnoreSpecialArchiveEntries),
    ("reject symlink output parents", RejectSymlinkOutputParent),
    ("preserve Unix backslash filenames", PreserveUnixBackslashFilename),
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
    var sanitized = DockerEndpointClassifier.SanitizeForDisplay("ssh://operator:secret@scanner.example:22?token=hidden#fragment");
    Check(!sanitized.Contains("secret", StringComparison.Ordinal) && !sanitized.Contains("hidden", StringComparison.Ordinal), "Docker endpoint display must redact credentials and query data");
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
        if (!OperatingSystem.IsWindows())
        {
            var directoryMode = File.GetUnixFileMode(destination);
            var fileMode = File.GetUnixFileMode(Path.Combine(destination, "nested space", "binary.bin"));
            Check(directoryMode == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute), "extraction root must be mode 0700");
            Check(fileMode == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "extracted reports must be mode 0600");
        }
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
    var projectPath = Path.Combine(Path.GetTempPath(), "Project A");
    var contexts = Enumerable.Range(0, 256)
        .AsParallel()
        .Select(_ => ScanExecutionContext.Create(projectPath, root, useVolumes: true, hasConfig: true))
        .ToArray();
    Check(contexts.Select(context => context.ScanId).Distinct().Count() == contexts.Length, "scan IDs must be unique");
    Check(contexts.Select(context => context.ContainerName).Distinct().Count() == contexts.Length, "container names must be unique");
    Check(contexts.Select(context => context.SourceVolumeName).Distinct().Count() == contexts.Length, "source volumes must be unique");
    Check(contexts.Select(context => context.OutputVolumeName).Distinct().Count() == contexts.Length, "output volumes must be unique");
    Check(contexts.Select(context => context.OutputPath).Distinct().Count() == contexts.Length, "same-project output paths must be unique");
    Check(contexts.All(context => context.ContainerName.Length <= 63 && context.ContainerName.StartsWith("vesper-", StringComparison.Ordinal)), "Docker names should be valid and concise");
    Check(contexts.All(context => context.HelperContainerName("config-upload").Length <= 63), "helper container names must stay within Docker naming limits");
    Check(contexts.Select(context => context.HelperContainerName("upload")).Distinct().Count() == contexts.Length, "helper names must be unique across scans");
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

static void RejectArchiveTraversal()
{
    var root = Path.Combine(Path.GetTempPath(), $"vesper-tar-root-{Guid.NewGuid():N}");
    var archive = Path.Combine(Path.GetTempPath(), $"vesper-tar-{Guid.NewGuid():N}.tar");
    Directory.CreateDirectory(root);
    try
    {
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "../escaped.txt")
        {
            DataStream = new MemoryStream([1, 2, 3]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));

        File.Delete(archive);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "C:/outside.txt")
        {
            DataStream = new MemoryStream([1]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));

        File.Delete(archive);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "/outside.txt")
        {
            DataStream = new MemoryStream([1]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));
        Check(!File.Exists(Path.Combine(Directory.GetParent(root)!.FullName, "escaped.txt")), "archive must not write above destination root");
    }
    finally
    {
        File.Delete(archive);
        Directory.Delete(root, recursive: true);
    }
}

static void IgnoreSpecialArchiveEntries()
{
    var root = Path.Combine(Path.GetTempPath(), $"vesper-tar-special-{Guid.NewGuid():N}");
    var archive = Path.Combine(Path.GetTempPath(), $"vesper-tar-{Guid.NewGuid():N}.tar");
    Directory.CreateDirectory(root);
    try
    {
        using (var stream = WorkspaceArchive.CreatePrivateArchiveFile(archive))
        using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
        {
            writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "symlink") { LinkName = "../outside" });
            writer.WriteEntry(new PaxTarEntry(TarEntryType.HardLink, "hardlink") { LinkName = "../outside" });
            writer.WriteEntry(new PaxTarEntry(TarEntryType.Fifo, "fifo"));
        }
        WorkspaceArchive.Extract(archive, root);
        Check(!File.Exists(Path.Combine(root, "symlink")), "symbolic links must not be created from an archive");
        Check(!File.Exists(Path.Combine(root, "hardlink")), "hard links must not be created from an archive");
        Check(!File.Exists(Path.Combine(root, "fifo")), "FIFO entries must not be extracted");
    }
    finally
    {
        File.Delete(archive);
        Directory.Delete(root, recursive: true);
    }
}

static void RejectSymlinkOutputParent()
{
    var root = Path.Combine(Path.GetTempPath(), $"vesper-tar-link-root-{Guid.NewGuid():N}");
    var outside = Path.Combine(Path.GetTempPath(), $"vesper-tar-link-outside-{Guid.NewGuid():N}");
    var archive = Path.Combine(Path.GetTempPath(), $"vesper-tar-{Guid.NewGuid():N}.tar");
    Directory.CreateDirectory(root);
    Directory.CreateDirectory(outside);
    try
    {
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(root, "linked"), outside);
            Directory.CreateSymbolicLink(Path.Combine(root, "nested-link"), outside);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            Console.WriteLine("SKIP symlink output-parent test: symlink creation is unavailable on this host.");
            return;
        }

        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "linked/escaped.txt")
        {
            DataStream = new MemoryStream([7, 8, 9]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));
        Check(!File.Exists(Path.Combine(outside, "escaped.txt")), "extraction must not follow a pre-existing symlink parent");

        File.Delete(archive);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "nested-link/child/result.json")
        {
            DataStream = new MemoryStream([1, 2, 3]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));
        Check(!File.Exists(Path.Combine(outside, "child", "result.json")), "nested symlink parents must not receive extracted files");

        File.Delete(archive);
        var outsideFile = Path.Combine(outside, "target.txt");
        File.WriteAllText(outsideFile, "outside", System.Text.Encoding.UTF8);
        File.CreateSymbolicLink(Path.Combine(root, "linked-file.txt"), outsideFile);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "linked-file.txt")
        {
            DataStream = new MemoryStream([4, 5, 6]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));
        Check(File.ReadAllText(outsideFile, System.Text.Encoding.UTF8) == "outside", "extraction must not overwrite through a symlink file");

        File.Delete(archive);
        var brokenFileTarget = Path.Combine(outside, "missing-file.txt");
        File.CreateSymbolicLink(Path.Combine(root, "broken-file-link.txt"), brokenFileTarget);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "broken-file-link.txt")
        {
            DataStream = new MemoryStream([4, 5, 6]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));
        Check(!File.Exists(brokenFileTarget), "extraction must not create a file through a dangling symlink");

        File.Delete(archive);
        var brokenParentTarget = Path.Combine(outside, "missing-parent");
        Directory.CreateSymbolicLink(Path.Combine(root, "broken-parent"), brokenParentTarget);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "broken-parent/child/result.json")
        {
            DataStream = new MemoryStream([1]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, root));
        Check(!Directory.Exists(brokenParentTarget), "extraction must not create directories through a dangling symlink parent");

        File.Delete(archive);
        var linkedRoot = root + "-link";
        Directory.CreateSymbolicLink(linkedRoot, outside);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "result.json")
        {
            DataStream = new MemoryStream([9]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, linkedRoot));
        Check(!File.Exists(Path.Combine(outside, "result.json")), "a symlink extraction root must be rejected before writing");
        Directory.Delete(linkedRoot);

        File.Delete(archive);
        var brokenRootTarget = Path.Combine(outside, "missing-root");
        var brokenRoot = root + "-broken-link";
        Directory.CreateSymbolicLink(brokenRoot, brokenRootTarget);
        WriteTar(archive, new PaxTarEntry(TarEntryType.RegularFile, "result.json")
        {
            DataStream = new MemoryStream([8]),
        });
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, brokenRoot));
        Check(!Directory.Exists(brokenRootTarget), "extraction must not create a directory through a dangling symlink root");
        File.Delete(brokenRoot);
    }
    finally
    {
        File.Delete(archive);
        Directory.Delete(root, recursive: true);
        Directory.Delete(outside, recursive: true);
    }
}

static void PreserveUnixBackslashFilename()
{
    if (OperatingSystem.IsWindows())
    {
        return;
    }

    var root = Path.Combine(Path.GetTempPath(), $"vesper-backslash-{Guid.NewGuid():N}");
    var output = Path.Combine(Path.GetTempPath(), $"vesper-backslash-output-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);
    var backslashFile = Path.Combine(root, "foo\\bar.txt");
    var nestedDirectory = Path.Combine(root, "foo");
    Directory.CreateDirectory(nestedDirectory);
    var slashFile = Path.Combine(nestedDirectory, "bar.txt");
    File.WriteAllText(backslashFile, "literal backslash", System.Text.Encoding.UTF8);
    File.WriteAllText(slashFile, "path separator", System.Text.Encoding.UTF8);
    var archive = WorkspaceArchive.Create(root, output, configPath: null, includeGit: false);
    var destination = Path.Combine(Path.GetTempPath(), $"vesper-backslash-extract-{Guid.NewGuid():N}");
    try
    {
        using var stream = File.OpenRead(archive.ArchivePath);
        using var reader = new TarReader(stream);
        var names = new List<string>();
        while (reader.GetNextEntry(copyData: false) is { } entry)
        {
            names.Add(entry.Name);
        }
        Check(names.Contains("foo\\bar.txt", StringComparer.Ordinal), "a legal Unix backslash filename must remain a single tar path component");
        Check(names.Contains("foo/bar.txt", StringComparer.Ordinal), "a slash path must remain a nested tar path");
        WorkspaceArchive.Extract(archive.ArchivePath, destination);
        Check(File.ReadAllText(Path.Combine(destination, "foo\\bar.txt")) == "literal backslash", "literal backslash file must remain distinct after extraction");
        Check(File.ReadAllText(Path.Combine(destination, "foo", "bar.txt")) == "path separator", "slash path must remain distinct after extraction");
    }
    finally
    {
        File.Delete(archive.ArchivePath);
        File.Delete(backslashFile);
        File.Delete(slashFile);
        Directory.Delete(nestedDirectory);
        Directory.Delete(root, recursive: true);
        if (Directory.Exists(destination))
        {
            Directory.Delete(destination, recursive: true);
        }
    }
}

static void WriteTar(string archivePath, TarEntry entry)
{
    using var stream = WorkspaceArchive.CreatePrivateArchiveFile(archivePath);
    using var writer = new TarWriter(stream, TarEntryFormat.Pax);
    writer.WriteEntry(entry);
}

static void ExpectInvalidData(Action action)
{
    try
    {
        action();
        throw new InvalidOperationException("unsafe archive must be rejected");
    }
    catch (InvalidDataException)
    {
    }
}

static void DockerTargetPinning()
{
    Check(DockerClient.ResolveTargetArguments("debian", null, null).SequenceEqual(["--context", "debian"]), "the selected context should be pinned");
    Check(DockerClient.ResolveTargetArguments("debian", "debian", "tcp://ignored").SequenceEqual(["--context", "debian"]), "DOCKER_CONTEXT should take precedence over DOCKER_HOST");
    Check(DockerClient.ResolveTargetArguments("default", null, "tcp://127.0.0.1:2375").SequenceEqual(["--host", "tcp://127.0.0.1:2375"]), "explicit DOCKER_HOST should be pinned");
}

static void WorkspaceTransferLimitValidation()
{
    var root = Path.Combine(Path.GetTempPath(), $"vesper-limit-source-{Guid.NewGuid():N}");
    var output = Path.Combine(Path.GetTempPath(), $"vesper-limit-output-{Guid.NewGuid():N}");
    var archive = Path.Combine(Path.GetTempPath(), $"vesper-limit-{Guid.NewGuid():N}.tar");
    Directory.CreateDirectory(root);
    File.WriteAllBytes(Path.Combine(root, "one.bin"), [1, 2, 3, 4, 5]);
    File.WriteAllBytes(Path.Combine(root, "two.bin"), [1]);
    try
    {
        var byteLimit = new WorkspaceTransferLimits(4, 10, 10, 10, 10, 10);
        ExpectInvalidData(() => WorkspaceArchive.Measure(root, output, null, includeGit: false, byteLimit));
        var fileCountLimit = new WorkspaceTransferLimits(10, 1, 10, 10, 10, 10);
        ExpectInvalidData(() => WorkspaceArchive.Measure(root, output, null, includeGit: false, fileCountLimit));
        var entryCountLimit = new WorkspaceTransferLimits(10, 10, 10, 10, 10, 1);
        var directoryRoot = Path.Combine(root, "empty-tree");
        Directory.CreateDirectory(Path.Combine(directoryRoot, "empty-a", "empty-b"));
        ExpectInvalidData(() => WorkspaceArchive.Measure(directoryRoot, output, null, includeGit: false, entryCountLimit));
        Directory.Delete(directoryRoot, recursive: true);
        var singleFileLimit = new WorkspaceTransferLimits(10, 10, 4, 10, 10, 10);
        ExpectInvalidData(() => WorkspaceArchive.Measure(root, output, null, includeGit: false, singleFileLimit));

        using (var stream = WorkspaceArchive.CreatePrivateArchiveFile(archive))
        using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
        {
            writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "oversized.json")
            {
                DataStream = new MemoryStream([1, 2, 3, 4, 5]),
            });
        }
        var extractLimit = new WorkspaceTransferLimits(10, 10, 4, 10, 10, 10);
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, output, extractLimit));

        File.Delete(archive);
        using (var stream = WorkspaceArchive.CreatePrivateArchiveFile(archive))
        using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
        {
            writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "ignored-link") { LinkName = "target" });
            writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "dir/"));
        }
        ExpectInvalidData(() => WorkspaceArchive.Extract(archive, output, entryCountLimit));
    }
    finally
    {
        File.Delete(archive);
        Directory.Delete(root, recursive: true);
        if (Directory.Exists(output))
        {
            Directory.Delete(output, recursive: true);
        }
    }
}

static void PrivateArchivePermissions()
{
    var archive = Path.Combine(Path.GetTempPath(), $"vesper-private-{Guid.NewGuid():N}.tar");
    try
    {
        using (WorkspaceArchive.CreatePrivateArchiveFile(archive))
        {
        }
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(archive);
            Check(mode == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "temporary tar files must be mode 0600");
        }
    }
    finally
    {
        File.Delete(archive);
    }
}

static void SavedGateExitSemantics()
{
    Check(SecurityGateExitPolicy.FromStatus("passed") == 0, "passed gates should return zero");
    Check(SecurityGateExitPolicy.FromStatus("failed") == 1, "policy failures should return one");
    Check(SecurityGateExitPolicy.FromStatus("indeterminate") == 2, "indeterminate gates must not return zero");
    Check(SecurityGateExitPolicy.FromStatus("unknown") == 2, "unknown gate states must not return zero");
}

static void EmptyWorkspaceArchive()
{
    var root = Path.Combine(Path.GetTempPath(), $"vesper-empty-source-{Guid.NewGuid():N}");
    var output = Path.Combine(Path.GetTempPath(), $"vesper-empty-output-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);
    var archive = WorkspaceArchive.Create(root, output, configPath: null, includeGit: false);
    try
    {
        Check(new FileInfo(archive.ArchivePath).Length >= 512, "empty workspace must still produce a valid tar stream");
        WorkspaceArchive.Extract(archive.ArchivePath, output);
        Check(Directory.Exists(output), "empty tar should safely extract without creating files");
        Check(!Directory.EnumerateFiles(output, "*", SearchOption.AllDirectories).Any(), "empty workspace archive should contain no files");
    }
    finally
    {
        File.Delete(archive.ArchivePath);
        Directory.Delete(root, recursive: true);
        if (Directory.Exists(output))
        {
            Directory.Delete(output, recursive: true);
        }
    }
}

static DockerClient CreateStallingDockerClient(string fakeMode = "--test-fake-docker")
{
    var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Test process path is unavailable.");
    var prefixArguments = new List<string>();
    if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
    {
        prefixArguments.Add(Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException("Test assembly path is unavailable."));
    }
    prefixArguments.Add(fakeMode);
    return new DockerClient(executable, new DockerOperationTimeouts(
        TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250)), prefixArguments);
}

static void DockerControlTimeout()
{
    try
    {
        CreateStallingDockerClient().CaptureAsync(["version"], CancellationToken.None).GetAwaiter().GetResult();
        throw new InvalidOperationException("stalled control process should time out");
    }
    catch (DockerOperationTimeoutException)
    {
    }
}

static void DockerTransferTimeout()
{
    var archive = Path.Combine(Path.GetTempPath(), $"vesper-timeout-{Guid.NewGuid():N}.tar");
    File.WriteAllBytes(archive, [1, 2, 3]);
    var execution = ScanExecutionContext.Create("workspace", Path.GetTempPath(), useVolumes: true, hasConfig: false);
    try
    {
        CreateStallingDockerClient().UploadArchiveAsync(
            "helper", execution.SourceVolumeName!, "/workspace", archive,
            execution.HelperContainerName("timeout"), execution, "upload", CancellationToken.None)
            .GetAwaiter().GetResult();
        throw new InvalidOperationException("stalled transfer process should time out");
    }
    catch (DockerOperationTimeoutException)
    {
    }
    finally
    {
        File.Delete(archive);
    }
}

static void DockerDaemonDisconnectClassification()
{
    var result = CreateStallingDockerClient("--test-docker-disconnect")
        .CaptureAsync(["volume", "inspect", "vesper-test"], CancellationToken.None)
        .GetAwaiter().GetResult();
    Check(result.ExitCode == 125, "a disconnected Docker CLI must retain a non-zero command status");
    Check(result.StandardError.Contains("controlled disconnect", StringComparison.Ordinal), "Docker disconnect details should remain available to the caller");
    Check(ScannerExitPolicy.AfterExport(2, exportSucceeded: false) == 2, "a disconnect or failed export must never pass the gate");
}

static void DateGroupedOutputPaths()
{
    var outputRoot = Path.Combine(Path.GetTempPath(), "date-grouped-output");
    var projectPath = Path.Combine(Path.GetTempPath(), "same-second-project");
    var startedAt = new DateTimeOffset(2026, 10, 1, 13, 42, 18, TimeSpan.Zero);
    var firstId = Guid.Parse("a8f55dfc-a41a-4c28-9808-990706ef8a22");
    var secondId = Guid.Parse("b761bdc9-a41a-4c28-9808-990706ef8a22");
    var first = ScanExecutionContext.Create(projectPath, outputRoot, useVolumes: false, hasConfig: false, firstId, startedAt: startedAt);
    var second = ScanExecutionContext.Create(projectPath, outputRoot, useVolumes: false, hasConfig: false, secondId, startedAt: startedAt);
    var dateDirectory = Path.Combine(outputRoot, "2026-10-01");

    Check(first.StartedAt == startedAt && second.StartedAt == startedAt, "the context must retain its single UTC execution timestamp");
    Check(Path.GetDirectoryName(first.OutputPath) == dateDirectory, "execution date should be the primary result grouping");
    Check(Path.GetFileName(first.OutputPath) == $"13-42-18_{first.ShortId}", "result directory should include captured time and short scan ID");
    Check(Path.GetDirectoryName(second.OutputPath) == dateDirectory, "same-day executions should share the date directory");
    Check(Path.GetFileName(second.OutputPath) == $"13-42-18_{second.ShortId}", "same-second executions should retain distinct short IDs");
    Check(first.OutputPath != second.OutputPath, "different full scan IDs must not collide within the same second");
    Check(first.ScanIdText == firstId.ToString("D"), "the full scan ID remains the authoritative identity");
}

static void LegacyAndDateGroupedReportLookup()
{
    var root = Path.Combine(Path.GetTempPath(), $"vesper-report-layout-{Guid.NewGuid():N}");
    var legacy = Path.Combine(root, "a8f55dfca41a4c28980990706ef8a22");
    var dateGrouped = Path.Combine(root, "2026-10-01", "13-42-18_b761bdc9");
    Directory.CreateDirectory(legacy);
    Directory.CreateDirectory(dateGrouped);
    try
    {
        File.WriteAllText(Path.Combine(legacy, "summary.json"), "{}", System.Text.Encoding.UTF8);
        File.WriteAllText(Path.Combine(legacy, "scan.json"), "{\"startedAt\":\"2026-10-01T12:00:00+00:00\"}", System.Text.Encoding.UTF8);
        File.WriteAllText(Path.Combine(dateGrouped, "summary.json"), "{}", System.Text.Encoding.UTF8);
        File.WriteAllText(Path.Combine(dateGrouped, "scan.json"), "{\"startedAt\":\"2026-10-01T13:42:18+00:00\"}", System.Text.Encoding.UTF8);

        Check(ScanReportLocator.FindLatest(root) == dateGrouped, "report lookup should select the latest metadata timestamp across legacy and date-grouped layouts");
        Check(ScanReportLocator.FindLatest(legacy) == legacy, "an explicit legacy scan directory should remain readable");
        Check(ScanReportLocator.FindLatest(Path.GetDirectoryName(dateGrouped)!) == dateGrouped, "a date directory should resolve to its latest scan");
    }
    finally
    {
        Directory.Delete(root, recursive: true);
    }
}
namespace Vesper.Cli;

public sealed record LaunchOptions(
    string Workspace,
    string? Output,
    WorkspaceMode WorkspaceMode,
    bool IncludeGit,
    bool KeepVolumes,
    bool Verbose,
    string Image,
    string? ConfigPath,
    ScanResourceLimits ResourceLimits);

public sealed class ScanLauncher(LaunchOptions options, DockerClient? dockerClient = null)
{
    private readonly DockerClient docker = dockerClient ?? new DockerClient();

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var workspace = Path.GetFullPath(options.Workspace);
        if (!Directory.Exists(workspace))
        {
            throw new DirectoryNotFoundException($"Workspace does not exist: {workspace}");
        }

        var outputRoot = options.Output is null
            ? Path.Combine(workspace, "security-results")
            : Path.GetFullPath(options.Output);
        if (string.Equals(workspace.TrimEnd(Path.DirectorySeparatorChar), outputRoot.TrimEnd(Path.DirectorySeparatorChar),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new ArgumentException("The output base directory cannot be the workspace root.");
        }

        string? configPath = null;
        if (options.ConfigPath is not null)
        {
            configPath = Path.GetFullPath(options.ConfigPath);
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException($"Configuration file was not found: {configPath}");
            }
        }

        var environment = await DockerEnvironmentDetector.DetectAsync(docker, cancellationToken);
        var mode = WorkspaceModeResolver.Resolve(options.WorkspaceMode, environment.IsRemote, environment.Endpoint, workspace);
        var execution = ScanExecutionContext.Create(workspace, outputRoot, mode == WorkspaceMode.Volume, configPath is not null);
        Directory.CreateDirectory(execution.OutputPath);
        var stats = WorkspaceArchive.Measure(workspace, execution.OutputRootPath, configPath, options.IncludeGit);

        Console.WriteLine("Vesper Security Scan");
        Console.WriteLine($"Docker context: {environment.Context}");
        Console.WriteLine($"Docker endpoint: {environment.Endpoint}");
        Console.WriteLine($"Workspace mode: {mode.ToString().ToLowerInvariant()}");
        Console.WriteLine("Preparing source...");
        Console.WriteLine($"  {stats.FileCount} files");
        Console.WriteLine($"  {stats.Bytes / 1_000_000d:F1} MB");
        if (options.Verbose)
        {
            Console.WriteLine($"Scan ID: {execution.ScanIdText}");
            Console.WriteLine($"Project: {execution.ProjectName}");
            Console.WriteLine($"Container: {execution.ContainerName}");
            if (execution.SourceVolumeName is not null)
            {
                Console.WriteLine($"Source volume: {execution.SourceVolumeName}");
                Console.WriteLine($"Output volume: {execution.OutputVolumeName}");
            }
            Console.WriteLine($"CPU: {options.ResourceLimits.Cpus}");
            Console.WriteLine($"Memory: {options.ResourceLimits.Memory}");
            Console.WriteLine($"PIDs: {options.ResourceLimits.PidsLimit}");
            Console.WriteLine($"Workspace: {workspace}");
            Console.WriteLine($"Output: {execution.OutputPath}");
        }

        if (mode == WorkspaceMode.Bind)
        {
            return await RunWithBindMountsAsync(execution, configPath, cancellationToken);
        }

        return await RunWithVolumesAsync(execution, configPath, cancellationToken);
    }

    private async Task<int> RunWithBindMountsAsync(ScanExecutionContext execution, string? configPath, CancellationToken cancellationToken)
    {
        var arguments = ScannerRunArguments(execution);
        arguments.Add("--mount");
        arguments.Add(DockerMountArguments.Bind(execution.SourcePath, "/workspace", readOnly: true));
        arguments.Add("--mount");
        arguments.Add(DockerMountArguments.Bind(execution.OutputPath, "/output"));
        if (configPath is not null)
        {
            arguments.Add("--mount");
            arguments.Add(DockerMountArguments.Bind(configPath, "/config/security.yaml", readOnly: true));
        }

        arguments.Add(options.Image);
        Console.WriteLine("Running security scan...");
        try
        {
            var exitCode = await docker.RunInheritedAsync(arguments, cancellationToken);
            PrintOutcome(exitCode, execution.OutputPath);
            return ScannerExitPolicy.AfterExport(exitCode, exportSucceeded: true);
        }
        finally
        {
            await RemoveContainerQuietlyAsync(execution.ContainerName, execution);
        }
    }

    private async Task<int> RunWithVolumesAsync(ScanExecutionContext execution, string? configPath, CancellationToken cancellationToken)
    {
        var sourceVolume = execution.SourceVolumeName!;
        var outputVolume = execution.OutputVolumeName!;
        var configVolume = execution.ConfigVolumeName;
        var helperContainers = new List<string>();
        var archivePaths = new List<string>();
        int? scannerExitCode = null;
        var exportSucceeded = false;

        try
        {
            var workspaceArchive = WorkspaceArchive.Create(execution.SourcePath, execution.OutputRootPath, configPath, options.IncludeGit);
            archivePaths.Add(workspaceArchive.ArchivePath);
            await CreateVolumeAsync(sourceVolume, execution, "source", cancellationToken);
            await CreateVolumeAsync(outputVolume, execution, "output", cancellationToken);

            Console.WriteLine("Uploading workspace...");
            var uploadName = execution.HelperContainerName("upload");
            helperContainers.Add(uploadName);
            await docker.UploadArchiveAsync(LauncherImages.ArchiveHelper, sourceVolume, "/workspace", workspaceArchive.ArchivePath, uploadName, execution, "upload", cancellationToken);
            Console.WriteLine("  completed");

            if (configPath is not null && configVolume is not null)
            {
                await CreateVolumeAsync(configVolume, execution, "config", cancellationToken);
                var configArchive = WorkspaceArchive.CreateSingleFile(configPath, "security.yaml");
                archivePaths.Add(configArchive);
                var configUploadName = execution.HelperContainerName("config-upload");
                helperContainers.Add(configUploadName);
                await docker.UploadArchiveAsync(LauncherImages.ArchiveHelper, configVolume, "/security-config", configArchive, configUploadName, execution, "config-upload", cancellationToken);
            }

            var scanArguments = ScannerRunArguments(execution);
            scanArguments.Add("--mount");
            scanArguments.Add(DockerMountArguments.Volume(sourceVolume, "/workspace", readOnly: true));
            scanArguments.Add("--mount");
            scanArguments.Add(DockerMountArguments.Volume(outputVolume, "/output"));
            if (configVolume is not null)
            {
                scanArguments.Add("--mount");
                scanArguments.Add(DockerMountArguments.Volume(configVolume, "/security-config", readOnly: true));
            }
            scanArguments.Add(options.Image);
            if (configVolume is not null)
            {
                scanArguments.Add("--config");
                scanArguments.Add("/security-config/security.yaml");
            }

            Console.WriteLine("Running security scan...");
            scannerExitCode = await docker.RunInheritedAsync(scanArguments, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Scan interrupted. Attempting to export partial results and clean up.");
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"[launcher] {exception.Message}");
        }
        finally
        {
            await RemoveContainerQuietlyAsync(execution.ContainerName, execution);
            foreach (var helper in helperContainers)
            {
                await RemoveContainerQuietlyAsync(helper, execution);
            }

            if (await IsOwnedVolumeAsync(outputVolume, execution))
            {
                try
                {
                    Console.WriteLine("Downloading results...");
                    var exportArchive = Path.Combine(Path.GetTempPath(), $"securityscan-export-{Guid.NewGuid():N}.tar");
                    archivePaths.Add(exportArchive);
                    var exportName = execution.HelperContainerName("download");
                    helperContainers.Add(exportName);
                    await docker.DownloadArchiveAsync(LauncherImages.ArchiveHelper, outputVolume, "/output", exportArchive, exportName, execution, "download", CancellationToken.None);
                    WorkspaceArchive.Extract(exportArchive, execution.OutputPath);
                    exportSucceeded = true;
                    Console.WriteLine($"  {DisplayPath(execution.OutputPath)}");
                }
                catch (Exception exception)
                {
                    Console.Error.WriteLine($"[launcher] Result export failed: {exception.Message}");
                }
            }

            foreach (var helper in helperContainers)
            {
                await RemoveContainerQuietlyAsync(helper, execution);
            }

            if (!options.KeepVolumes)
            {
                Console.WriteLine("Cleaning temporary volumes...");
            }
            await CleanupVolumesAsync(execution);
            foreach (var archivePath in archivePaths)
            {
                TryDelete(archivePath);
            }
        }

        if (scannerExitCode is null)
        {
            Console.Error.WriteLine("Runner could not complete the scan.");
            return 2;
        }

        PrintOutcome(scannerExitCode.Value, execution.OutputPath);
        return ScannerExitPolicy.AfterExport(scannerExitCode.Value, exportSucceeded);
    }

    private async Task CreateVolumeAsync(string name, ScanExecutionContext execution, string resource, CancellationToken cancellationToken)
    {
        var arguments = new List<string> { "volume", "create" };
        arguments.AddRange(execution.Labels(resource));
        arguments.Add(name);
        var result = await docker.CaptureAsync(arguments, cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new DockerCommandException($"Unable to create temporary Docker volume '{name}'.", result.ExitCode);
        }

        if (!await IsOwnedVolumeAsync(name, execution))
        {
            throw new DockerCommandException($"Docker volume name collision for '{name}'; the existing volume is not owned by scan {execution.ScanIdText}.", 1);
        }
    }

    private async Task CleanupVolumesAsync(ScanExecutionContext execution)
    {
        var volumes = new[]
        {
            execution.SourceVolumeName,
            execution.OutputVolumeName,
            execution.ConfigVolumeName,
        }.Where(name => name is not null).Cast<string>().ToArray();

        var ownedVolumes = new List<string>();
        foreach (var volume in volumes)
        {
            if (await IsOwnedVolumeAsync(volume, execution))
            {
                ownedVolumes.Add(volume);
            }
        }

        if (options.KeepVolumes)
        {
            Console.WriteLine("Keeping temporary volumes:");
            foreach (var volume in ownedVolumes)
            {
                Console.WriteLine($"  {volume}");
            }
            return;
        }

        foreach (var volume in TemporaryVolumeCleanup.VolumesToRemove(ownedVolumes, keepVolumes: false))
        {
            try
            {
                var result = await docker.CaptureAsync(["volume", "rm", "--force", volume], CancellationToken.None);
                if (result.ExitCode != 0)
                {
                    Console.Error.WriteLine($"[launcher] Could not remove temporary volume '{volume}'. Check it manually.");
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"[launcher] Could not remove temporary volume '{volume}': {exception.Message}");
            }
        }
    }

    private async Task<bool> IsOwnedVolumeAsync(string name, ScanExecutionContext execution)
    {
        try
        {
            var result = await docker.CaptureAsync(
                ["volume", "inspect", name, "--format", "{{ index .Labels \"securityscan.managed\" }}|{{ index .Labels \"securityscan.scan-id\" }}"],
                CancellationToken.None);
            return result.ExitCode == 0 && execution.OwnsResourceLabels(result.StandardOutput);
        }
        catch
        {
            return false;
        }
    }

    private async Task RemoveContainerQuietlyAsync(string name, ScanExecutionContext execution)
    {
        try
        {
            var inspection = await docker.CaptureAsync(
                ["container", "inspect", name, "--format", "{{ index .Config.Labels \"securityscan.managed\" }}|{{ index .Config.Labels \"securityscan.scan-id\" }}"],
                CancellationToken.None);
            if (inspection.ExitCode != 0 || !execution.OwnsResourceLabels(inspection.StandardOutput))
            {
                return;
            }
            await docker.CaptureAsync(["rm", "--force", name], CancellationToken.None);
        }
        catch
        {
        }
    }

    private List<string> ScannerRunArguments(ScanExecutionContext execution)
    {
        var arguments = new List<string>
        {
            "run", "--rm", "--name", execution.ContainerName,
        };
        arguments.AddRange(execution.Labels("runner"));
        arguments.AddRange([
            "--env", $"SECURITY_SCAN_ID={execution.ScanIdText}",
            "--read-only", "--tmpfs", "/tmp",
            "--security-opt=no-new-privileges", "--cap-drop=ALL",
            $"--cpus={options.ResourceLimits.Cpus}",
            $"--memory={options.ResourceLimits.Memory}",
            $"--pids-limit={options.ResourceLimits.PidsLimit}",
        ]);
        if (!string.IsNullOrWhiteSpace(execution.OutputExclusionPath))
        {
            arguments.Add("--env");
            arguments.Add($"SECURITY_SCAN_OUTPUT_RELATIVE_PATH={execution.OutputExclusionPath}");
        }
        return arguments;
    }

    private static void PrintOutcome(int exitCode, string output)
    {
        if (exitCode == 0)
        {
            Console.WriteLine("Scan completed. Security gate passed.");
        }
        else if (exitCode == 1)
        {
            Console.WriteLine("Scan completed. Security gate failed.");
        }
        else
        {
            Console.WriteLine($"Runner did not complete successfully (exit code {exitCode}).");
        }

        Console.WriteLine($"Results: {DisplayPath(output)}");
    }

    private static string DisplayPath(string path)
    {
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, path);
        return Path.IsPathRooted(relative) || relative.StartsWith("..", StringComparison.Ordinal)
            ? path
            : $"./{relative.Replace('\\', '/')}";
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
        }
    }
}
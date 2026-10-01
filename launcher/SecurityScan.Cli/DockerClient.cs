using System.Diagnostics;

namespace Vesper.Cli;

public sealed record DockerCommandResult(int ExitCode, string StandardOutput, string StandardError);

public sealed class DockerCommandException(string message, int exitCode) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

public sealed class DockerOperationTimeoutException(string message) : TimeoutException(message);

public sealed record DockerOperationTimeouts(TimeSpan Control, TimeSpan Transfer, TimeSpan Runner)
{
    public static DockerOperationTimeouts Default { get; } = new(
        TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(15), TimeSpan.FromHours(1));
}

public sealed class DockerClient
{
    private readonly string executable;
    private readonly DockerOperationTimeouts operationTimeouts;
    private readonly IReadOnlyList<string> prefixArguments;
    private string[] targetArguments = [];

    public DockerClient(
        string executable = "docker",
        DockerOperationTimeouts? operationTimeouts = null,
        IReadOnlyList<string>? prefixArguments = null)
    {
        this.executable = executable;
        this.operationTimeouts = operationTimeouts ?? DockerOperationTimeouts.Default;
        this.prefixArguments = prefixArguments ?? [];
        if (this.operationTimeouts.Control <= TimeSpan.Zero
            || this.operationTimeouts.Transfer <= TimeSpan.Zero
            || this.operationTimeouts.Runner <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeouts), "Docker operation timeouts must be positive.");
        }
    }

    public void PinTarget(string context, string? contextOverride, string? hostOverride)
    {
        targetArguments = ResolveTargetArguments(context, contextOverride, hostOverride).ToArray();
    }

    public static IReadOnlyList<string> ResolveTargetArguments(string context, string? contextOverride, string? hostOverride)
    {
        if (!string.IsNullOrWhiteSpace(contextOverride))
        {
            return ["--context", context];
        }
        if (!string.IsNullOrWhiteSpace(hostOverride))
        {
            return ["--host", hostOverride];
        }
        return ["--context", context];
    }

    public async Task<DockerCommandResult> CaptureAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        using var process = Start(arguments, redirectInput: false, redirectOutput: true, redirectError: true);
        using var timeout = CreateOperationToken(cancellationToken, operationTimeouts.Control);
        var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            await IgnoreCancellationAsync(stdoutTask, stderrTask);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            throw new DockerOperationTimeoutException($"Docker control command exceeded {operationTimeouts.Control.TotalSeconds:g} seconds.");
        }

        return new DockerCommandResult(process.ExitCode, await stdoutTask, await stderrTask);
    }

    public async Task<int> RunInheritedAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        using var process = Start(arguments, redirectInput: false, redirectOutput: true, redirectError: true);
        using var timeout = CreateOperationToken(cancellationToken, operationTimeouts.Runner);
        var stdoutTask = ForwardLinesAsync(process.StandardOutput, Console.Out, timeout.Token);
        var stderrTask = ForwardLinesAsync(process.StandardError, Console.Error, timeout.Token);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            await Task.WhenAll(stdoutTask, stderrTask);
            return process.ExitCode;
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            await IgnoreCancellationAsync(stdoutTask, stderrTask);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            throw new DockerOperationTimeoutException($"Docker runner command exceeded {operationTimeouts.Runner.TotalSeconds:g} seconds.");
        }
    }

    public async Task UploadArchiveAsync(
        string image,
        string volume,
        string targetDirectory,
        string archivePath,
        string containerName,
        ScanExecutionContext execution,
        string resource,
        CancellationToken cancellationToken)
    {
        var args = new List<string> { "run", "--rm", "--name", containerName };
        args.AddRange(execution.Labels(resource));
        args.AddRange([
            "-i", "--user", "0:0",
            "--read-only", "--tmpfs", "/tmp:size=64m,noexec,nosuid,nodev",
            "--security-opt=no-new-privileges", "--cap-drop=ALL", "--network=none",
            "--cpus=1", "--memory=128m", "--pids-limit=128",
            "--mount", DockerMountArguments.Volume(volume, targetDirectory),
            "--entrypoint", "tar", image, "-x", "-f", "-", "-C", targetDirectory,
        ]);

        using var process = Start(args, redirectInput: true, redirectOutput: false, redirectError: true);
        using var timeout = CreateOperationToken(cancellationToken, operationTimeouts.Transfer);
        var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            await using var archive = File.OpenRead(archivePath);
            await archive.CopyToAsync(process.StandardInput.BaseStream, timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.StandardInput.Close();
            Kill(process);
            await IgnoreCancellationAsync(stderrTask);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            throw new DockerOperationTimeoutException($"Docker workspace upload exceeded {operationTimeouts.Transfer.TotalSeconds:g} seconds.");
        }
        catch
        {
            process.StandardInput.Close();
            Kill(process);
            throw;
        }

        var stderr = await stderrTask;
        if (process.ExitCode != 0)
        {
            throw new DockerCommandException($"Docker volume upload failed: {Tail(stderr)}", process.ExitCode);
        }
    }

    public async Task DownloadArchiveAsync(
        string image,
        string volume,
        string sourceDirectory,
        string archivePath,
        string containerName,
        ScanExecutionContext execution,
        string resource,
        long maxArchiveBytes,
        CancellationToken cancellationToken)
    {
        var args = new List<string> { "run", "--rm", "--name", containerName };
        args.AddRange(execution.Labels(resource));
        args.AddRange([
            "--user", "1000:1000",
            "--read-only", "--tmpfs", "/tmp:size=64m,noexec,nosuid,nodev",
            "--security-opt=no-new-privileges", "--cap-drop=ALL", "--network=none",
            "--cpus=1", "--memory=128m", "--pids-limit=128",
            "--mount", DockerMountArguments.Volume(volume, sourceDirectory, readOnly: true),
            "--entrypoint", "tar", image, "-c", "-f", "-", "-C", sourceDirectory, ".",
        ]);

        using var process = Start(args, redirectInput: false, redirectOutput: true, redirectError: true);
        using var timeout = CreateOperationToken(cancellationToken, operationTimeouts.Transfer);
        var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            await using var archive = WorkspaceArchive.CreatePrivateArchiveFile(archivePath);
            await CopyToLimitAsync(process.StandardOutput.BaseStream, archive, maxArchiveBytes, timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            await IgnoreCancellationAsync(stderrTask);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            throw new DockerOperationTimeoutException($"Docker result download exceeded {operationTimeouts.Transfer.TotalSeconds:g} seconds.");
        }
        catch
        {
            Kill(process);
            throw;
        }

        var stderr = await stderrTask;
        if (process.ExitCode != 0)
        {
            throw new DockerCommandException($"Docker volume download failed: {Tail(stderr)}", process.ExitCode);
        }
    }

    private Process Start(IReadOnlyList<string> arguments, bool redirectInput, bool redirectOutput, bool redirectError)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardInput = redirectInput,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = redirectError,
            CreateNoWindow = true,
        };
        foreach (var prefixArgument in prefixArguments)
        {
            startInfo.ArgumentList.Add(prefixArgument);
        }
        foreach (var targetArgument in targetArguments)
        {
            startInfo.ArgumentList.Add(targetArgument);
        }
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("Docker CLI did not start.");
            }
        }
        catch
        {
            process.Dispose();
            throw;
        }

        return process;
    }

    private static void Kill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static CancellationTokenSource CreateOperationToken(CancellationToken cancellationToken, TimeSpan timeout)
    {
        var tokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        tokenSource.CancelAfter(timeout);
        return tokenSource;
    }

    private static async Task IgnoreCancellationAsync(params Task[] tasks)
    {
        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }
    }

    private static string Tail(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length <= 400 ? trimmed : trimmed[^400..];
    }

    private static async Task ForwardLinesAsync(StreamReader reader, TextWriter writer, CancellationToken cancellationToken)
    {
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            await writer.WriteLineAsync(line);
        }
    }

    private static async Task CopyToLimitAsync(Stream source, Stream destination, long maximumBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long totalBytes = 0;
        int bytesRead;
        while ((bytesRead = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            if (bytesRead > maximumBytes - totalBytes)
            {
                throw new InvalidDataException("Docker result archive exceeds the derived archive metadata limit.");
            }
            await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
            totalBytes += bytesRead;
        }
    }
}
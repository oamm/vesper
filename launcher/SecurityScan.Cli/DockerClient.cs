using System.Diagnostics;

namespace Vesper.Cli;

public sealed record DockerCommandResult(int ExitCode, string StandardOutput, string StandardError);

public sealed class DockerCommandException(string message, int exitCode) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

public sealed class DockerClient(string executable = "docker")
{
    public async Task<DockerCommandResult> CaptureAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        using var process = Start(arguments, redirectInput: false, redirectOutput: true, redirectError: true);
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            throw;
        }

        return new DockerCommandResult(process.ExitCode, await stdoutTask, await stderrTask);
    }

    public async Task<int> RunInheritedAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        using var process = Start(arguments, redirectInput: false, redirectOutput: true, redirectError: true);
        var stdoutTask = ForwardLinesAsync(process.StandardOutput, Console.Out, cancellationToken);
        var stderrTask = ForwardLinesAsync(process.StandardError, Console.Error, cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdoutTask, stderrTask);
            return process.ExitCode;
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            try
            {
                await Task.WhenAll(stdoutTask, stderrTask);
            }
            catch
            {
            }
            throw;
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
            "--mount", DockerMountArguments.Volume(volume, targetDirectory),
            "--entrypoint", "tar", image, "-x", "-f", "-", "-C", targetDirectory,
        ]);

        using var process = Start(args, redirectInput: true, redirectOutput: false, redirectError: true);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await using var archive = File.OpenRead(archivePath);
            await archive.CopyToAsync(process.StandardInput.BaseStream, cancellationToken);
            process.StandardInput.Close();
            await process.WaitForExitAsync(cancellationToken);
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
        CancellationToken cancellationToken)
    {
        var args = new List<string> { "run", "--rm", "--name", containerName };
        args.AddRange(execution.Labels(resource));
        args.AddRange([
            "--user", "0:0",
            "--mount", DockerMountArguments.Volume(volume, sourceDirectory, readOnly: true),
            "--entrypoint", "tar", image, "-c", "-f", "-", "-C", sourceDirectory, ".",
        ]);

        using var process = Start(args, redirectInput: false, redirectOutput: true, redirectError: true);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await using var archive = File.Create(archivePath);
            await process.StandardOutput.BaseStream.CopyToAsync(archive, cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
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
}
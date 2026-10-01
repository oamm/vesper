using System.Net;
using System.Text.Json;

namespace Vesper.Cli;

public enum WorkspaceMode
{
    Auto,
    Bind,
    Volume
}

public sealed record DockerEnvironmentInfo(string Context, string Endpoint, bool IsRemote);

public sealed class WorkspaceModeException(string message) : InvalidOperationException(message);

public static class DockerEndpointClassifier
{
    public static bool IsRemote(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return true;
        }

        if (endpoint.StartsWith("npipe://", StringComparison.OrdinalIgnoreCase)
            || endpoint.StartsWith("unix://", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            return true;
        }

        if (uri.Scheme.Equals("ssh", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (uri.Scheme.Equals("tcp", StringComparison.OrdinalIgnoreCase)
            || uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
            || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return !IsLoopback(uri.Host);
        }

        return true;
    }

    private static bool IsLoopback(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
    }
}

public static class WorkspaceModeResolver
{
    public static WorkspaceMode Resolve(WorkspaceMode requested, bool daemonIsRemote, string? endpoint = null, string? workspace = null)
    {
        if (requested == WorkspaceMode.Bind && daemonIsRemote)
        {
            throw new WorkspaceModeException(
                $"Bind mode cannot access local path:\n\n{workspace ?? "<workspace>"}\n\nbecause the active Docker daemon is remote:\n\n{endpoint ?? "<remote endpoint>"}\n\nUse --workspace-mode volume or switch to a local Docker context.");
        }

        return requested == WorkspaceMode.Auto
            ? daemonIsRemote ? WorkspaceMode.Volume : WorkspaceMode.Bind
            : requested;
    }
}

public static class ScannerExitPolicy
{
    public static int AfterExport(int scannerExitCode, bool exportSucceeded)
    {
        if (!exportSucceeded || scannerExitCode is < 0 or > 4)
        {
            return 2;
        }

        return scannerExitCode;
    }
}

public static class TemporaryVolumeCleanup
{
    public static IReadOnlyList<string> VolumesToRemove(IEnumerable<string> volumes, bool keepVolumes)
    {
        return keepVolumes ? [] : volumes.Where(name => !string.IsNullOrWhiteSpace(name)).ToArray();
    }
}

public static class DockerEnvironmentDetector
{
    public static async Task<DockerEnvironmentInfo> DetectAsync(DockerClient docker, CancellationToken cancellationToken)
    {
        var contextResult = await docker.CaptureAsync(["context", "show"], cancellationToken);
        if (contextResult.ExitCode != 0)
        {
            throw new DockerCommandException("Unable to determine the active Docker context.", contextResult.ExitCode);
        }

        var context = contextResult.StandardOutput.Trim();
        var endpoint = string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DOCKER_CONTEXT"))
            ? Environment.GetEnvironmentVariable("DOCKER_HOST")
            : null;
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            var inspect = await docker.CaptureAsync(["context", "inspect", context], cancellationToken);
            if (inspect.ExitCode != 0)
            {
                throw new DockerCommandException("Unable to inspect the active Docker context endpoint.", inspect.ExitCode);
            }

            using var document = JsonDocument.Parse(inspect.StandardOutput);
            var root = document.RootElement;
            var contextElement = root.ValueKind == JsonValueKind.Array ? root[0] : root;
            endpoint = contextElement.GetProperty("Endpoints").GetProperty("docker").GetProperty("Host").GetString();
        }

        endpoint ??= "unknown";
        return new DockerEnvironmentInfo(context, endpoint, DockerEndpointClassifier.IsRemote(endpoint));
    }
}
using System.Diagnostics;

namespace Vesper.Cli;

internal sealed record RepositoryMetadata(string? Commit, string? Branch, string? Dirty)
{
    public static RepositoryMetadata Empty { get; } = new(null, null, null);

    public IReadOnlyDictionary<string, string> EnvironmentValues => new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["SECURITY_SCAN_REPOSITORY_COMMIT"] = Commit ?? "",
        ["SECURITY_SCAN_REPOSITORY_BRANCH"] = Branch ?? "",
        ["SECURITY_SCAN_REPOSITORY_DIRTY"] = Dirty ?? "",
    };

    public static RepositoryMetadata Capture(string workspace)
    {
        if (Run(workspace, ["rev-parse", "--is-inside-work-tree"]) != "true")
        {
            return Empty;
        }

        var commit = Run(workspace, ["rev-parse", "HEAD"]);
        var branch = Run(workspace, ["symbolic-ref", "--quiet", "--short", "HEAD"]);
        var dirty = Run(workspace, ["status", "--porcelain"]);
        return new RepositoryMetadata(
            string.IsNullOrWhiteSpace(commit) ? null : commit,
            string.IsNullOrWhiteSpace(branch) ? null : branch,
            dirty is null ? null : (dirty.Length == 0 ? "false" : "true"));
    }

    private static string? Run(string workspace, IReadOnlyList<string> arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo("git")
            {
                WorkingDirectory = workspace,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }
            using var process = Process.Start(startInfo);
            if (process is null || !process.WaitForExit(2000))
            {
                try { process?.Kill(entireProcessTree: true); } catch { }
                return null;
            }
            return process.ExitCode == 0 ? process.StandardOutput.ReadToEnd().Trim() : null;
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}

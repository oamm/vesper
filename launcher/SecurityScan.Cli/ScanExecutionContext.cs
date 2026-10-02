using System.Globalization;

namespace Vesper.Cli;

public sealed record ScanExecutionContext(
    Guid ScanId,
    DateTimeOffset StartedAt,
    string DockerContext,
    string SourcePath,
    string OutputRootPath,
    string OutputPath,
    string? OutputExclusionPath,
    string ContainerName,
    string ProjectName,
    string? SourceVolumeName,
    string? OutputVolumeName,
    string? ConfigVolumeName)
{
    public string ScanIdText => ScanId.ToString("D");
    public string ShortId => ScanId.ToString("N")[..12];
    public string StartedAtText => StartedAt.ToString("O", CultureInfo.InvariantCulture);

    public static ScanExecutionContext Create(
        string sourcePath,
        string outputRootPath,
        bool useVolumes,
        bool hasConfig,
        Guid? scanId = null,
        string dockerContext = "default",
        DateTimeOffset? startedAt = null)
    {
        var id = scanId ?? Guid.NewGuid();
        var executionStartedAt = (startedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var shortId = id.ToString("N")[..12];
        var projectName = SanitizeProjectName(Path.GetFileName(Path.TrimEndingDirectorySeparator(sourcePath)));
        var sourceFullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourcePath));
        var outputFullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outputRootPath));
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var sourcePrefix = sourceFullPath + Path.DirectorySeparatorChar;
        var outputExclusion = outputFullPath.StartsWith(sourcePrefix, comparison)
            ? Path.GetRelativePath(sourceFullPath, outputFullPath).Replace('\\', '/')
            : null;
        var dateDirectory = executionStartedAt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var timeDirectory = $"{executionStartedAt.ToString("HH-mm-ss", CultureInfo.InvariantCulture)}_{shortId}";
        return new ScanExecutionContext(
            id,
            executionStartedAt,
            dockerContext,
            sourceFullPath,
            outputFullPath,
            Path.Combine(outputFullPath, dateDirectory, timeDirectory),
            outputExclusion,
            $"vesper-{shortId}",
            projectName,
            useVolumes ? $"vesper-source-{shortId}" : null,
            useVolumes ? $"vesper-output-{shortId}" : null,
            useVolumes && hasConfig ? $"vesper-config-{shortId}" : null);
    }

    public string HelperContainerName(string resource)
    {
        return $"vesper-{resource}-{ShortId}";
    }

    public IReadOnlyList<string> Labels(string resource)
    {
        return [
            "--label", "securityscan.managed=true",
            "--label", $"securityscan.scan-id={ScanIdText}",
            "--label", $"securityscan.resource={resource}",
            "--label", $"securityscan.project={ProjectName}",
        ];
    }

    public bool OwnsResourceLabels(string? labels)
    {
        var parts = labels?.Trim().Split('|');
        return parts is { Length: 2 }
            && string.Equals(parts[0], "true", StringComparison.Ordinal)
            && string.Equals(parts[1], ScanIdText, StringComparison.OrdinalIgnoreCase);
    }

    private static string SanitizeProjectName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "workspace";
        }

        var sanitized = new string(value.Select(character =>
            char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-'
                ? character
                : '-').ToArray()).Trim('-');
        return sanitized.Length == 0 ? "workspace" : sanitized[..Math.Min(sanitized.Length, 63)];
    }
}
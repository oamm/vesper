using System.Globalization;

namespace Vesper.Cli;

public sealed record WorkspaceTransferLimits(
    long MaxWorkspaceBytes,
    int MaxFiles,
    long MaxFileBytes,
    long MaxOutputBytes,
    int MaxOutputFiles,
    int MaxEntries)
{
    public static WorkspaceTransferLimits Default { get; } = new(
        20L * 1024 * 1024 * 1024,
        500_000,
        2L * 1024 * 1024 * 1024,
        4L * 1024 * 1024 * 1024,
        100_000,
        600_000);

    public long MaxWorkspaceArchiveBytes => ArchiveCeiling(MaxWorkspaceBytes, MaxEntries);
    public long MaxOutputArchiveBytes => ArchiveCeiling(MaxOutputBytes, MaxEntries);

    public static WorkspaceTransferLimits Parse(
        string maxWorkspaceBytes,
        string maxFiles,
        string maxFileBytes,
        string maxOutputBytes,
        string maxOutputFiles,
        string maxEntries)
    {
        var limits = new WorkspaceTransferLimits(
            ParsePositiveLong(maxWorkspaceBytes, "--max-workspace-bytes"),
            ParsePositiveInt(maxFiles, "--max-files"),
            ParsePositiveLong(maxFileBytes, "--max-file-bytes"),
            ParsePositiveLong(maxOutputBytes, "--max-output-bytes"),
            ParsePositiveInt(maxOutputFiles, "--max-output-files"),
            ParsePositiveInt(maxEntries, "--max-entries"));
        if (limits.MaxFileBytes > limits.MaxWorkspaceBytes || limits.MaxFileBytes > limits.MaxOutputBytes)
        {
            throw new ArgumentException("Per-file byte limits cannot exceed workspace/output byte limits.");
        }
        return limits;
    }

    private static long ParsePositiveLong(string value, string option)
    {
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed < 1)
        {
            throw new ArgumentException($"{option} must be a positive byte count.");
        }
        return parsed;
    }

    private static int ParsePositiveInt(string value, string option)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed < 1)
        {
            throw new ArgumentException($"{option} must be a positive integer.");
        }
        return parsed;
    }

    private static long ArchiveCeiling(long contentBytes, int entries)
    {
        const long tarEndMarkersAndBlockPadding = 10_240;
        const long maximumMetadataPerEntry = 4_096;
        var metadataBytes = (long)entries * maximumMetadataPerEntry;
        if (contentBytes > long.MaxValue - metadataBytes - tarEndMarkersAndBlockPadding)
        {
            return long.MaxValue;
        }
        return contentBytes + metadataBytes + tarEndMarkersAndBlockPadding;
    }
}
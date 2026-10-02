using System.Globalization;
using System.Text.Json;

namespace Vesper.Cli;

public static class ScanReportLocator
{
    public static string? FindLatest(string requestedPath)
    {
        var path = Path.GetFullPath(requestedPath);
        if (HasSummary(path))
        {
            return path;
        }
        if (!Directory.Exists(path))
        {
            return null;
        }

        var candidates = new List<string>();
        foreach (var child in Directory.EnumerateDirectories(path))
        {
            AddIfReport(child, candidates);
            foreach (var nested in Directory.EnumerateDirectories(child))
            {
                AddIfReport(nested, candidates);
            }
        }

        return candidates
            .OrderByDescending(ReadStartedAt)
            .ThenByDescending(Directory.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    private static void AddIfReport(string path, ICollection<string> candidates)
    {
        if (HasSummary(path))
        {
            candidates.Add(path);
        }
    }

    private static bool HasSummary(string path)
    {
        return File.Exists(Path.Combine(path, "summary.json"));
    }

    private static DateTimeOffset ReadStartedAt(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(path, "scan.json")));
            if (document.RootElement.TryGetProperty("startedAt", out var value)
                && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var startedAt))
            {
                return startedAt;
            }
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
        }

        return Directory.GetLastWriteTimeUtc(path);
    }
}
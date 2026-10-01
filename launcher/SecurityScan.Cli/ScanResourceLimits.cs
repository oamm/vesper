using System.Globalization;
using System.Text.RegularExpressions;

namespace Vesper.Cli;

public sealed record ScanResourceLimits(string Cpus, string Memory, int PidsLimit)
{
    private static readonly Regex MemoryPattern = new(
        @"^[1-9]\d*(?:\.\d+)?(?:[kKmMgGtTpP](?:[bB])?|[bB])?$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static ScanResourceLimits Default { get; } = new("2", "4g", 512);

    public static ScanResourceLimits Parse(string cpus, string memory, string pidsLimit)
    {
        if (!double.TryParse(cpus, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var cpuCount)
            || cpuCount <= 0 || cpuCount > 256)
        {
            throw new ArgumentException("--cpus must be a number greater than 0 and no greater than 256.");
        }

        if (!MemoryPattern.IsMatch(memory))
        {
            throw new ArgumentException("--memory must be a positive Docker memory value such as 4g, 512m, or 1073741824b.");
        }

        if (!int.TryParse(pidsLimit, NumberStyles.None, CultureInfo.InvariantCulture, out var pids) || pids is < 1 or > 1_000_000)
        {
            throw new ArgumentException("--pids-limit must be an integer from 1 to 1000000.");
        }

        return new ScanResourceLimits(cpuCount.ToString("0.##", CultureInfo.InvariantCulture), memory, pids);
    }
}
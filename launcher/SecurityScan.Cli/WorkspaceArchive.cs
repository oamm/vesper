using System.Formats.Tar;

namespace Vesper.Cli;

public sealed record WorkspaceStats(int FileCount, long Bytes);
public sealed record WorkspaceArchiveInfo(string ArchivePath, WorkspaceStats Stats);

public static class WorkspaceArchive
{
    private static readonly HashSet<string> DefaultExcludedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".hg", ".svn", "node_modules", "bin", "obj", "security-results",
        "dist", "build", "artifacts", "coverage", ".venv", "venv", "__pycache__", ".terraform",
    };

    public static WorkspaceArchiveInfo Create(
        string workspace,
        string outputPath,
        string? configPath,
        bool includeGit)
    {
        var sourceRoot = Path.GetFullPath(workspace);
        var outputFullPath = Path.GetFullPath(outputPath);
        var configFullPath = configPath is null ? null : Path.GetFullPath(configPath);
        var (files, directories) = Enumerate(sourceRoot, outputFullPath, configFullPath, includeGit);
        var stats = new WorkspaceStats(files.Count, files.Sum(file => new FileInfo(file).Length));
        var archivePath = Path.Combine(Path.GetTempPath(), $"securityscan-{Guid.NewGuid():N}.tar");

        using (var stream = File.Create(archivePath))
        using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
        {
            foreach (var directory in directories)
            {
                var relative = RelativeTarPath(sourceRoot, directory).TrimEnd('/') + "/";
                var entry = new PaxTarEntry(TarEntryType.Directory, relative) { Mode = (UnixFileMode)Convert.ToInt32("755", 8) };
                writer.WriteEntry(entry);
            }

            foreach (var file in files)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, RelativeTarPath(sourceRoot, file))
                {
                    Mode = (UnixFileMode)Convert.ToInt32("644", 8),
                };
                using var fileStream = File.OpenRead(file);
                entry.DataStream = fileStream;
                writer.WriteEntry(entry);
            }
        }

        return new WorkspaceArchiveInfo(archivePath, stats);
    }

    public static string CreateSingleFile(string localFile, string archiveEntryName)
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"securityscan-{Guid.NewGuid():N}.tar");
        using (var stream = File.Create(archivePath))
        using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, archiveEntryName)
            {
                Mode = (UnixFileMode)Convert.ToInt32("644", 8),
            };
            using var fileStream = File.OpenRead(localFile);
            entry.DataStream = fileStream;
            writer.WriteEntry(entry);
        }

        return archivePath;
    }

    public static void Extract(string archivePath, string destination)
    {
        var root = Path.GetFullPath(destination);
        Directory.CreateDirectory(root);
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        using var stream = File.OpenRead(archivePath);
        using var reader = new TarReader(stream);
        TarEntry? entry;
        while ((entry = reader.GetNextEntry(copyData: false)) is not null)
        {
            if (entry.EntryType is not (TarEntryType.Directory or TarEntryType.RegularFile or TarEntryType.V7RegularFile))
            {
                continue;
            }

            var segments = entry.Name.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Where(segment => segment != ".").ToArray();
            if (segments.Length == 0)
            {
                if (entry.EntryType == TarEntryType.Directory)
                {
                    continue;
                }
                throw new InvalidDataException("The output archive contains an empty file path.");
            }

            if (segments.Any(segment => segment == ".."))
            {
                throw new InvalidDataException("The output archive contains an unsafe path.");
            }

            var target = Path.GetFullPath(Path.Combine(root, Path.Combine(segments)));
            if (!target.StartsWith(rootPrefix, comparison))
            {
                throw new InvalidDataException("The output archive contains a path outside the output directory.");
            }

            if (entry.EntryType == TarEntryType.Directory)
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var destinationStream = File.Create(target);
            entry.DataStream?.CopyTo(destinationStream);
        }
    }

    public static WorkspaceStats Measure(string workspace, string outputPath, string? configPath, bool includeGit)
    {
        var (files, _) = Enumerate(
            Path.GetFullPath(workspace),
            Path.GetFullPath(outputPath),
            configPath is null ? null : Path.GetFullPath(configPath),
            includeGit);
        return new WorkspaceStats(files.Count, files.Sum(file => new FileInfo(file).Length));
    }

    private static (List<string> Files, List<string> Directories) Enumerate(
        string sourceRoot,
        string outputPath,
        string? configPath,
        bool includeGit)
    {
        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException($"Workspace does not exist: {sourceRoot}");
        }

        var excludedDirectories = new HashSet<string>(DefaultExcludedDirectories, StringComparer.OrdinalIgnoreCase);
        if (includeGit)
        {
            excludedDirectories.Remove(".git");
        }

        var pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var files = new List<string>();
        var directories = new List<string>();
        var pending = new Stack<string>();
        pending.Push(sourceRoot);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (excludedDirectories.Contains(Path.GetFileName(entry))
                        || IsSameOrChild(entry, outputPath, pathComparison))
                    {
                        continue;
                    }

                    directories.Add(entry);
                    pending.Push(entry);
                }
                else if (!IsSamePath(entry, outputPath, pathComparison)
                         && (configPath is null || !IsSamePath(entry, configPath, pathComparison)))
                {
                    files.Add(entry);
                }
            }
        }

        files.Sort(StringComparer.Ordinal);
        directories.Sort(StringComparer.Ordinal);
        return (files, directories);
    }

    private static bool IsSameOrChild(string candidate, string parent, StringComparison comparison)
    {
        if (IsSamePath(candidate, parent, comparison))
        {
            return true;
        }

        var prefix = parent.EndsWith(Path.DirectorySeparatorChar) ? parent : parent + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }

    private static bool IsSamePath(string left, string right, StringComparison comparison)
    {
        return string.Equals(Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar), comparison);
    }

    private static string RelativeTarPath(string root, string path)
    {
        return Path.GetRelativePath(root, path).Replace('\\', '/');
    }
}
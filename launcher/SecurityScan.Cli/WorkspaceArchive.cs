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
        bool includeGit,
        WorkspaceTransferLimits? limits = null,
        IReadOnlyCollection<string>? excludedFiles = null)
    {
        limits ??= WorkspaceTransferLimits.Default;
        var sourceRoot = Path.GetFullPath(workspace);
        var outputFullPath = Path.GetFullPath(outputPath);
        var configFullPath = configPath is null ? null : Path.GetFullPath(configPath);
        var (files, directories) = Enumerate(sourceRoot, outputFullPath, configFullPath, includeGit, limits, excludedFiles);
        var stats = new WorkspaceStats(files.Count, files.Sum(file => new FileInfo(file).Length));
        var archivePath = Path.Combine(Path.GetTempPath(), $"securityscan-{Guid.NewGuid():N}.tar");

        try
        {
            using (var stream = CreatePrivateArchiveFile(archivePath))
            using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
            {
                if (files.Count == 0 && directories.Count == 0)
                {
                    writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "./")
                    {
                        Mode = (UnixFileMode)Convert.ToInt32("755", 8),
                    });
                }
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
            if (new FileInfo(archivePath).Length > limits.MaxWorkspaceArchiveBytes)
            {
                throw new InvalidDataException("Workspace archive exceeds the derived archive metadata limit.");
            }
        }
        catch
        {
            if (!TryDelete(archivePath))
            {
                Console.Error.WriteLine("[vesper] Temporary source archive cleanup failed; inspect the system temp directory.");
            }
            throw;
        }

        return new WorkspaceArchiveInfo(archivePath, stats);
    }

    public static string CreateSingleFile(string localFile, string archiveEntryName, WorkspaceTransferLimits? limits = null)
    {
        return CreateInputArchive([(localFile, archiveEntryName)], limits);
    }

    public static string CreateInputArchive(
        IReadOnlyCollection<(string SourcePath, string ArchivePath)> inputs,
        WorkspaceTransferLimits? limits = null)
    {
        limits ??= WorkspaceTransferLimits.Default;
        if (inputs.Count == 0)
        {
            throw new ArgumentException("At least one input file is required.", nameof(inputs));
        }
        foreach (var input in inputs)
        {
            if (new FileInfo(input.SourcePath).Length > limits.MaxFileBytes)
            {
                throw new InvalidDataException($"Input file exceeds the {limits.MaxFileBytes} byte per-file limit.");
            }
        }
        var archivePath = Path.Combine(Path.GetTempPath(), $"securityscan-{Guid.NewGuid():N}.tar");
        try
        {
            using (var stream = CreatePrivateArchiveFile(archivePath))
            using (var writer = new TarWriter(stream, TarEntryFormat.Pax))
            {
                foreach (var input in inputs.OrderBy(item => item.ArchivePath, StringComparer.Ordinal))
                {
                    var entry = new PaxTarEntry(TarEntryType.RegularFile, input.ArchivePath)
                    {
                        Mode = (UnixFileMode)Convert.ToInt32("644", 8),
                    };
                    using var fileStream = File.OpenRead(input.SourcePath);
                    entry.DataStream = fileStream;
                    writer.WriteEntry(entry);
                }
            }
            if (new FileInfo(archivePath).Length > limits.MaxOutputArchiveBytes)
            {
                throw new InvalidDataException("Input archive exceeds the derived archive metadata limit.");
            }
        }
        catch
        {
            if (!TryDelete(archivePath))
            {
                Console.Error.WriteLine("[vesper] Temporary input archive cleanup failed; inspect the system temp directory.");
            }
            throw;
        }

        return archivePath;
    }

    public static void Extract(string archivePath, string destination, WorkspaceTransferLimits? limits = null)
    {
        limits ??= WorkspaceTransferLimits.Default;
        if (new FileInfo(archivePath).Length > limits.MaxOutputArchiveBytes)
        {
            throw new InvalidDataException("The output archive exceeds the derived archive metadata limit.");
        }
        var root = Path.GetFullPath(destination);
        RejectReparsePoint(root);
        Directory.CreateDirectory(root);
        EnsureNoReparsePointParents(root, root);
        RestrictDirectoryPermissions(root);
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        using var stream = File.OpenRead(archivePath);
        using var reader = new TarReader(stream);
        var fileCount = 0;
        var entryCount = 0;
        long totalBytes = 0;
        TarEntry? entry;
        while ((entry = reader.GetNextEntry(copyData: false)) is not null)
        {
            if (++entryCount > limits.MaxEntries)
            {
                throw new InvalidDataException($"The output archive exceeds the {limits.MaxEntries} entry limit.");
            }
            if (entry.EntryType is not (TarEntryType.Directory or TarEntryType.RegularFile or TarEntryType.V7RegularFile))
            {
                continue;
            }

            var entryName = entry.Name;
            if (Path.IsPathRooted(entryName)
                || entryName.StartsWith("/", StringComparison.Ordinal)
                || (OperatingSystem.IsWindows() && entryName.StartsWith("\\", StringComparison.Ordinal))
                || (entryName.Length >= 2 && char.IsAsciiLetter(entryName[0]) && entryName[1] == ':')
                || entryName.Contains('\0'))
            {
                throw new InvalidDataException("The output archive contains an absolute or invalid path.");
            }

            var normalizedEntryName = OperatingSystem.IsWindows() ? entryName.Replace('\\', '/') : entryName;
            var segments = normalizedEntryName.Split('/', StringSplitOptions.RemoveEmptyEntries)
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

            if (OperatingSystem.IsWindows() && segments.Any(segment => segment.Contains(':') || segment.EndsWith(' ') || segment.EndsWith('.')))
            {
                throw new InvalidDataException("The output archive contains a Windows-ambiguous path component.");
            }

            if (entry.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile)
            {
                if (++fileCount > limits.MaxOutputFiles)
                {
                    throw new InvalidDataException($"The output archive exceeds the {limits.MaxOutputFiles} file limit.");
                }
                if (entry.Length < 0 || entry.Length > limits.MaxFileBytes || entry.Length > limits.MaxOutputBytes - totalBytes)
                {
                    throw new InvalidDataException("The output archive exceeds configured byte limits.");
                }
                totalBytes += entry.Length;
            }

            var target = Path.GetFullPath(Path.Combine(root, Path.Combine(segments)));
            if (!target.StartsWith(rootPrefix, comparison))
            {
                throw new InvalidDataException("The output archive contains a path outside the output directory.");
            }
            EnsureNoReparsePointParents(root, target);

            if (entry.EntryType == TarEntryType.Directory)
            {
                Directory.CreateDirectory(target);
                RestrictDirectoryPermissions(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var destinationStream = File.Create(target);
            entry.DataStream?.CopyTo(destinationStream);
            RestrictFilePermissions(target);
        }
    }

    public static WorkspaceStats Measure(
        string workspace,
        string outputPath,
        string? configPath,
        bool includeGit,
        WorkspaceTransferLimits? limits = null,
        IReadOnlyCollection<string>? excludedFiles = null)
    {
        var (files, _) = Enumerate(
            Path.GetFullPath(workspace),
            Path.GetFullPath(outputPath),
            configPath is null ? null : Path.GetFullPath(configPath),
            includeGit,
            limits ?? WorkspaceTransferLimits.Default,
            excludedFiles);
        return new WorkspaceStats(files.Count, files.Sum(file => new FileInfo(file).Length));
    }

    private static (List<string> Files, List<string> Directories) Enumerate(
        string sourceRoot,
        string outputPath,
        string? configPath,
        bool includeGit,
        WorkspaceTransferLimits limits,
        IReadOnlyCollection<string>? excludedFiles = null)
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
        var excludedFilePaths = (excludedFiles ?? Array.Empty<string>())
            .Select(Path.GetFullPath)
            .Append(configPath)
            .Where(path => path is not null)
            .Cast<string>()
            .ToHashSet(pathComparison == StringComparison.OrdinalIgnoreCase ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        var files = new List<string>();
        var directories = new List<string>();
        var entryCount = 0;
        long totalBytes = 0;
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

                    if (++entryCount > limits.MaxEntries)
                    {
                        throw new InvalidDataException($"Workspace exceeds the {limits.MaxEntries} entry limit.");
                    }
                    directories.Add(entry);
                    pending.Push(entry);
                }
                else if (!IsSamePath(entry, outputPath, pathComparison)
                         && !excludedFilePaths.Contains(Path.GetFullPath(entry)))
                {
                    if (++entryCount > limits.MaxEntries)
                    {
                        throw new InvalidDataException($"Workspace exceeds the {limits.MaxEntries} entry limit.");
                    }
                    if (files.Count >= limits.MaxFiles)
                    {
                        throw new InvalidDataException($"Workspace exceeds the {limits.MaxFiles} file limit.");
                    }
                    var fileLength = new FileInfo(entry).Length;
                    if (fileLength > limits.MaxFileBytes)
                    {
                        throw new InvalidDataException($"Workspace file exceeds the {limits.MaxFileBytes} byte per-file limit.");
                    }
                    if (fileLength > limits.MaxWorkspaceBytes - totalBytes)
                    {
                        throw new InvalidDataException($"Workspace exceeds the {limits.MaxWorkspaceBytes} byte limit.");
                    }
                    totalBytes += fileLength;
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
        var relativePath = Path.GetRelativePath(root, path);
        return OperatingSystem.IsWindows() ? relativePath.Replace('\\', '/') : relativePath;
    }

    public static FileStream CreatePrivateArchiveFile(string path)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 4096,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        return new FileStream(path, options);
    }

    private static void EnsureNoReparsePointParents(string root, string directory)
    {
        var current = Path.GetFullPath(directory);
        var fullRoot = Path.GetFullPath(root);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        while (current.StartsWith(fullRoot, comparison))
        {
            RejectReparsePoint(current);
            if (string.Equals(current, fullRoot, comparison))
            {
                return;
            }
            current = Path.GetDirectoryName(current)!;
        }
        throw new InvalidDataException("The output path escapes the extraction root.");
    }

    private static void RejectReparsePoint(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("The output path contains a symlink or reparse point.");
            }
        }
        catch (FileNotFoundException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    private static void RestrictDirectoryPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void RestrictFilePermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static bool TryDelete(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (IOException exception)
        {
            Console.Error.WriteLine($"[vesper] Temporary archive cleanup failed ({exception.GetType().Name}).");
            return false;
        }
        catch (UnauthorizedAccessException exception)
        {
            Console.Error.WriteLine($"[vesper] Temporary archive cleanup failed ({exception.GetType().Name}).");
            return false;
        }
    }
}
using ModelContextProtocol;

namespace CklMcp.Tools;

/// <summary>
/// Command-line options: <c>--read-only</c> blocks every tool that edits findings or writes
/// checklist files, and repeatable <c>--root &lt;dir&gt;</c> restricts all file access to the
/// given directories. With no roots specified, any path is allowed.
/// </summary>
public sealed class ServerOptions
{
    public bool ReadOnly { get; private set; }
    public List<string> Roots { get; } = new();

    public static ServerOptions Parse(string[] args)
    {
        var options = new ServerOptions();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--read-only":
                    options.ReadOnly = true;
                    break;
                case "--root":
                    if (i + 1 >= args.Length)
                    {
                        throw new ArgumentException("--root requires a directory path.");
                    }

                    var root = Path.GetFullPath(args[++i]);
                    if (!Directory.Exists(root))
                    {
                        throw new ArgumentException($"--root directory does not exist: {root}");
                    }

                    options.Roots.Add(root);
                    break;
            }
        }

        return options;
    }

    public string ValidateReadPath(string path)
    {
        var full = Normalize(path);
        if (!File.Exists(full))
        {
            throw new McpException($"File not found: {full}");
        }

        return full;
    }

    public string ValidateWritePath(string path)
    {
        var full = Normalize(path);
        var directory = Path.GetDirectoryName(full);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new McpException($"Directory does not exist: {directory}");
        }

        return full;
    }

    public void RequireWritable(string toolName)
    {
        if (ReadOnly)
        {
            throw new McpException($"Server is running in --read-only mode; '{toolName}' is disabled.");
        }
    }

    private string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new McpException("A file path is required.");
        }

        var full = Path.GetFullPath(path);
        if (Roots.Count > 0 && !Roots.Any(r => IsUnder(full, r)))
        {
            throw new McpException(
                $"Path is outside the allowed roots ({string.Join(", ", Roots)}): {full}");
        }

        return full;
    }

    private static bool IsUnder(string path, string root) =>
        path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
}

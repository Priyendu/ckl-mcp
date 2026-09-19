using ModelContextProtocol;

namespace CklMcp.Tools;

/// <summary>
/// Command-line options: <c>--read-only</c> blocks every tool that edits findings or writes
/// checklist files, and repeatable <c>--root &lt;dir&gt;</c> restricts all file access to the
/// given directories. With no roots specified, any path is allowed.
/// </summary>
public sealed class ServerOptions
{
    public const string StdioUsage = """
        ckl-mcp (stdio MCP server for DISA STIG checklists)

        Usage: CklMcp.Server [options]

          --read-only    Disable every tool that edits findings or writes checklist files.
          --root <dir>   Restrict all file access to this directory (repeatable).
          -h, --help     Show this help.

        Unknown options are rejected, so a typo such as --readonly fails at startup instead of
        silently leaving the server read-write. For the HTTP server, see CklMcp.Http --help.
        """;

    public bool ReadOnly { get; private set; }
    public List<string> Roots { get; } = new();

    /// <summary>
    /// Parses <c>--read-only</c> and <c>--root</c>. With <paramref name="rejectUnknown"/> false (the
    /// default) any other argument is skipped, which lets a host that has options of its own, such
    /// as the HTTP server, share this parser and validate those itself. With it true, anything
    /// unrecognized is an error: these flags are safety settings, and a silently ignored typo
    /// would quietly turn one off.
    /// </summary>
    public static ServerOptions Parse(string[] args, bool rejectUnknown = false)
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
                default:
                    if (rejectUnknown)
                    {
                        throw new ArgumentException($"Unknown option '{args[i]}'.");
                    }

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

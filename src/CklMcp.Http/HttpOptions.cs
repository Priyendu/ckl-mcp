using System.Net;
using System.Security.Cryptography;
using CklMcp.Tools;

namespace CklMcp.Http;

/// <summary>
/// Command-line options for the HTTP server. The rules here are the safety net for a server that can
/// read and write files: it binds to loopback unless told otherwise, always requires a bearer token,
/// and refuses to listen on a non-loopback address unless the operator has explicitly opted in,
/// supplied their own token, and restricted file access with <c>--root</c>.
/// </summary>
public sealed class HttpOptions
{
    public const int MinTokenLength = 24;
    public const string TokenEnvVar = "CKL_MCP_TOKEN";
    public const string EndpointPath = "/mcp";

    public const string Usage = """
        ckl-mcp HTTP server (MCP Streamable HTTP, stateless, one shared workspace)

        Usage: CklMcp.Http [options]

          --host <ip>             Address to bind: an IP address or 'localhost'. Default 127.0.0.1.
          --port <n>              Port to listen on (0 = pick a free port). Default 8765.
          --token-file <path>     Read the bearer token from this file. Otherwise the CKL_MCP_TOKEN
                                  environment variable is used; if neither is set, a random token is
                                  generated for this run and printed to stderr (loopback only).
          --allow-origin <origin> Also accept browser requests from this Origin (repeatable).
                                  Loopback origins are always accepted.
          --allow-remote          Required to bind a non-loopback address. Also requires an explicit
                                  token and at least one --root.
          --root <dir>            Restrict all file access to this directory (repeatable).
          --read-only             Disable every tool that edits findings or writes checklist files.
          -h, --help              Show this help.

        The endpoint is <scheme>://<host>:<port>/mcp and every request needs
        'Authorization: Bearer <token>'. TLS is not built in: to reach this server from a
        hosted model API, put it behind a TLS-terminating tunnel or reverse proxy.
        """;

    private static readonly HashSet<string> LoopbackHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "127.0.0.1", "[::1]", "::1"
    };

    private readonly List<string> _allowedOrigins = new();

    public IPAddress BindAddress { get; private set; } = IPAddress.Loopback;
    public int Port { get; private set; } = 8765;
    public bool AllowRemote { get; private set; }

    /// <summary>The bearer token clients must present.</summary>
    public string Token { get; private set; } = string.Empty;

    /// <summary>True when no token was supplied and one was generated for this run.</summary>
    public bool TokenGenerated { get; private set; }

    public IReadOnlyList<string> AllowedOrigins => _allowedOrigins;

    public bool IsLoopback => IPAddress.IsLoopback(BindAddress);

    public static HttpOptions Parse(string[] args, ServerOptions server, Func<string, string?>? getEnv = null)
    {
        getEnv ??= Environment.GetEnvironmentVariable;
        var options = new HttpOptions();
        string? tokenFile = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--host":
                    options.BindAddress = ParseHost(Value(args, ref i));
                    break;
                case "--port":
                    var port = Value(args, ref i);
                    if (!int.TryParse(port, out var parsed) || parsed is < 0 or > 65535)
                    {
                        throw new ArgumentException($"--port must be a number from 0 to 65535, got '{port}'.");
                    }

                    options.Port = parsed;
                    break;
                case "--token-file":
                    tokenFile = Value(args, ref i);
                    break;
                case "--allow-origin":
                    options._allowedOrigins.Add(NormalizeOrigin(Value(args, ref i)));
                    break;
                case "--allow-remote":
                    options.AllowRemote = true;
                    break;
                case "--read-only":
                    break; // consumed by ServerOptions
                case "--root":
                    Value(args, ref i); // consumed by ServerOptions; skip its value
                    break;
                default:
                    // A silently ignored typo (say --tokn-file) would quietly weaken a security setting.
                    throw new ArgumentException($"Unknown option '{args[i]}'.");
            }
        }

        options.ResolveToken(tokenFile, getEnv);

        if (!options.IsLoopback)
        {
            if (!options.AllowRemote)
            {
                throw new ArgumentException(
                    $"Refusing to bind {options.BindAddress}: it is not a loopback address. " +
                    "Pass --allow-remote to expose the server beyond this machine.");
            }

            if (options.TokenGenerated)
            {
                throw new ArgumentException(
                    "Binding a non-loopback address requires an explicit token (--token-file or " +
                    $"{TokenEnvVar}); a generated one is only allowed on loopback.");
            }

            if (server.Roots.Count == 0)
            {
                throw new ArgumentException(
                    "Binding a non-loopback address requires --root <dir> so remote callers can't reach " +
                    "arbitrary files.");
            }
        }

        return options;
    }

    /// <summary>
    /// True for browser origins that may call the server: loopback origins, plus any that were
    /// allowed explicitly. A request with no Origin header (every non-browser client) never gets here.
    /// </summary>
    public bool IsOriginAllowed(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https"))
        {
            return false;
        }

        if (LoopbackHosts.Contains(uri.Host))
        {
            return true;
        }

        return _allowedOrigins.Contains(uri.GetLeftPart(UriPartial.Authority), StringComparer.OrdinalIgnoreCase);
    }

    private void ResolveToken(string? tokenFile, Func<string, string?> getEnv)
    {
        string? explicitToken = null;
        if (tokenFile is not null)
        {
            if (!File.Exists(tokenFile))
            {
                throw new ArgumentException($"--token-file not found: {tokenFile}");
            }

            explicitToken = File.ReadAllText(tokenFile).Trim();
        }
        else
        {
            var fromEnv = getEnv(TokenEnvVar);
            if (!string.IsNullOrWhiteSpace(fromEnv))
            {
                explicitToken = fromEnv.Trim();
            }
        }

        if (explicitToken is null)
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            TokenGenerated = true;
            return;
        }

        if (explicitToken.Length < MinTokenLength)
        {
            throw new ArgumentException(
                $"The bearer token must be at least {MinTokenLength} characters (got {explicitToken.Length}). " +
                "Generate one with, for example, 'openssl rand -base64 32'.");
        }

        if (explicitToken.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            throw new ArgumentException("The bearer token must not contain whitespace or control characters.");
        }

        Token = explicitToken;
    }

    private static IPAddress ParseHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return IPAddress.Loopback;
        }

        // Only literal IPs: resolving a hostname could quietly turn "local" into a public address.
        if (IPAddress.TryParse(host, out var address))
        {
            return address;
        }

        throw new ArgumentException($"--host must be an IP address or 'localhost', got '{host}'.");
    }

    private static string NormalizeOrigin(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException($"--allow-origin must look like https://host[:port], got '{origin}'.");
        }

        return uri.GetLeftPart(UriPartial.Authority);
    }

    private static string Value(string[] args, ref int i)
    {
        if (i + 1 >= args.Length)
        {
            throw new ArgumentException($"{args[i]} requires a value.");
        }

        return args[++i];
    }
}

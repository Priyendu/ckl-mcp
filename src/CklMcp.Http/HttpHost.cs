using System.Net;
using CklMcp.Tools;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace CklMcp.Http;

public static class HttpHost
{
    /// <summary>Tool arguments are small JSON; anything near this size is not a legitimate call.</summary>
    private const long MaxRequestBodyBytes = 1024 * 1024;

    public static WebApplication Build(HttpOptions http, ServerOptions server)
    {
        // No args on purpose: --urls or ASPNETCORE_URLS must not be able to move the listener
        // somewhere the safety checks in HttpOptions never saw.
        var builder = WebApplication.CreateBuilder();

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = MaxRequestBodyBytes;
            kestrel.Listen(http.BindAddress, http.Port);
        });

        // ASP.NET logs five lines per request, which buries the useful ones. Keep warnings (and the
        // auth rejections and per-call MCP lines, which are the audit trail of what a client did).
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

        builder.Services.AddSingleton(http);
        builder.Services.AddSingleton(new TokenAuthenticator(http.Token));

        // Stateless: every request stands alone, which is also how the newest MCP protocol revision
        // works over HTTP (it drops Mcp-Session-Id). Checklist state therefore lives in the one
        // shared Workspace, not in a protocol session.
        builder.Services
            .AddCklMcpServer(server)
            .WithHttpTransport(o => o.Stateless = true);

        var app = builder.Build();

        // Authenticate before anything else, so an unauthenticated caller learns nothing about
        // which paths exist or how the server is configured.
        app.Use(async (context, next) =>
        {
            var authenticator = context.RequestServices.GetRequiredService<TokenAuthenticator>();
            if (!authenticator.IsAuthorized(context.Request.Headers.Authorization.ToString()))
            {
                Reject(context, StatusCodes.Status401Unauthorized, "missing or invalid bearer token");
                context.Response.Headers.WWWAuthenticate = "Bearer realm=\"ckl-mcp\"";
                return;
            }

            // Non-browser clients send no Origin. A browser that does must come from an allowed
            // origin, which blocks a web page from driving a local server (DNS rebinding).
            if (context.Request.Headers.TryGetValue(HeaderNames.Origin, out var origin) &&
                !http.IsOriginAllowed(origin.ToString()))
            {
                Reject(context, StatusCodes.Status403Forbidden, "origin not allowed");
                return;
            }

            await next();
        });

        app.MapMcp(HttpOptions.EndpointPath);
        return app;
    }

    /// <summary>
    /// Builds and starts the server, then verifies the addresses the OS actually bound. If anything
    /// is listening beyond what the options allow, the server is stopped instead of returned.
    /// </summary>
    public static async Task<WebApplication> StartAsync(HttpOptions http, ServerOptions server,
        CancellationToken cancellationToken = default)
    {
        var app = Build(http, server);
        await app.StartAsync(cancellationToken);
        try
        {
            VerifyBoundAddresses(app, http);
        }
        catch
        {
            await app.StopAsync(CancellationToken.None);
            await app.DisposeAsync();
            throw;
        }

        return app;
    }

    /// <summary>The URL clients should connect to, including the MCP path.</summary>
    public static string EndpointUrl(WebApplication app) =>
        BoundAddresses(app).First().TrimEnd('/') + HttpOptions.EndpointPath;

    public static IReadOnlyList<string> BannerLines(WebApplication app, HttpOptions http, ServerOptions server)
    {
        var lines = new List<string>
        {
            "ckl-mcp HTTP server (MCP Streamable HTTP, stateless)",
            $"  endpoint : {EndpointUrl(app)}",
            http.TokenGenerated
                ? $"  auth     : Authorization: Bearer {http.Token}"
                : "  auth     : bearer token required (from --token-file or CKL_MCP_TOKEN)",
            "  workspace: ONE shared workspace for every client of this process",
            $"  mode     : {(server.ReadOnly ? "read-only" : "read-write")}",
            $"  roots    : {(server.Roots.Count == 0 ? "none (any path this process can access)" : string.Join(", ", server.Roots))}"
        };

        if (http.TokenGenerated)
        {
            lines.Add("  note     : that token was generated for this run; set your own with --token-file or CKL_MCP_TOKEN");
        }

        if (!http.IsLoopback)
        {
            lines.Add("  WARNING  : listening beyond loopback over plain HTTP. Put this behind a TLS-terminating proxy.");
        }

        return lines;
    }

    private static void Reject(HttpContext context, int statusCode, string reason)
    {
        // Log who and why, never the header: a near-miss token must not end up in a log file.
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ckl-mcp.auth")
            .LogWarning("Rejected request from {RemoteIp}: {Reason}",
                context.Connection.RemoteIpAddress, reason);
        context.Response.StatusCode = statusCode;
    }

    private static IReadOnlyList<string> BoundAddresses(WebApplication app) =>
        app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.ToList()
        ?? new List<string>();

    private static void VerifyBoundAddresses(WebApplication app, HttpOptions http)
    {
        var addresses = BoundAddresses(app);
        if (addresses.Count == 0)
        {
            throw new InvalidOperationException("The server started but reports no listening address.");
        }

        foreach (var address in addresses)
        {
            if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
                !IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip))
            {
                throw new InvalidOperationException($"Could not verify listening address '{address}'.");
            }

            if (!IPAddress.IsLoopback(ip) && !http.AllowRemote)
            {
                throw new InvalidOperationException(
                    $"The server is listening on non-loopback address '{address}' without --allow-remote.");
            }
        }
    }
}

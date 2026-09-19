using System.Net;
using System.Text;
using System.Text.Json;
using CklMcp.Http;
using CklMcp.Tools;
using CklViewer.Tests;
using CklViewer.Writing;
using Microsoft.AspNetCore.Builder;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit;

namespace CklMcp.Tests;

/// <summary>End-to-end tests: a real Kestrel listener on a random loopback port, real HTTP requests.</summary>
public sealed class HttpTransportTests : IAsyncLifetime
{
    private const string Token = "test-token-0123456789-abcdefghij";

    private const string InitializeBody =
        """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}""";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ckl-mcp-httptests-" + Guid.NewGuid().ToString("N"));
    private readonly List<WebApplication> _apps = new();

    public Task InitializeAsync()
    {
        Directory.CreateDirectory(_dir);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        foreach (var app in _apps)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        Directory.Delete(_dir, recursive: true);
    }

    private async Task<(string Url, HttpOptions Http)> StartAsync(params string[] extraArgs)
    {
        var args = new[] { "--port", "0" }.Concat(extraArgs).ToArray();
        var server = ServerOptions.Parse(args);
        var http = HttpOptions.Parse(args, server, name => name == HttpOptions.TokenEnvVar ? Token : null);

        var app = await HttpHost.StartAsync(http, server);
        _apps.Add(app);
        return (HttpHost.EndpointUrl(app), http);
    }

    private string WriteSampleCkl(string name = "sample.ckl")
    {
        var path = Path.Combine(_dir, name);
        CklWriter.WriteFile(SampleData.BuildChecklist(), path);
        return path;
    }

    private static Task<McpClient> ConnectAsync(string url, string token = Token) =>
        McpClient.CreateAsync(new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(url),
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" }
        }));

    private static async Task<JsonElement> CallAsync(McpClient client, string tool, Dictionary<string, object?>? args = null)
    {
        var result = await client.CallToolAsync(tool, args ?? new Dictionary<string, object?>());
        var text = result.Content.OfType<TextContentBlock>().First().Text;
        Assert.NotEqual(true, result.IsError);
        return JsonDocument.Parse(text).RootElement;
    }

    private static async Task<HttpStatusCode> PostAsync(string url, string? authorization, string? origin = null)
    {
        using var http = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(InitializeBody, Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/event-stream");
        if (authorization is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        if (origin is not null)
        {
            request.Headers.TryAddWithoutValidation("Origin", origin);
        }

        using var response = await http.SendAsync(request);
        return response.StatusCode;
    }

    [Fact]
    public async Task RequestsWithoutTheRightTokenAreRejected()
    {
        var (url, _) = await StartAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, await PostAsync(url, null));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostAsync(url, "Bearer wrong-token"));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostAsync(url, Token)); // no scheme
        Assert.Equal(HttpStatusCode.Unauthorized, await PostAsync(url, $"Basic {Token}"));
        Assert.Equal(HttpStatusCode.OK, await PostAsync(url, $"Bearer {Token}"));
    }

    [Fact]
    public async Task UnauthenticatedCallersLearnNothingAboutOtherPaths()
    {
        var (url, _) = await StartAsync();
        var other = url.Replace(HttpOptions.EndpointPath, "/anything-else");

        // Same 401 as the real endpoint, so probing for paths reveals nothing.
        Assert.Equal(HttpStatusCode.Unauthorized, await PostAsync(other, null));
        Assert.Equal(HttpStatusCode.NotFound, await PostAsync(other, $"Bearer {Token}"));
    }

    [Fact]
    public async Task BrowserOriginsAreCheckedEvenWithAValidToken()
    {
        var (url, _) = await StartAsync("--allow-origin", "https://app.example.com");
        var auth = $"Bearer {Token}";

        Assert.Equal(HttpStatusCode.Forbidden, await PostAsync(url, auth, "https://evil.example"));
        Assert.Equal(HttpStatusCode.Forbidden, await PostAsync(url, auth, "null"));
        Assert.Equal(HttpStatusCode.OK, await PostAsync(url, auth, "http://localhost:3000"));
        Assert.Equal(HttpStatusCode.OK, await PostAsync(url, auth, "https://app.example.com"));
    }

    [Fact]
    public async Task ListensOnLoopbackOnly()
    {
        var (url, http) = await StartAsync();

        Assert.True(http.IsLoopback);
        Assert.Equal("127.0.0.1", new Uri(url).Host);
    }

    [Fact]
    public async Task ExposesTheSameToolsAsStdio()
    {
        var (url, _) = await StartAsync();
        await using var client = await ConnectAsync(url);

        var names = (await client.ListToolsAsync()).Select(t => t.Name).ToHashSet();

        Assert.Equal(15, names.Count);
        Assert.Contains("load_checklists", names);
        Assert.Contains("merge_prior_assessment", names);
        Assert.Contains("export_excel_report", names);
    }

    [Fact]
    public async Task WorkspaceIsSharedAcrossSeparateConnections()
    {
        // Hosted APIs typically open a fresh connection per request, and the newest protocol revision
        // has no HTTP sessions at all, so state must outlive any single connection.
        var (url, _) = await StartAsync();
        var path = WriteSampleCkl();

        await using (var first = await ConnectAsync(url))
        {
            var loaded = await CallAsync(first, "load_checklists", new() { ["paths"] = new[] { path } });
            Assert.Equal(3, loaded[0].GetProperty("totalFindings").GetInt32());
        }

        await using var second = await ConnectAsync(url);
        var summary = await CallAsync(second, "get_summary");

        Assert.Equal(1, summary.GetProperty("checklists").GetInt32());
        Assert.Equal(3, summary.GetProperty("totalFindings").GetInt32());
    }

    [Fact]
    public async Task EditsAndSavesWorkEndToEnd()
    {
        var (url, _) = await StartAsync();
        var path = WriteSampleCkl();
        await using var client = await ConnectAsync(url);

        await CallAsync(client, "load_checklists", new() { ["paths"] = new[] { path } });
        var updated = await CallAsync(client, "update_finding", new()
        {
            ["vulnId"] = "V-220710",
            ["status"] = "NotAFinding",
            ["internalNotes"] = "over http"
        });
        Assert.Equal("NotAFinding", updated.GetProperty("status").GetString());
        Assert.Equal("over http", updated.GetProperty("internalNotes").GetString());

        await CallAsync(client, "save_checklist");
        var reloaded = CklViewer.Parsing.CklParser.ParseFile(path);
        Assert.Equal(CklViewer.Models.FindingStatus.NotAFinding,
            reloaded.AllVulnerabilities.Single(v => v.VulnId == "V-220710").Status);
    }

    [Fact]
    public async Task ReadOnlyAndRootRestrictionsApplyOverHttp()
    {
        var inside = WriteSampleCkl();
        var outsideDir = Path.Combine(Path.GetTempPath(), "ckl-mcp-outside-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outsideDir);
        try
        {
            var outside = Path.Combine(outsideDir, "outside.ckl");
            CklWriter.WriteFile(SampleData.BuildChecklist(), outside);

            var (url, _) = await StartAsync("--read-only", "--root", _dir);
            await using var client = await ConnectAsync(url);

            await CallAsync(client, "load_checklists", new() { ["paths"] = new[] { inside } });

            var blockedEdit = await client.CallToolAsync("update_finding",
                new Dictionary<string, object?> { ["vulnId"] = "V-220697", ["status"] = "NotAFinding" });
            Assert.True(blockedEdit.IsError);

            var blockedLoad = await client.CallToolAsync("load_checklists",
                new Dictionary<string, object?> { ["paths"] = new[] { outside } });
            Assert.True(blockedLoad.IsError);
        }
        finally
        {
            Directory.Delete(outsideDir, recursive: true);
        }
    }

    [Fact]
    public async Task ConcurrentCallsDoNotCorruptTheSharedWorkspace()
    {
        var (url, _) = await StartAsync();
        var path = WriteSampleCkl();
        await using (var setup = await ConnectAsync(url))
        {
            await CallAsync(setup, "load_checklists", new() { ["paths"] = new[] { path } });
        }

        var calls = Enumerable.Range(0, 24).Select(async i =>
        {
            await using var client = await ConnectAsync(url);
            await CallAsync(client, "update_finding", new()
            {
                ["vulnId"] = "V-220697",
                ["comments"] = $"call {i}"
            });
            return await CallAsync(client, "get_summary");
        });

        var summaries = await Task.WhenAll(calls);

        Assert.All(summaries, s => Assert.Equal(3, s.GetProperty("totalFindings").GetInt32()));
    }
}

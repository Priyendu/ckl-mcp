using CklMcp.Http;
using CklMcp.Tools;
using Xunit;

namespace CklMcp.Tests;

public sealed class HttpOptionsTests : IDisposable
{
    private const string GoodToken = "abcdefghijklmnopqrstuvwxyz012345"; // 32 chars

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ckl-mcp-httpopts-" + Guid.NewGuid().ToString("N"));

    public HttpOptionsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static Func<string, string?> Env(string? token = null) =>
        name => name == HttpOptions.TokenEnvVar ? token : null;

    private static HttpOptions Parse(string[] args, string? envToken = null)
    {
        var server = ServerOptions.Parse(args);
        return HttpOptions.Parse(args, server, Env(envToken));
    }

    [Fact]
    public void DefaultsAreLoopbackWithAGeneratedToken()
    {
        var options = Parse(Array.Empty<string>());

        Assert.True(options.IsLoopback);
        Assert.Equal(8765, options.Port);
        Assert.True(options.TokenGenerated);
        Assert.True(options.Token.Length >= HttpOptions.MinTokenLength);
        Assert.DoesNotContain('=', options.Token); // URL/header-safe, no padding
    }

    [Fact]
    public void GeneratedTokensAreDifferentEachRun()
    {
        Assert.NotEqual(Parse(Array.Empty<string>()).Token, Parse(Array.Empty<string>()).Token);
    }

    [Fact]
    public void TokenComesFromTheEnvironmentAndIsNotGenerated()
    {
        var options = Parse(Array.Empty<string>(), GoodToken);

        Assert.Equal(GoodToken, options.Token);
        Assert.False(options.TokenGenerated);
    }

    [Fact]
    public void TokenFileWinsOverEnvironmentAndIsTrimmed()
    {
        var file = Path.Combine(_dir, "token.txt");
        File.WriteAllText(file, GoodToken + Environment.NewLine);

        var options = Parse(new[] { "--token-file", file }, "an-environment-token-that-is-long-enough");

        Assert.Equal(GoodToken, options.Token);
    }

    [Fact]
    public void ShortOrWhitespaceTokensAreRejected()
    {
        Assert.Throws<ArgumentException>(() => Parse(Array.Empty<string>(), "too-short"));
        Assert.Throws<ArgumentException>(() => Parse(Array.Empty<string>(), "has a space inside the long token!!"));
    }

    [Fact]
    public void MissingTokenFileIsAnError()
    {
        Assert.Throws<ArgumentException>(() => Parse(new[] { "--token-file", Path.Combine(_dir, "nope.txt") }));
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("192.168.1.10")]
    public void NonLoopbackBindIsRefusedWithoutAllowRemote(string host)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Parse(new[] { "--host", host, "--root", _dir }, GoodToken));
        Assert.Contains("--allow-remote", ex.Message);
    }

    [Fact]
    public void NonLoopbackBindNeedsAnExplicitToken()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Parse(new[] { "--host", "0.0.0.0", "--allow-remote", "--root", _dir }));
        Assert.Contains("explicit token", ex.Message);
    }

    [Fact]
    public void NonLoopbackBindNeedsARoot()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Parse(new[] { "--host", "0.0.0.0", "--allow-remote" }, GoodToken));
        Assert.Contains("--root", ex.Message);
    }

    [Fact]
    public void NonLoopbackBindIsAllowedWhenEverySafeguardIsMet()
    {
        var options = Parse(new[] { "--host", "0.0.0.0", "--allow-remote", "--root", _dir }, GoodToken);

        Assert.False(options.IsLoopback);
        Assert.True(options.AllowRemote);
    }

    [Fact]
    public void HostnamesAreRejectedButLocalhostIsAccepted()
    {
        Assert.Throws<ArgumentException>(() => Parse(new[] { "--host", "example.com" }));
        Assert.True(Parse(new[] { "--host", "localhost" }).IsLoopback);
        Assert.True(Parse(new[] { "--host", "::1" }).IsLoopback);
    }

    [Theory]
    [InlineData("--tokn-file")]
    [InlineData("--allow-remot")]
    [InlineData("--bogus")]
    public void UnknownOptionsAreRejectedRatherThanIgnored(string option)
    {
        var ex = Assert.Throws<ArgumentException>(() => Parse(new[] { option }));
        Assert.Contains(option, ex.Message);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData("70000")]
    public void InvalidPortsAreRejected(string port)
    {
        Assert.Throws<ArgumentException>(() => Parse(new[] { "--port", port }));
    }

    [Fact]
    public void OptionsMissingTheirValueAreRejected()
    {
        Assert.Throws<ArgumentException>(() => Parse(new[] { "--port" }));
        Assert.Throws<ArgumentException>(() => Parse(new[] { "--allow-origin" }));
    }

    [Fact]
    public void SharedFlagsAreAcceptedAndReachServerOptions()
    {
        var args = new[] { "--read-only", "--root", _dir, "--port", "0" };
        var server = ServerOptions.Parse(args);
        var options = HttpOptions.Parse(args, server, Env());

        Assert.True(server.ReadOnly);
        Assert.Single(server.Roots);
        Assert.Equal(0, options.Port);
    }

    [Fact]
    public void OriginPolicyAllowsLoopbackAndExplicitlyAllowedOriginsOnly()
    {
        var options = Parse(new[] { "--allow-origin", "https://app.example.com/" });

        Assert.True(options.IsOriginAllowed("http://localhost:3000"));
        Assert.True(options.IsOriginAllowed("http://127.0.0.1:8080"));
        Assert.True(options.IsOriginAllowed("http://[::1]:5173"));
        Assert.True(options.IsOriginAllowed("https://app.example.com"));
        Assert.True(options.IsOriginAllowed("HTTPS://APP.EXAMPLE.COM"));

        Assert.False(options.IsOriginAllowed("https://evil.example"));
        Assert.False(options.IsOriginAllowed("http://app.example.com")); // wrong scheme
        Assert.False(options.IsOriginAllowed("https://app.example.com.evil.example"));
        Assert.False(options.IsOriginAllowed("null"));
        Assert.False(options.IsOriginAllowed("file:///etc/passwd"));
        Assert.False(options.IsOriginAllowed(""));
    }

    [Fact]
    public void TokenAuthenticatorAcceptsOnlyTheExactBearerToken()
    {
        var auth = new TokenAuthenticator(GoodToken);

        Assert.True(auth.IsAuthorized($"Bearer {GoodToken}"));
        Assert.True(auth.IsAuthorized($"bearer {GoodToken}")); // scheme is case-insensitive
        Assert.True(auth.IsAuthorized($"Bearer  {GoodToken} ")); // stray whitespace around it

        Assert.False(auth.IsAuthorized(null));
        Assert.False(auth.IsAuthorized(""));
        Assert.False(auth.IsAuthorized(GoodToken)); // no scheme
        Assert.False(auth.IsAuthorized($"Basic {GoodToken}"));
        Assert.False(auth.IsAuthorized("Bearer " + GoodToken[..^1]));
        Assert.False(auth.IsAuthorized("Bearer " + GoodToken + "x"));
        Assert.False(auth.IsAuthorized("Bearer " + GoodToken.ToUpperInvariant()));
    }
}

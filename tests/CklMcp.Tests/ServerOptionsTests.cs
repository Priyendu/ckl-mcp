using CklMcp.Tools;
using Xunit;

namespace CklMcp.Tests;

public sealed class ServerOptionsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ckl-mcp-optstests-" + Guid.NewGuid().ToString("N"));

    public ServerOptionsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void StrictModeAcceptsTheKnownOptions()
    {
        var options = ServerOptions.Parse(new[] { "--read-only", "--root", _dir }, rejectUnknown: true);

        Assert.True(options.ReadOnly);
        Assert.Single(options.Roots);
    }

    [Fact]
    public void StrictModeAcceptsNoArguments()
    {
        var options = ServerOptions.Parse(Array.Empty<string>(), rejectUnknown: true);

        Assert.False(options.ReadOnly);
        Assert.Empty(options.Roots);
    }

    [Theory]
    [InlineData("--readonly")]
    [InlineData("--read_only")]
    [InlineData("--Read-Only")]
    [InlineData("-read-only")]
    [InlineData("--rooot")]
    [InlineData("--bogus")]
    [InlineData("stray-positional")]
    public void StrictModeRejectsUnknownOptionsInsteadOfIgnoringThem(string option)
    {
        var ex = Assert.Throws<ArgumentException>(() => ServerOptions.Parse(new[] { option }, rejectUnknown: true));

        Assert.Contains(option, ex.Message);
    }

    [Fact]
    public void AMisspeltFlagAmongValidOnesIsStillCaught()
    {
        // The dangerous case: the rest looks fine, so nothing else would reveal the missing restriction.
        Assert.Throws<ArgumentException>(() =>
            ServerOptions.Parse(new[] { "--root", _dir, "--readonly" }, rejectUnknown: true));
    }

    [Fact]
    public void ARootValueIsNotMistakenForAnUnknownOption()
    {
        var options = ServerOptions.Parse(new[] { "--root", _dir, "--read-only" }, rejectUnknown: true);

        Assert.Equal(Path.GetFullPath(_dir), options.Roots.Single());
    }

    [Fact]
    public void RootProblemsAreStillReportedInStrictMode()
    {
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(new[] { "--root" }, rejectUnknown: true));
        Assert.Throws<ArgumentException>(() =>
            ServerOptions.Parse(new[] { "--root", Path.Combine(_dir, "missing") }, rejectUnknown: true));
    }

    [Fact]
    public void DefaultModeStillSkipsOtherArgumentsForHostsThatValidateThemselves()
    {
        // CklMcp.Http passes its own options through this parser and checks them itself.
        var options = ServerOptions.Parse(new[] { "--port", "0", "--allow-remote", "--read-only" });

        Assert.True(options.ReadOnly);
    }
}

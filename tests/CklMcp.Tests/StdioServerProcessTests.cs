using System.Diagnostics;
using Xunit;

namespace CklMcp.Tests;

/// <summary>Runs the real stdio executable, since "the typo stops the server" is a process-level guarantee.</summary>
public sealed class StdioServerProcessTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    /// <summary>
    /// tests/CklMcp.Tests/bin/&lt;Config&gt;/&lt;tfm&gt;/  to  src/CklMcp.Server/bin/&lt;Config&gt;/&lt;tfm&gt;/CklMcp.Server.dll.
    /// The test project builds the server (a build-order-only project reference), in the same configuration.
    /// </summary>
    private static string ServerDll()
    {
        var output = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var tfm = output.Name;
        var config = output.Parent!.Name;
        var repo = output.Parent.Parent!.Parent!.Parent!.Parent!;

        var dll = Path.Combine(repo.FullName, "src", "CklMcp.Server", "bin", config, tfm, "CklMcp.Server.dll");
        Assert.True(File.Exists(dll), $"Server build not found at {dll}");
        return dll;
    }

    private static Process Start(params string[] serverArgs)
    {
        var info = new ProcessStartInfo("dotnet")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        info.ArgumentList.Add(ServerDll());
        foreach (var arg in serverArgs)
        {
            info.ArgumentList.Add(arg);
        }

        return Process.Start(info)!;
    }

    private static void Reap(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }

        process.Dispose();
    }

    [Theory]
    [InlineData("--readonly")]
    [InlineData("--rooot")]
    [InlineData("--bogus")]
    public async Task AnUnknownOptionStopsTheServerBeforeItServesAnything(string option)
    {
        var process = Start(option);
        try
        {
            var stderr = process.StandardError.ReadToEndAsync();
            var stdout = process.StandardOutput.ReadToEndAsync();
            Assert.True(process.WaitForExit(Limit), "Server should exit on its own, not keep running.");

            Assert.Equal(2, process.ExitCode);
            Assert.Contains($"Unknown option '{option}'", await stderr);
            Assert.Equal(string.Empty, await stdout); // stdout is the protocol channel: nothing may leak onto it
        }
        finally
        {
            Reap(process);
        }
    }

    [Fact]
    public async Task HelpPrintsUsageAndExitsCleanly()
    {
        var process = Start("--help");
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync();
            Assert.True(process.WaitForExit(Limit));

            Assert.Equal(0, process.ExitCode);
            var text = await stdout;
            Assert.Contains("--read-only", text);
            Assert.Contains("--root", text);
        }
        finally
        {
            Reap(process);
        }
    }

    [Fact]
    public async Task ValidOptionsStillStartAServerThatAnswersTheHandshake()
    {
        var process = Start("--read-only");
        try
        {
            await process.StandardInput.WriteLineAsync(
                """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}""");
            await process.StandardInput.FlushAsync();

            var reply = process.StandardOutput.ReadLineAsync();
            var finished = await Task.WhenAny(reply, Task.Delay(Limit));
            Assert.Same(reply, finished);

            Assert.Contains("\"ckl-mcp\"", await reply);
            Assert.False(process.HasExited);
        }
        finally
        {
            Reap(process);
        }
    }
}

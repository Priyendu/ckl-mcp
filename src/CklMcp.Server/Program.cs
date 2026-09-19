using CklMcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

if (args.Contains("-h") || args.Contains("--help"))
{
    // Nothing has started yet, so stdout is not carrying protocol messages.
    Console.WriteLine(ServerOptions.StdioUsage);
    return 0;
}

ServerOptions options;
try
{
    options = ServerOptions.Parse(args, rejectUnknown: true);
}
catch (ArgumentException ex)
{
    // Exit before serving anything: better a server that won't start than one that runs without
    // the restriction you thought you set.
    Console.Error.WriteLine($"error: {ex.Message}");
    Console.Error.WriteLine("Run with --help for usage.");
    return 2;
}

var builder = Host.CreateApplicationBuilder(args);

// Stdio transport: stdout carries protocol messages, so all logging must go to stderr.
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

builder.Services
    .AddCklMcpServer(options)
    .WithStdioServerTransport();

await builder.Build().RunAsync();
return 0;

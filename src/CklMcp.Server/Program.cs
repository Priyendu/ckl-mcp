using CklMcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var options = ServerOptions.Parse(args);

var builder = Host.CreateApplicationBuilder(args);

// Stdio transport: stdout carries protocol messages, so all logging must go to stderr.
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

builder.Services
    .AddCklMcpServer(options)
    .WithStdioServerTransport();

await builder.Build().RunAsync();

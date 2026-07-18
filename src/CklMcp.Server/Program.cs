using CklMcp.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var options = ServerOptions.Parse(args);

var builder = Host.CreateApplicationBuilder(args);

// Stdio transport: stdout carries protocol messages, so all logging must go to stderr.
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

builder.Services.AddSingleton(options);
builder.Services.AddSingleton<Workspace>();
builder.Services
    .AddMcpServer(o =>
    {
        o.ServerInfo = new()
        {
            Name = "ckl-mcp",
            Version = "0.1.0"
        };
        o.ServerInstructions =
            "Manage DISA STIG checklists (.ckl / .cklb). Typical flow: load_checklists (or " +
            "new_from_benchmark), get_summary to orient, list_findings with filters to locate work, " +
            "get_finding for full rule text, update_finding / bulk_update_findings to record results, " +
            "then save_checklist. Edits are held in memory until save_checklist is called.";
    })
    .WithStdioServerTransport()
    .WithTools<ChecklistTools>();

await builder.Build().RunAsync();

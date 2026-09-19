using Microsoft.Extensions.DependencyInjection;

namespace CklMcp.Tools;

public static class CklMcpServiceCollectionExtensions
{
    /// <summary>
    /// Registers the checklist tools, the shared <see cref="Workspace"/>, and the server identity.
    /// Each transport (stdio, HTTP) chains its own transport registration onto the result, so they
    /// all expose exactly the same tool surface.
    /// </summary>
    public static IMcpServerBuilder AddCklMcpServer(this IServiceCollection services, ServerOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<Workspace>();
        return services
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
            .WithTools<ChecklistTools>();
    }
}

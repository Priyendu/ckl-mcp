# ckl-mcp

An MCP (Model Context Protocol) server for DISA STIG checklists, built on the parsing engine of
[Ckl-viewer](https://github.com/Priyendu/Ckl-viewer). It lets any MCP-capable AI agent —
GitHub Copilot (VS Code agent mode), Claude Code, Claude Desktop, Cursor, and others — load,
query, edit, and save `.ckl` / `.cklb` checklists, apply SCAP scan results, and generate
Excel reports.

## How it works

The server speaks MCP over stdio. Checklists are loaded into an in-memory workspace (each gets an
id like `doc-1`), mirroring Ckl-viewer's merged multi-file view. Edits accumulate in memory and are
written back only when `save_checklist` is called; documents with unsaved changes are flagged and
protected from accidental close.

## Tools

| Tool | Purpose |
|---|---|
| `load_checklists` | Load `.ckl` / `.cklb` files (or XCCDF benchmarks) into the session |
| `new_from_benchmark` | Create a fresh Not Reviewed checklist from a DISA benchmark (.xml/.zip) |
| `list_checklists` | Loaded documents with summaries and unsaved-change flags |
| `close_checklists` | Remove documents (refuses to drop unsaved edits unless told to) |
| `get_summary` | Totals by status, open findings by CAT I/II/III, per-document breakdown |
| `list_findings` | Compact paged rows; filter by status / severity / STIG / document / free text |
| `get_finding` | Full rule detail: discussion, check content, fix text, CCIs, comments |
| `update_finding` | Set status, finding details, comments, severity override on one finding |
| `bulk_update_findings` | Same edits across many findings, selected by ids or filters |
| `update_asset` | Edit target-asset fields (host name, IP, MAC, FQDN, …) |
| `apply_xccdf_results` | Apply SCAP XCCDF scan results: pass/fail/notapplicable update matching findings |
| `merge_prior_assessment` | Carry a prior assessment into a new STIG release (flags or resets rules whose text changed) |
| `save_checklist` | Save in place, or save-as with `.ckl` ↔ `.cklb` format conversion |
| `export_excel_report` | Vulnerator-style workbook: Executive Summary, POA&M, Vulnerability Details |
| `compare_checklists` | Diff two checklists: status changes and added/removed findings |

## Build

Requires the .NET 8 SDK (or newer).

```
dotnet build
dotnet test
dotnet publish src/CklMcp.Server -c Release -o publish
```

## Server options

| Flag | Effect |
|---|---|
| `--read-only` | Disables every tool that edits findings or writes checklist files (report export stays available) |
| `--root <dir>` | Restrict all file access to this directory; repeatable. No roots = no restriction |

## Hooking it up

### VS Code / GitHub Copilot (agent mode)

`.vscode/mcp.json` in your workspace (or add via **MCP: Add Server**):

```json
{
  "servers": {
    "ckl": {
      "type": "stdio",
      "command": "dotnet",
      "args": ["run", "--project", "D:/work/ckl-mcp/src/CklMcp.Server", "--", "--root", "D:/checklists"]
    }
  }
}
```

For a published build, use the exe directly:

```json
{
  "servers": {
    "ckl": {
      "type": "stdio",
      "command": "D:/work/ckl-mcp/publish/CklMcp.Server.exe",
      "args": ["--root", "D:/checklists"]
    }
  }
}
```

### Claude Code

```
claude mcp add ckl -- D:/work/ckl-mcp/publish/CklMcp.Server.exe --root D:/checklists
```

### Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ckl": {
      "command": "D:/work/ckl-mcp/publish/CklMcp.Server.exe",
      "args": ["--root", "D:/checklists"]
    }
  }
}
```

## Example agent workflow

1. `load_checklists` with your host's `.ckl` files
2. `get_summary` — see open counts by CAT
3. `apply_xccdf_results` with the latest SCAP scan output
4. `list_findings` filtered to `NotReviewed`, then `get_finding` / `update_finding` to work through the rest
5. `save_checklist`, then `export_excel_report` for the POA&M workbook

## Credits and license

MIT. `src/CklMcp.Core` is sourced from [Ckl-viewer](https://github.com/Priyendu/Ckl-viewer)
(MIT, same author); the `CklViewer.*` namespaces are kept intact so upstream fixes can be
synced by copying files.

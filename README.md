# ckl-mcp

[![CI](https://github.com/Priyendu/ckl-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Priyendu/ckl-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io) (Model Context Protocol) server that lets an AI agent work
with **DISA STIG checklists** (`.ckl` / `.cklb`): load and query them, record findings, apply SCAP scan
results, carry a prior assessment into a new STIG release, and produce Excel reports.

> **Prefer a desktop app?** This is the agent-facing companion to
> **[Ckl-viewer](https://github.com/Priyendu/Ckl-viewer)**, the Windows UI for viewing and editing
> STIG checklists. Both share the same parsing and reporting engine, so files and Excel reports move
> freely between them.

It speaks MCP over **stdio**, so it works with any MCP-capable client: Claude, ChatGPT/Codex, Gemini,
GitHub Copilot, Cursor, and the client SDKs from all three model vendors. See
[Connect your model](#connect-your-model).

## What it can do

- **Load** `.ckl`, `.cklb`, DISA XCCDF benchmarks (`.xml`/`.zip`), and previously exported `.xlsx` reports.
- **Query** with the same filters as the Ckl-viewer UI (status, severity, STIG, free text), paged so
  a 400-rule STIG doesn't flood the model's context.
- **Edit** status, finding details, comments, severity overrides and asset fields, one finding at a
  time or in bulk. Edits stay in memory until you save.
- **Apply SCAP** XCCDF results, matching by rule version and rule id.
- **Merge a prior assessment** into a new STIG release, flagging or resetting rules whose text changed.
- **Save** in place or convert between `.ckl` and `.cklb`.
- **Report** to a Vulnerator-style Excel workbook (Executive Summary, POA&M, Vulnerability Details).
  Status and severity cells recolor themselves if you edit them in Excel, and the workbook can be
  loaded back in.
- **Diff** two checklists (what opened, what closed).

## Quick start

### 1. Get the server

**Download** the latest build from [Releases](https://github.com/Priyendu/ckl-mcp/releases) and unpack it.
Builds are published for Windows x64 (zip), Linux x64 and macOS Apple silicon (tar.gz). The
self-contained builds need nothing else; the Windows framework-dependent one needs the
[.NET 8 runtime](https://dotnet.microsoft.com/download/dotnet/8.0). On Linux and macOS you may need
`chmod +x CklMcp.Server`, and on macOS, `xattr -d com.apple.quarantine CklMcp.Server` because the
build is not code-signed. Any other platform (for example Intel Macs or Linux ARM) can build from source.

**Or build from source** (requires the .NET SDK, 8 or newer):

```
git clone https://github.com/Priyendu/ckl-mcp.git
cd ckl-mcp
dotnet publish src/CklMcp.Server -c Release -o publish
```

The server executable is `CklMcp.Server` (`CklMcp.Server.exe` on Windows). In the examples below,
replace `/path/to/CklMcp.Server` with the real location. Use forward slashes in JSON on Windows
(`C:/tools/ckl-mcp/CklMcp.Server.exe`) to avoid escaping.

### 2. Connect your model

Pick your client in the next section. The server takes no configuration to start. Two optional flags
are worth knowing about now:

| Flag | Effect |
|---|---|
| `--read-only` | Disables every tool that edits findings or writes checklist files (report export stays available). Good for analysis-only use. |
| `--root <dir>` | Restricts all file access to this directory; repeatable. Without it, the server can read and write any path the process can. |

### 3. Try it

Ask your assistant:

> Load `/path/to/host.ckl` and summarize it. Then list the open CAT I findings.

## Connect your model

MCP integration comes in two flavors. **This server works with the first today; the second needs an
HTTP transport that is not built yet** (see [Hosted API connectors](#hosted-api-connectors-not-yet)).

| Where the model runs | How it connects | Supported |
|---|---|---|
| Local app or CLI (Claude, Codex, Gemini CLI, Copilot, Cursor) | Launches this server as a subprocess over stdio | Yes |
| Your own code using a vendor SDK (Anthropic, OpenAI Agents, Google Gen AI) | Your code launches the subprocess and hands the tools to the model | Yes |
| Vendor-hosted MCP connector (OpenAI Responses API, Anthropic Messages API, ChatGPT / Claude.ai custom connectors) | The vendor's cloud calls your server over HTTPS | Not yet |

Tested by the maintainer while developing: **Claude Code** and **Codex** (desktop). The other
configurations below follow each vendor's current documentation but have not been exercised end to
end. If one doesn't work for you, please open an issue.

### Anthropic

**Claude Code**

```
claude mcp add ckl --scope user -- /path/to/CklMcp.Server
```

Add `--root /path/to/checklists` (and/or `--read-only`) after the executable to restrict it.

**Claude Desktop**: edit `claude_desktop_config.json` (Settings, Developer, Edit Config):

```json
{
  "mcpServers": {
    "ckl": {
      "command": "/path/to/CklMcp.Server",
      "args": ["--root", "/path/to/checklists"]
    }
  }
}
```

**Anthropic API, your own code** ([client-side MCP helpers](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector#client-side-mcp-helpers)),
Python, `pip install "anthropic[mcp]"`:

```python
import asyncio
from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

client = AsyncAnthropic()

async def main():
    params = StdioServerParameters(command="/path/to/CklMcp.Server", args=["--read-only"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as mcp:
            await mcp.initialize()
            tools = (await mcp.list_tools()).tools
            runner = client.beta.messages.tool_runner(
                model="claude-sonnet-5",
                max_tokens=2048,
                messages=[{"role": "user", "content": "Load /path/to/host.ckl and summarize it."}],
                tools=[async_mcp_tool(t, mcp) for t in tools],
            )
            print(await runner.until_done())

asyncio.run(main())
```

### OpenAI

**Codex** (CLI and desktop app) reads `~/.codex/config.toml`. Either run:

```
codex mcp add ckl -- /path/to/CklMcp.Server
```

or add the table yourself (use single quotes for Windows paths so backslashes stay literal):

```toml
[mcp_servers.ckl]
command = '/path/to/CklMcp.Server'
args = ['--root', '/path/to/checklists']
startup_timeout_sec = 30
```

Restart Codex after editing the file; it reads MCP configuration at startup.

**OpenAI Agents SDK, your own code** (`pip install openai-agents`):

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    async with MCPServerStdio(
        name="ckl",
        params={"command": "/path/to/CklMcp.Server", "args": ["--read-only"]},
    ) as server:
        agent = Agent(
            name="STIG assistant",
            instructions="Use the ckl tools to answer questions about STIG checklists.",
            mcp_servers=[server],
        )
        result = await Runner.run(agent, "Load /path/to/host.ckl and summarize it.")
        print(result.final_output)

asyncio.run(main())
```

### Google

**Gemini CLI** reads `~/.gemini/settings.json` (user) or `.gemini/settings.json` (project):

```json
{
  "mcpServers": {
    "ckl": {
      "command": "/path/to/CklMcp.Server",
      "args": ["--root", "/path/to/checklists"],
      "timeout": 60000
    }
  }
}
```

**Gemini API, your own code** (`pip install google-genai mcp`; the SDK's MCP support is marked
experimental by Google):

```python
import asyncio
from google import genai
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

client = genai.Client()
params = StdioServerParameters(command="/path/to/CklMcp.Server", args=["--read-only"])

async def main():
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            response = await client.aio.models.generate_content(
                model="gemini-2.5-flash",
                contents="Load /path/to/host.ckl and summarize it.",
                config=genai.types.GenerateContentConfig(tools=[session]),
            )
            print(response.text)

asyncio.run(main())
```

### GitHub Copilot, Cursor, and other MCP clients

**VS Code (GitHub Copilot agent mode)**: `.vscode/mcp.json` in your workspace, or run
**MCP: Add Server**:

```json
{
  "servers": {
    "ckl": {
      "type": "stdio",
      "command": "/path/to/CklMcp.Server",
      "args": ["--root", "/path/to/checklists"]
    }
  }
}
```

**Cursor**: `~/.cursor/mcp.json` uses the same shape as Claude Desktop (`"mcpServers": { "ckl": { "command": ..., "args": [...] } }`).

Any other MCP client that can launch a stdio server takes the same three things: a command, its
arguments, and (optionally) environment variables.

### Hosted API connectors (not yet)

The [OpenAI Responses API](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) and
the [Anthropic Messages API MCP connector](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector)
run in the vendor's cloud and can only reach **remote HTTPS** MCP servers, so a local stdio process
can't be attached to them. An opt-in Streamable HTTP transport (loopback by default, bearer-token
auth) is planned. Until then, use the client-side SDK routes above, which give API access to models
from all three vendors.

## Tools

| Tool | Purpose |
|---|---|
| `load_checklists` | Load `.ckl` / `.cklb` files, XCCDF benchmarks, or an exported `.xlsx` report (one document per asset) |
| `new_from_benchmark` | Create a fresh Not Reviewed checklist from a DISA benchmark (`.xml`/`.zip`) |
| `list_checklists` | Loaded documents with summaries and unsaved-change flags |
| `close_checklists` | Remove documents (refuses to drop unsaved edits unless told to) |
| `get_summary` | Totals by status, open findings by CAT I/II/III, per-document breakdown |
| `list_findings` | Compact paged rows; filter by status / severity / STIG / document / free text |
| `get_finding` | Full rule detail: discussion, check content, fix text, CCIs, comments, internal notes |
| `update_finding` | Set status, finding details, comments, severity override, or internal notes on one finding |
| `bulk_update_findings` | Same edits across many findings, selected by ids or filters |
| `update_asset` | Edit target-asset fields (host name, IP, MAC, FQDN, ...) |
| `apply_xccdf_results` | Apply SCAP results: pass, fail and notapplicable update matching findings |
| `merge_prior_assessment` | Carry a prior assessment into a new STIG release (flags or resets rules whose text changed) |
| `save_checklist` | Save in place, or save-as with `.ckl` / `.cklb` format conversion |
| `export_excel_report` | Executive Summary, POA&M and Vulnerability Details workbook; optional Internal Notes column |
| `compare_checklists` | Diff two checklists: status changes and added/removed findings |

## Working safely

- **Work on copies at first.** Edit tools change what `save_checklist` writes. Until you trust the
  workflow, point the server at copies, or start it with `--read-only`.
- **Edits are held in memory** until `save_checklist`. Unsaved documents are flagged, and
  `close_checklists` refuses to discard them unless told to.
- **Scope file access** with `--root`. Without it, an agent can be handed any path.
- **Checklists can be sensitive.** They describe real systems and their weaknesses, and the default
  asset marking is `CUI`. Anything a tool returns is sent to whichever model provider you connected.
  Check your organization's rules before pointing a hosted model at real checklists. Anthropic's
  hosted MCP connector, for example, is not covered by zero-data-retention terms. Use only data you
  are cleared to share with that provider.

## Internal notes

Findings can carry a team-only `internalNotes` field (set with `update_finding` / `bulk_update_findings`,
read with `get_finding`). It **never** travels in `.ckl` or `.cklb`, since those formats have no such
field and the notes aren't meant to leave the team. It appears as the last column of the
Vulnerability Details sheet in `export_excel_report` (on by default; pass `includeInternalNotes: false`
for a report that will be shared). Loading that `.xlsx` back in restores the notes, so they survive
an export, hand-edit and reimport loop. They are dropped whenever a checklist is saved as
`.ckl` / `.cklb`.

## Example workflow

1. `load_checklists` with your host's `.ckl` files
2. `get_summary` to see open counts by CAT
3. `apply_xccdf_results` with the latest SCAP scan output
4. `list_findings` filtered to `NotReviewed`, then `get_finding` / `update_finding` to work through the rest
5. `save_checklist`, then `export_excel_report` for the POA&M workbook

**New STIG release?** `new_from_benchmark` with the new benchmark, load last cycle's checklist, then
`merge_prior_assessment` to carry your work forward.

## Development

```
dotnet build
dotnet test
```

Layout:

```
src/CklMcp.Core/     parsing, writing, reporting (shared engine, from Ckl-viewer)
src/CklMcp.Server/   the MCP server (stdio)
tests/CklMcp.Tests/  engine tests plus tool-level tests
```

`src/CklMcp.Core` is kept in step with [Ckl-viewer](https://github.com/Priyendu/Ckl-viewer): the
`CklViewer.*` namespaces are unchanged, so upstream fixes are synced by copying files. Bug reports and
pull requests are welcome; parsing or reporting changes generally belong in Ckl-viewer first.

To report a security problem, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Third-party components are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
Ckl-viewer, the source of the core engine, is also MIT-licensed and by the same author.

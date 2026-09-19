# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**. Please don't open a public issue for anything exploitable.

Include what you found, how to reproduce it, and the version or commit you tested. You'll get an
acknowledgement, and a fix or a mitigation plan as soon as reasonably possible. This is a small
volunteer-maintained project, so there is no guaranteed response time.

## Supported versions

Only the latest release receives fixes.

## What this server can do (threat model)

ckl-mcp is a local process that a trusted MCP client launches over stdio. It can **read and write files
the process can access**, because loading, saving and exporting checklists is its job. Keep that in
mind when deciding what to connect it to:

- **Scope it.** `--root <dir>` (repeatable) restricts all file access to those directories. Without
  it, whatever the model asks for is allowed, including paths outside your checklist folder.
- **Limit it.** `--read-only` disables every tool that edits findings or writes checklist files.
- **Checklist content is data.** Rule text, finding details and comments are returned to the model
  verbatim. A checklist from an untrusted source can contain text that tries to steer the model
  (prompt injection). Review edits the agent proposes, especially bulk updates, before saving, and
  prefer `--read-only` when analyzing files you did not create.
- **Sensitive data.** Checklists can describe real systems and their weaknesses. Whatever the server
  returns goes to the model provider you connected.

## In scope

- Path handling that escapes `--root`
- Unsafe parsing of `.ckl` (XML), `.cklb` (JSON), XCCDF/`.zip` benchmarks, or `.xlsx` files, such as
  XXE, zip-slip, or resource exhaustion from crafted input
- Anything that makes the server write outside the paths a caller asked for

## Out of scope

- Behavior of the connected model or client
- Running the server with no `--root` and being able to access files (this is the documented default)
- Vulnerabilities in third-party dependencies with no exploitable path through this project
  (report those upstream)

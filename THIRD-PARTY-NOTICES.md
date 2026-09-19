# Third-party notices

ckl-mcp is released under the [MIT License](LICENSE). It builds on the following components, which are
distributed under their own licenses. Versions are those resolved at the time of writing; run
`dotnet list src/CklMcp.Server package --include-transitive` for the current set.

## Ckl-viewer

`src/CklMcp.Core` is derived from [Ckl-viewer](https://github.com/Priyendu/Ckl-viewer) (MIT,
Copyright (c) 2026 Priyendu, the same author as this project).

## Apache License 2.0

The full license text is at <https://www.apache.org/licenses/LICENSE-2.0>.

| Package | Version | Project |
|---|---|---|
| ModelContextProtocol | 2.0.0-preview.3 | <https://github.com/modelcontextprotocol/csharp-sdk> |
| ModelContextProtocol.Core | 2.0.0-preview.3 | <https://github.com/modelcontextprotocol/csharp-sdk> |
| ModelContextProtocol.AspNetCore (only in the `CklMcp.Http` executable) | 2.0.0-preview.3 | <https://github.com/modelcontextprotocol/csharp-sdk> |
| SixLabors.Fonts | 1.0.0 | <https://github.com/SixLabors/Fonts> |

## MIT License

| Package | Version |
|---|---|
| ClosedXML | 0.104.2 |
| ClosedXML.Parser | 1.2.0 |
| DocumentFormat.OpenXml, DocumentFormat.OpenXml.Framework | 3.1.1 |
| ExcelNumberFormat | 1.1.0 |
| RBush | 4.0.0 |
| System.IO.Packaging | 8.0.1 |
| Microsoft.Extensions.Hosting, .Configuration, .DependencyInjection, .Logging, .Options and related `Microsoft.Extensions.*` packages | 10.0.x |
| Microsoft.Extensions.AI.Abstractions | 10.5.2 |
| System.Diagnostics.DiagnosticSource, System.Diagnostics.EventLog, System.IO.Pipelines, System.Net.ServerSentEvents, System.Text.Encodings.Web, System.Text.Json | 10.0.x |

The `CklMcp.Http` executable additionally uses the ASP.NET Core shared framework (MIT,
Copyright (c) .NET Foundation and Contributors), which ships with the .NET runtime and is bundled into
its self-contained builds.

Each package's own license text and copyright notice is published with it on
[nuget.org](https://www.nuget.org/) and is included in its `.nupkg`.

## Test-only dependencies

xUnit and the .NET test SDK are used to run tests and are not part of the shipped server.

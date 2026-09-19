using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Serialization;
using CklViewer.Merging;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Reports;
using CklViewer.Writing;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace CklMcp.Tools;

[McpServerToolType]
public sealed class ChecklistTools(Workspace workspace, ServerOptions options)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private const int DefaultPageSize = 50;
    private const int MaxPageSize = 200;

    // ---------------------------------------------------------------- loading

    [McpServerTool(Name = "load_checklists")]
    [Description("Load one or more DISA STIG checklist files into the session: .ckl, .cklb, an XCCDF " +
                 "benchmark (imported as a fresh Not Reviewed checklist), or a previously exported " +
                 ".xlsx report (re-imported from its Vulnerability Details sheet, so edits made in " +
                 "Excel can be saved back as .ckl/.cklb â€” one document per asset in the workbook). " +
                 "Returns a document id and summary for each loaded checklist.")]
    public string LoadChecklists(
        [Description("Absolute or relative paths of .ckl / .cklb / .xlsx files to load.")] string[] paths)
    {
        if (paths is null || paths.Length == 0)
        {
            throw new McpException("At least one path is required.");
        }

        lock (workspace.SyncRoot)
        {
            var loaded = new List<object>();
            foreach (var path in paths)
            {
                var full = options.ValidateReadPath(path);
                IReadOnlyList<ChecklistDocument> documents;
                try
                {
                    documents = ChecklistLoader.LoadAll(full);
                }
                catch (Exception ex) when (ex is not McpException)
                {
                    throw new McpException($"Failed to parse '{full}': {ex.Message}");
                }

                foreach (var document in documents)
                {
                    var entry = workspace.Add(document, dirty: document.SourcePath is null);
                    loaded.Add(DocumentSummary(entry));
                }
            }

            return JsonSerializer.Serialize(loaded, Json);
        }
    }

    [McpServerTool(Name = "new_from_benchmark")]
    [Description("Create a new checklist from a DISA STIG benchmark file (XCCDF .xml or .zip). " +
                 "Every rule starts as Not Reviewed. The checklist exists only in memory until " +
                 "save_checklist is called with a path.")]
    public string NewFromBenchmark(
        [Description("Path to the DISA benchmark (.xml or .zip).")] string path,
        [Description("Optional host name to set on the new checklist's asset.")] string? hostName = null)
    {
        options.RequireWritable("new_from_benchmark");
        var full = options.ValidateReadPath(path);

        lock (workspace.SyncRoot)
        {
            ChecklistDocument document;
            try
            {
                document = XccdfBenchmarkParser.ParseFile(full);
            }
            catch (Exception ex) when (ex is not McpException)
            {
                throw new McpException($"Failed to parse benchmark '{full}': {ex.Message}");
            }

            document.SourcePath = null; // force an explicit save path; never overwrite the benchmark
            if (!string.IsNullOrWhiteSpace(hostName))
            {
                document.Asset.HostName = hostName;
            }

            var entry = workspace.Add(document, dirty: true);
            return JsonSerializer.Serialize(DocumentSummary(entry), Json);
        }
    }

    [McpServerTool(Name = "list_checklists")]
    [Description("List the checklists currently loaded in the session, with per-document summaries " +
                 "and whether each has unsaved changes.")]
    public string ListChecklists()
    {
        lock (workspace.SyncRoot)
        {
            return JsonSerializer.Serialize(
                workspace.Documents.Select(DocumentSummary), Json);
        }
    }

    [McpServerTool(Name = "close_checklists")]
    [Description("Remove checklists from the session. Refuses to close documents with unsaved " +
                 "changes unless discard_unsaved is true.")]
    public string CloseChecklists(
        [Description("Document ids to close. Omit to close all.")] string[]? documentIds = null,
        [Description("Set true to discard unsaved changes.")] bool discardUnsaved = false)
    {
        lock (workspace.SyncRoot)
        {
            var targets = documentIds is { Length: > 0 }
                ? documentIds.Select(workspace.GetRequired).ToList()
                : workspace.Documents.ToList();

            var dirty = targets.Where(t => t.Dirty).Select(t => t.Id).ToList();
            if (dirty.Count > 0 && !discardUnsaved)
            {
                throw new McpException(
                    $"Unsaved changes in: {string.Join(", ", dirty)}. Call save_checklist first, " +
                    "or pass discard_unsaved=true to drop the edits.");
            }

            foreach (var target in targets)
            {
                workspace.Remove(target);
            }

            return JsonSerializer.Serialize(new { closed = targets.Select(t => t.Id) }, Json);
        }
    }

    // ---------------------------------------------------------------- reading

    [McpServerTool(Name = "get_summary")]
    [Description("Compliance overview of all loaded checklists: totals by status, open findings " +
                 "by CAT severity, and a per-document breakdown. Call this first to orient.")]
    public string GetSummary()
    {
        lock (workspace.SyncRoot)
        {
            var all = workspace.Documents.SelectMany(d => d.Document.AllVulnerabilities).ToList();
            var result = new
            {
                checklists = workspace.Documents.Count,
                totalFindings = all.Count,
                byStatus = StatusCounts(all),
                openByCategory = new
                {
                    catI = all.Count(v => v.Status == FindingStatus.Open && v.Category == "CAT I"),
                    catII = all.Count(v => v.Status == FindingStatus.Open && v.Category == "CAT II"),
                    catIII = all.Count(v => v.Status == FindingStatus.Open && v.Category == "CAT III")
                },
                documents = workspace.Documents.Select(DocumentSummary)
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    [McpServerTool(Name = "list_findings")]
    [Description("List findings as compact rows with paging. Filter by status, severity, STIG, " +
                 "document, or free-text search â€” the same filters as the Ckl-viewer UI. Use " +
                 "get_finding for the full rule text of a single finding.")]
    public string ListFindings(
        [Description("Filter to one document id (e.g. doc-1). Omit for all loaded checklists.")]
        string? documentId = null,
        [Description("Filter by status: Open, NotAFinding, NotApplicable, or NotReviewed.")]
        string? status = null,
        [Description("Filter by severity: high/medium/low or CAT I/CAT II/CAT III.")]
        string? severity = null,
        [Description("Filter by STIG: substring match on STIG id or title.")]
        string? stig = null,
        [Description("Case-insensitive search across id, title, discussion, check/fix text, CCIs, " +
                     "details, and comments.")]
        string? search = null,
        [Description("1-based page number (default 1).")] int page = 1,
        [Description("Rows per page, max 200 (default 50).")]
        int pageSize = DefaultPageSize)
    {
        lock (workspace.SyncRoot)
        {
            var rows = Filter(documentId, status, severity, stig, search).ToList();

            pageSize = Math.Clamp(pageSize, 1, MaxPageSize);
            page = Math.Max(page, 1);
            var totalPages = Math.Max(1, (int)Math.Ceiling(rows.Count / (double)pageSize));

            var result = new
            {
                total = rows.Count,
                page,
                totalPages,
                findings = rows
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(r => new
                    {
                        documentId = r.Entry.Id,
                        vulnId = r.Vuln.VulnId,
                        ruleVersion = NullIfEmpty(r.Vuln.RuleVersion),
                        title = r.Vuln.RuleTitle,
                        status = r.Vuln.Status.ToString(),
                        category = r.Vuln.Category
                    })
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    [McpServerTool(Name = "get_finding")]
    [Description("Full detail for one finding: rule discussion, check content, fix text, CCIs, and " +
                 "the current status, details, and comments.")]
    public string GetFinding(
        [Description("V-key (V-220697), rule id, or rule version (WN10-00-000005).")] string vulnId,
        [Description("Document id, required only when the id matches several loaded checklists.")]
        string? documentId = null)
    {
        lock (workspace.SyncRoot)
        {
            var (entry, v) = workspace.ResolveFinding(vulnId, documentId);
            var result = new
            {
                documentId = entry.Id,
                hostName = NullIfEmpty(entry.Document.Asset.HostName),
                stig = entry.Document.Stigs
                    .FirstOrDefault(s => s.Vulnerabilities.Contains(v))?.Title,
                vulnId = v.VulnId,
                ruleId = NullIfEmpty(v.RuleId),
                ruleVersion = NullIfEmpty(v.RuleVersion),
                title = v.RuleTitle,
                status = v.Status.ToString(),
                severity = v.SeverityValue,
                severityOverride = NullIfEmpty(v.SeverityOverride),
                severityJustification = NullIfEmpty(v.SeverityJustification),
                category = v.Category,
                ccis = v.Ccis,
                legacyIds = v.LegacyIds,
                discussion = v.Discussion,
                checkContent = v.CheckContent,
                fixText = v.FixText,
                findingDetails = v.FindingDetails,
                comments = v.Comments,
                internalNotes = NullIfEmpty(v.InternalNotes)
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    // ---------------------------------------------------------------- editing

    [McpServerTool(Name = "update_finding")]
    [Description("Update one finding. Only the provided fields change; text fields replace the " +
                 "existing value (read with get_finding first to append). Edits stay in memory " +
                 "until save_checklist.")]
    public string UpdateFinding(
        [Description("V-key (V-220697), rule id, or rule version.")] string vulnId,
        [Description("Document id, required only when the id is ambiguous across checklists.")]
        string? documentId = null,
        [Description("New status: Open, NotAFinding, NotApplicable, or NotReviewed.")]
        string? status = null,
        [Description("Replacement Finding Details text.")] string? findingDetails = null,
        [Description("Replacement Comments text.")] string? comments = null,
        [Description("Severity override: high, medium, or low. Pass an empty string to clear.")]
        string? severityOverride = null,
        [Description("Justification for the severity override.")] string? severityJustification = null,
        [Description("Replacement team-internal notes. Never written to .ckl/.cklb; only appears " +
                     "in Excel reports when export_excel_report's include_internal_notes is true " +
                     "(the default).")]
        string? internalNotes = null)
    {
        options.RequireWritable("update_finding");
        lock (workspace.SyncRoot)
        {
            var (entry, v) = workspace.ResolveFinding(vulnId, documentId);
            ApplyEdits(v, status, findingDetails, comments, severityOverride, severityJustification, internalNotes);
            entry.Dirty = true;

            var result = new
            {
                documentId = entry.Id,
                vulnId = v.VulnId,
                status = v.Status.ToString(),
                category = v.Category,
                findingDetails = v.FindingDetails,
                comments = v.Comments,
                severityOverride = NullIfEmpty(v.SeverityOverride),
                internalNotes = NullIfEmpty(v.InternalNotes),
                unsavedChanges = true
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    [McpServerTool(Name = "bulk_update_findings")]
    [Description("Update many findings in one call. Select them either by an explicit vuln_ids list " +
                 "or by filters (status/severity/stig/search, same semantics as list_findings); at " +
                 "least one selector is required, as is at least one field to set. Example: mark " +
                 "every Not Reviewed finding of a STIG as Not Applicable with a comment.")]
    public string BulkUpdateFindings(
        [Description("Explicit V-keys to update. Alternative to the filter parameters.")]
        string[]? vulnIds = null,
        [Description("Limit the operation to one document id.")] string? documentId = null,
        [Description("Select findings currently in this status.")] string? whereStatus = null,
        [Description("Select findings of this severity (high/medium/low or CAT I/II/III).")]
        string? whereSeverity = null,
        [Description("Select findings whose STIG id or title contains this text.")]
        string? whereStig = null,
        [Description("Select findings matching this free-text search.")] string? whereSearch = null,
        [Description("Status to set: Open, NotAFinding, NotApplicable, or NotReviewed.")]
        string? setStatus = null,
        [Description("Finding Details text to set on every selected finding.")]
        string? setFindingDetails = null,
        [Description("Comments text to set on every selected finding.")] string? setComments = null,
        [Description("Team-internal notes to set on every selected finding. Never written to " +
                     ".ckl/.cklb.")]
        string? setInternalNotes = null)
    {
        options.RequireWritable("bulk_update_findings");
        if (setStatus is null && setFindingDetails is null && setComments is null && setInternalNotes is null)
        {
            throw new McpException(
                "Nothing to do: provide set_status, set_finding_details, set_comments, or set_internal_notes.");
        }

        var hasFilter = whereStatus is not null || whereSeverity is not null ||
                        whereStig is not null || whereSearch is not null;
        if (vulnIds is not { Length: > 0 } && !hasFilter)
        {
            throw new McpException(
                "Refusing to update everything: provide vuln_ids or at least one where_* filter. " +
                "To really select all findings of a document, pass its document_id plus a filter " +
                "such as where_search=''.");
        }

        lock (workspace.SyncRoot)
        {
            List<(LoadedChecklist Entry, Vulnerability Vuln)> targets;
            if (vulnIds is { Length: > 0 })
            {
                targets = vulnIds.Select(id => workspace.ResolveFinding(id, documentId)).ToList();
            }
            else
            {
                targets = Filter(documentId, whereStatus, whereSeverity, whereStig, whereSearch).ToList();
            }

            foreach (var (entry, v) in targets)
            {
                ApplyEdits(v, setStatus, setFindingDetails, setComments, null, null, setInternalNotes);
                entry.Dirty = true;
            }

            var result = new
            {
                updated = targets.Count,
                documents = targets.Select(t => t.Entry.Id).Distinct(),
                vulnIds = targets.Select(t => t.Vuln.VulnId).Take(100),
                unsavedChanges = targets.Count > 0
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    [McpServerTool(Name = "update_asset")]
    [Description("Update the target-asset fields of a checklist (host name, IP, MAC, FQDN, etc.).")]
    public string UpdateAsset(
        [Description("Document id. Optional when exactly one checklist is loaded.")]
        string? documentId = null,
        string? hostName = null,
        string? hostIp = null,
        string? hostMac = null,
        string? hostFqdn = null,
        [Description("Free-text target comment.")] string? targetComment = null,
        [Description("Asset role, e.g. None, Member Server, Workstation.")] string? role = null,
        [Description("Classification marking, e.g. CUI.")] string? marking = null,
        string? techArea = null,
        [Description("True when the asset is a web or database instance.")] bool? webOrDatabase = null,
        string? webDbSite = null,
        string? webDbInstance = null)
    {
        options.RequireWritable("update_asset");
        lock (workspace.SyncRoot)
        {
            var entry = workspace.ResolveDocument(documentId);
            var asset = entry.Document.Asset;

            if (hostName is not null) asset.HostName = hostName;
            if (hostIp is not null) asset.HostIp = hostIp;
            if (hostMac is not null) asset.HostMac = hostMac;
            if (hostFqdn is not null) asset.HostFqdn = hostFqdn;
            if (targetComment is not null) asset.TargetComment = targetComment;
            if (role is not null) asset.Role = role;
            if (marking is not null) asset.Marking = marking;
            if (techArea is not null) asset.TechArea = techArea;
            if (webOrDatabase is not null) asset.WebOrDatabase = webOrDatabase.Value;
            if (webDbSite is not null) asset.WebDbSite = webDbSite;
            if (webDbInstance is not null) asset.WebDbInstance = webDbInstance;

            entry.Dirty = true;
            return JsonSerializer.Serialize(DocumentSummary(entry), Json);
        }
    }

    // ---------------------------------------------------------------- automation

    [McpServerTool(Name = "apply_xccdf_results")]
    [Description("Apply SCAP scan results (XCCDF result XML) to loaded checklists: pass marks the " +
                 "finding Not a Finding, fail marks it Open, notapplicable marks it Not Applicable; " +
                 "other results leave the finding untouched. A timestamped note is appended to " +
                 "Finding Details. Reports matched/updated counts per file and checklist.")]
    public string ApplyXccdfResults(
        [Description("Paths of XCCDF result files to apply.")] string[] paths,
        [Description("Apply to this document only. Omit to apply to every loaded checklist.")]
        string? documentId = null)
    {
        options.RequireWritable("apply_xccdf_results");
        if (paths is null || paths.Length == 0)
        {
            throw new McpException("At least one XCCDF result path is required.");
        }

        lock (workspace.SyncRoot)
        {
            var targets = documentId is null
                ? workspace.Documents.ToList()
                : new List<LoadedChecklist> { workspace.GetRequired(documentId) };
            if (targets.Count == 0)
            {
                throw new McpException("No checklists are loaded. Call load_checklists first.");
            }

            var outcomes = new List<object>();
            foreach (var path in paths)
            {
                var full = options.ValidateReadPath(path);
                foreach (var entry in targets)
                {
                    XccdfApplyOutcome outcome;
                    try
                    {
                        outcome = XccdfResultApplier.Apply(entry.Document, full);
                    }
                    catch (Exception ex) when (ex is not McpException)
                    {
                        throw new McpException($"Failed to apply '{full}': {ex.Message}");
                    }

                    if (outcome.Updated > 0)
                    {
                        entry.Dirty = true;
                    }

                    outcomes.Add(new
                    {
                        file = Path.GetFileName(full),
                        documentId = entry.Id,
                        benchmarkId = outcome.BenchmarkId,
                        scanResults = outcome.TotalResults,
                        matched = outcome.Matched,
                        updated = outcome.Updated
                    });
                }
            }

            return JsonSerializer.Serialize(outcomes, Json);
        }
    }

    [McpServerTool(Name = "save_checklist")]
    [Description("Write a checklist back to disk. With no path, saves to the file it was loaded " +
                 "from in its original format. With a path, does save-as â€” the extension (.ckl or " +
                 ".cklb) picks the format, so this also converts between formats â€” and future saves " +
                 "target the new file.")]
    public string SaveChecklist(
        [Description("Document id. Optional when exactly one checklist is loaded.")]
        string? documentId = null,
        [Description("Target path for save-as (.ckl or .cklb). Required for checklists created " +
                     "from a benchmark.")]
        string? path = null,
        [Description("Explicit format override: ckl or cklb. Defaults to the path extension.")]
        string? format = null)
    {
        options.RequireWritable("save_checklist");
        lock (workspace.SyncRoot)
        {
            var entry = workspace.ResolveDocument(documentId);
            var document = entry.Document;

            var targetPath = path is not null
                ? options.ValidateWritePath(path)
                : document.SourcePath
                  ?? throw new McpException(
                      $"{entry.Id} has no source file (created from a benchmark); provide a path.");

            var targetFormat = format?.Trim().ToLowerInvariant() switch
            {
                "ckl" => ChecklistFormat.Ckl,
                "cklb" => ChecklistFormat.Cklb,
                null or "" => path is not null
                    ? Path.GetExtension(targetPath).ToLowerInvariant() switch
                    {
                        ".ckl" => ChecklistFormat.Ckl,
                        ".cklb" or ".json" => ChecklistFormat.Cklb,
                        var ext => throw new McpException(
                            $"Cannot infer format from extension '{ext}'; use .ckl or .cklb, " +
                            "or pass format explicitly.")
                    }
                    : document.SourceFormat,
                var other => throw new McpException($"Unknown format '{other}'; use ckl or cklb.")
            };

            if (targetFormat == ChecklistFormat.Ckl)
            {
                CklWriter.WriteFile(document, targetPath);
            }
            else
            {
                CklbWriter.WriteFile(document, targetPath);
            }

            document.SourcePath = targetPath;
            document.SourceFormat = targetFormat;
            entry.Dirty = false;

            return JsonSerializer.Serialize(new
            {
                documentId = entry.Id,
                savedTo = targetPath,
                format = targetFormat.ToString().ToLowerInvariant()
            }, Json);
        }
    }

    [McpServerTool(Name = "export_excel_report")]
    [Description("Generate the Vulnerator-style Excel workbook (Executive Summary, POA&M, and " +
                 "Vulnerability Details tabs) covering the selected checklists. Status and Severity " +
                 "cells use Excel conditional formatting, so their color tracks the cell text even " +
                 "after a manual edit in Excel. Allowed even in read-only mode, since it never " +
                 "modifies checklist files.")]
    public string ExportExcelReport(
        [Description("Output .xlsx path.")] string path,
        [Description("Document ids to include. Omit to include all loaded checklists.")]
        string[]? documentIds = null,
        [Description("Append a team-only \"Internal Notes\" column at the end of the Vulnerability " +
                     "Details sheet. On by default; set false to produce a report meant to leave " +
                     "the team, since this data is never written to .ckl/.cklb either way.")]
        bool includeInternalNotes = true)
    {
        lock (workspace.SyncRoot)
        {
            var targets = documentIds is { Length: > 0 }
                ? documentIds.Select(workspace.GetRequired).ToList()
                : workspace.Documents.ToList();
            if (targets.Count == 0)
            {
                throw new McpException("No checklists are loaded. Call load_checklists first.");
            }

            var full = options.ValidateWritePath(path);
            if (!full.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase))
            {
                full += ".xlsx";
            }

            ExcelReportGenerator.WriteReport(targets.Select(t => t.Document).ToList(), full,
                includeInternalNotes: includeInternalNotes);

            return JsonSerializer.Serialize(new
            {
                savedTo = full,
                checklists = targets.Select(t => t.Id),
                includeInternalNotes
            }, Json);
        }
    }

    [McpServerTool(Name = "merge_prior_assessment")]
    [Description("Carry a prior assessment forward into a new STIG release. The target checklist " +
                 "(typically freshly created via new_from_benchmark) keeps its rule set; the source " +
                 "checklist supplies status, finding details, comments, and severity overrides, " +
                 "matched by rule version, then V-key, then legacy IDs. Rules whose check/fix text " +
                 "changed between versions get an audit note â€” or are reset to Not Reviewed when " +
                 "reset_changed_rules is true. The target is modified in memory; save_checklist persists it.")]
    public string MergePriorAssessment(
        [Description("Document id of the new-version checklist to merge into.")] string targetDocumentId,
        [Description("Document id of the prior assessment supplying statuses and notes.")]
        string sourceDocumentId,
        [Description("Reset findings whose rule text changed to Not Reviewed instead of carrying " +
                     "their status with a re-verify note (default false).")]
        bool resetChangedRules = false)
    {
        options.RequireWritable("merge_prior_assessment");
        lock (workspace.SyncRoot)
        {
            var target = workspace.GetRequired(targetDocumentId);
            var source = workspace.GetRequired(sourceDocumentId);
            if (ReferenceEquals(target, source))
            {
                throw new McpException("target_document_id and source_document_id must differ.");
            }

            var outcome = ChecklistMerger.Merge(target.Document, source.Document, resetChangedRules);
            target.Dirty = true;

            var result = new
            {
                targetDocumentId = target.Id,
                sourceDocumentId = source.Id,
                carried = outcome.Carried,
                unchangedRuleText = outcome.Unchanged,
                changedRuleText = outcome.Changed,
                newRules = outcome.NewRules,
                removedRules = outcome.Removed,
                resetChangedRules,
                unsavedChanges = true
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    [McpServerTool(Name = "compare_checklists")]
    [Description("Diff two loaded checklists by V-key â€” e.g. last month's assessment vs. a fresh " +
                 "scan of the same STIG. Reports findings whose status changed plus findings that " +
                 "exist in only one of the two.")]
    public string CompareChecklists(
        [Description("Baseline document id.")] string documentIdA,
        [Description("Comparison document id.")] string documentIdB)
    {
        lock (workspace.SyncRoot)
        {
            var a = workspace.GetRequired(documentIdA);
            var b = workspace.GetRequired(documentIdB);

            var mapA = a.Document.AllVulnerabilities.ToDictionary(v => v.VulnId, StringComparer.OrdinalIgnoreCase);
            var mapB = b.Document.AllVulnerabilities.ToDictionary(v => v.VulnId, StringComparer.OrdinalIgnoreCase);

            var changed = mapA.Values
                .Where(v => mapB.TryGetValue(v.VulnId, out var other) && other.Status != v.Status)
                .Select(v => new
                {
                    vulnId = v.VulnId,
                    title = v.RuleTitle,
                    category = v.Category,
                    from = v.Status.ToString(),
                    to = mapB[v.VulnId].Status.ToString()
                })
                .ToList();

            var result = new
            {
                baseline = new { documentId = a.Id, host = NullIfEmpty(a.Document.Asset.HostName) },
                comparison = new { documentId = b.Id, host = NullIfEmpty(b.Document.Asset.HostName) },
                statusChanged = changed,
                onlyInBaseline = mapA.Keys.Where(k => !mapB.ContainsKey(k)).ToList(),
                onlyInComparison = mapB.Keys.Where(k => !mapA.ContainsKey(k)).ToList()
            };
            return JsonSerializer.Serialize(result, Json);
        }
    }

    // ---------------------------------------------------------------- helpers

    private object DocumentSummary(LoadedChecklist entry)
    {
        var vulns = entry.Document.AllVulnerabilities.ToList();
        return new
        {
            documentId = entry.Id,
            title = entry.Document.Title
                    ?? string.Join(" + ", entry.Document.Stigs.Select(s => s.DisplayName)
                        .Where(n => !string.IsNullOrEmpty(n))),
            hostName = NullIfEmpty(entry.Document.Asset.HostName),
            sourcePath = entry.Document.SourcePath,
            format = entry.Document.SourcePath is null
                ? null
                : entry.Document.SourceFormat.ToString().ToLowerInvariant(),
            stigs = entry.Document.Stigs.Select(s => s.Title),
            totalFindings = vulns.Count,
            byStatus = StatusCounts(vulns),
            unsavedChanges = entry.Dirty
        };
    }

    private static object StatusCounts(IReadOnlyCollection<Vulnerability> vulns) => new
    {
        open = vulns.Count(v => v.Status == FindingStatus.Open),
        notAFinding = vulns.Count(v => v.Status == FindingStatus.NotAFinding),
        notApplicable = vulns.Count(v => v.Status == FindingStatus.NotApplicable),
        notReviewed = vulns.Count(v => v.Status == FindingStatus.NotReviewed)
    };

    private IEnumerable<(LoadedChecklist Entry, Vulnerability Vuln)> Filter(
        string? documentId, string? status, string? severity, string? stig, string? search)
    {
        var statusFilter = ParseStatusFilter(status);
        var severityFilter = ParseSeverityFilter(severity);

        var scope = documentId is null
            ? workspace.Documents
            : new[] { workspace.GetRequired(documentId) };

        foreach (var entry in scope)
        {
            foreach (var s in entry.Document.Stigs)
            {
                if (stig is not null &&
                    !s.Title.Contains(stig, StringComparison.OrdinalIgnoreCase) &&
                    !s.StigId.Contains(stig, StringComparison.OrdinalIgnoreCase) &&
                    !s.DisplayName.Contains(stig, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (var v in s.Vulnerabilities)
                {
                    if (statusFilter is not null && v.Status != statusFilter)
                    {
                        continue;
                    }

                    if (severityFilter is not null &&
                        !Severity.Normalize(v.EffectiveSeverity).Equals(severityFilter, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (search is not null && search.Length > 0 && !MatchesSearch(v, entry, search))
                    {
                        continue;
                    }

                    yield return (entry, v);
                }
            }
        }
    }

    private static bool MatchesSearch(Vulnerability v, LoadedChecklist entry, string text) =>
        Contains(v.VulnId, text) || Contains(v.RuleId, text) || Contains(v.RuleVersion, text) ||
        Contains(v.RuleTitle, text) || Contains(v.Discussion, text) ||
        Contains(v.CheckContent, text) || Contains(v.FixText, text) ||
        Contains(v.CciDisplay, text) || Contains(v.FindingDetails, text) ||
        Contains(v.Comments, text) || Contains(entry.Document.Asset.HostName, text);

    private static bool Contains(string haystack, string needle) =>
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private static FindingStatus? ParseStatusFilter(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim().ToLowerInvariant().Replace("_", "").Replace(" ", "");
        return normalized switch
        {
            "open" => FindingStatus.Open,
            "notafinding" => FindingStatus.NotAFinding,
            "notapplicable" => FindingStatus.NotApplicable,
            "notreviewed" => FindingStatus.NotReviewed,
            _ => throw new McpException(
                $"Unknown status '{value}'. Use Open, NotAFinding, NotApplicable, or NotReviewed.")
        };
    }

    private static string? ParseSeverityFilter(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim().ToLowerInvariant();
        return normalized switch
        {
            "high" or "cat i" or "cat_i" or "cati" or "1" => Severity.High,
            "medium" or "cat ii" or "cat_ii" or "catii" or "2" => Severity.Medium,
            "low" or "cat iii" or "cat_iii" or "catiii" or "3" => Severity.Low,
            _ => throw new McpException(
                $"Unknown severity '{value}'. Use high/medium/low or CAT I/CAT II/CAT III.")
        };
    }

    private static void ApplyEdits(Vulnerability v, string? status, string? findingDetails,
        string? comments, string? severityOverride, string? severityJustification, string? internalNotes = null)
    {
        if (status is not null)
        {
            v.Status = ParseStatusFilter(status)
                       ?? throw new McpException("status must not be empty.");
        }

        if (findingDetails is not null)
        {
            v.FindingDetails = findingDetails;
        }

        if (comments is not null)
        {
            v.Comments = comments;
        }

        if (severityOverride is not null)
        {
            v.SeverityOverride = severityOverride.Length == 0
                ? string.Empty
                : ParseSeverityFilter(severityOverride)!;
        }

        if (severityJustification is not null)
        {
            v.SeverityJustification = severityJustification;
        }

        if (internalNotes is not null)
        {
            v.InternalNotes = internalNotes;
        }
    }

    private static string? NullIfEmpty(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}

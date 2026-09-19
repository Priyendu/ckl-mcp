using CklViewer.Models;
using ModelContextProtocol;

namespace CklMcp.Tools;

/// <summary>A checklist held in the session, addressable by a short id like "doc-1".</summary>
public sealed class LoadedChecklist(string id, ChecklistDocument document)
{
    public string Id { get; } = id;
    public ChecklistDocument Document { get; } = document;

    /// <summary>True when in-memory edits have not been written back to disk.</summary>
    public bool Dirty { get; set; }
}

/// <summary>
/// In-memory session state: the set of loaded checklists, mirroring the merged multi-file
/// view of the Ckl-viewer app. Tools take the coarse <see cref="SyncRoot"/> lock so
/// concurrent MCP requests cannot interleave mid-edit.
/// </summary>
public sealed class Workspace
{
    private readonly List<LoadedChecklist> _documents = new();
    private int _nextId = 1;

    public object SyncRoot { get; } = new();

    public IReadOnlyList<LoadedChecklist> Documents => _documents;

    public LoadedChecklist Add(ChecklistDocument document, bool dirty = false)
    {
        var entry = new LoadedChecklist($"doc-{_nextId++}", document) { Dirty = dirty };
        _documents.Add(entry);
        return entry;
    }

    public void Remove(LoadedChecklist entry) => _documents.Remove(entry);

    public LoadedChecklist? Find(string id) =>
        _documents.FirstOrDefault(d => d.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    public LoadedChecklist GetRequired(string id) =>
        Find(id) ?? throw new McpException(
            $"No loaded checklist with id '{id}'. Loaded: " +
            (_documents.Count == 0 ? "(none)" : string.Join(", ", _documents.Select(d => d.Id))));

    /// <summary>
    /// The document to operate on when a tool's document_id is optional: the named one,
    /// or the single loaded document, or an error when the choice is ambiguous.
    /// </summary>
    public LoadedChecklist ResolveDocument(string? documentId)
    {
        if (!string.IsNullOrWhiteSpace(documentId))
        {
            return GetRequired(documentId);
        }

        return _documents.Count switch
        {
            0 => throw new McpException("No checklists are loaded. Call load_checklists first."),
            1 => _documents[0],
            _ => throw new McpException(
                "Multiple checklists are loaded; specify document_id. Loaded: " +
                string.Join(", ", _documents.Select(d => $"{d.Id} ({d.Document.Asset.HostName})")))
        };
    }

    /// <summary>
    /// Locates a finding by V-key (e.g. V-220697), rule id, or rule version, optionally
    /// scoped to one document. Errors when the id matches findings in several documents.
    /// </summary>
    public (LoadedChecklist Entry, Vulnerability Vulnerability) ResolveFinding(string vulnId, string? documentId)
    {
        if (string.IsNullOrWhiteSpace(vulnId))
        {
            throw new McpException("vuln_id is required.");
        }

        var scope = string.IsNullOrWhiteSpace(documentId)
            ? _documents
            : new List<LoadedChecklist> { GetRequired(documentId) };

        var matches = new List<(LoadedChecklist, Vulnerability)>();
        foreach (var entry in scope)
        {
            foreach (var vuln in entry.Document.AllVulnerabilities)
            {
                if (vulnId.Equals(vuln.VulnId, StringComparison.OrdinalIgnoreCase) ||
                    vulnId.Equals(vuln.RuleId, StringComparison.OrdinalIgnoreCase) ||
                    vulnId.Equals(vuln.RuleVersion, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add((entry, vuln));
                }
            }
        }

        return matches.Count switch
        {
            0 => throw new McpException($"No finding matches '{vulnId}'" +
                (documentId is null ? " in any loaded checklist." : $" in {documentId}.")),
            1 => matches[0],
            _ => throw new McpException(
                $"'{vulnId}' matches findings in several checklists; specify document_id. Matches: " +
                string.Join(", ", matches.Select(m => $"{m.Item1.Id} ({m.Item1.Document.Asset.HostName})")))
        };
    }
}

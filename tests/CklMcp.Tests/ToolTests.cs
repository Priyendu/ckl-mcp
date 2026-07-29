using System.Text.Json;
using CklMcp.Server;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Tests;
using CklViewer.Writing;
using ModelContextProtocol;
using Xunit;

namespace CklMcp.Tests;

public sealed class ToolTests : IDisposable
{
    private readonly string _dir;
    private readonly Workspace _workspace = new();
    private readonly ChecklistTools _tools;

    public ToolTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "ckl-mcp-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _tools = new ChecklistTools(_workspace, ServerOptions.Parse(Array.Empty<string>()));
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteSampleCkl(string name = "sample.ckl")
    {
        var path = Path.Combine(_dir, name);
        CklWriter.WriteFile(SampleData.BuildChecklist(), path);
        return path;
    }

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void LoadAndSummarize()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        var summary = Parse(_tools.GetSummary());
        Assert.Equal(1, summary.GetProperty("checklists").GetInt32());
        Assert.Equal(3, summary.GetProperty("totalFindings").GetInt32());
        Assert.Equal(1, summary.GetProperty("byStatus").GetProperty("open").GetInt32());
        Assert.Equal(1, summary.GetProperty("byStatus").GetProperty("notReviewed").GetInt32());

        var doc = summary.GetProperty("documents")[0];
        Assert.Equal("doc-1", doc.GetProperty("documentId").GetString());
        Assert.False(doc.GetProperty("unsavedChanges").GetBoolean());
    }

    [Fact]
    public void ListFindingsFiltersByStatusAndSeverity()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        var open = Parse(_tools.ListFindings(status: "Open"));
        Assert.Equal(1, open.GetProperty("total").GetInt32());
        Assert.Equal("V-220697", open.GetProperty("findings")[0].GetProperty("vulnId").GetString());

        var catI = Parse(_tools.ListFindings(severity: "CAT I"));
        Assert.Equal(1, catI.GetProperty("total").GetInt32());
        Assert.Equal("V-220706", catI.GetProperty("findings")[0].GetProperty("vulnId").GetString());

        Assert.Throws<McpException>(() => _tools.ListFindings(status: "bogus"));
    }

    [Fact]
    public void ListFindingsPaginates()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        var page = Parse(_tools.ListFindings(page: 2, pageSize: 2));
        Assert.Equal(3, page.GetProperty("total").GetInt32());
        Assert.Equal(2, page.GetProperty("totalPages").GetInt32());
        Assert.Equal(1, page.GetProperty("findings").GetArrayLength());
    }

    [Fact]
    public void GetFindingByRuleVersion()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        var finding = Parse(_tools.GetFinding("WN10-00-000005"));
        Assert.Equal("V-220697", finding.GetProperty("vulnId").GetString());
        Assert.Contains("Enterprise Edition", finding.GetProperty("checkContent").GetString());
    }

    [Fact]
    public void UpdateFindingMarksDirtyAndSavePersists()
    {
        var path = WriteSampleCkl();
        _tools.LoadChecklists(new[] { path });

        var updated = Parse(_tools.UpdateFinding("V-220710",
            status: "NotAFinding", findingDetails: "Verified ESS is running."));
        Assert.Equal("NotAFinding", updated.GetProperty("status").GetString());
        Assert.True(_workspace.Documents[0].Dirty);

        _tools.SaveChecklist();
        Assert.False(_workspace.Documents[0].Dirty);

        var reloaded = CklParser.ParseFile(path);
        var vuln = reloaded.AllVulnerabilities.Single(v => v.VulnId == "V-220710");
        Assert.Equal(FindingStatus.NotAFinding, vuln.Status);
        Assert.Equal("Verified ESS is running.", vuln.FindingDetails);
    }

    [Fact]
    public void SaveAsCklbConvertsFormat()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        var target = Path.Combine(_dir, "converted.cklb");
        var result = Parse(_tools.SaveChecklist(path: target));
        Assert.Equal("cklb", result.GetProperty("format").GetString());

        var reloaded = CklbParser.ParseFile(target);
        Assert.Equal("SAMPLE-HOST", reloaded.Asset.HostName);
        Assert.Equal(3, reloaded.AllVulnerabilities.Count());
    }

    [Fact]
    public void BulkUpdateRequiresSelectorAndAppliesFilter()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        Assert.Throws<McpException>(() => _tools.BulkUpdateFindings(setStatus: "Open"));
        Assert.Throws<McpException>(() => _tools.BulkUpdateFindings(whereStatus: "Open"));

        var result = Parse(_tools.BulkUpdateFindings(
            whereStatus: "NotReviewed", setStatus: "NotApplicable", setComments: "Feature not installed."));
        Assert.Equal(1, result.GetProperty("updated").GetInt32());

        var vuln = _workspace.Documents[0].Document.AllVulnerabilities.Single(v => v.VulnId == "V-220710");
        Assert.Equal(FindingStatus.NotApplicable, vuln.Status);
        Assert.Equal("Feature not installed.", vuln.Comments);
    }

    [Fact]
    public void ApplyXccdfUpdatesStatuses()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });
        var xccdf = Path.Combine(_dir, "results.xml");
        File.WriteAllText(xccdf, SampleData.XccdfResult);

        var outcomes = Parse(_tools.ApplyXccdfResults(new[] { xccdf }));
        Assert.Equal(3, outcomes[0].GetProperty("matched").GetInt32());
        Assert.Equal(3, outcomes[0].GetProperty("updated").GetInt32());

        var vulns = _workspace.Documents[0].Document.AllVulnerabilities.ToDictionary(v => v.VulnId);
        Assert.Equal(FindingStatus.NotAFinding, vulns["V-220697"].Status);
        Assert.Equal(FindingStatus.Open, vulns["V-220706"].Status);
        Assert.Equal(FindingStatus.NotApplicable, vulns["V-220710"].Status);
        Assert.True(_workspace.Documents[0].Dirty);
    }

    [Fact]
    public void CloseRefusesDirtyWithoutDiscard()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });
        _tools.UpdateFinding("V-220697", comments: "edited");

        Assert.Throws<McpException>(() => _tools.CloseChecklists());
        _tools.CloseChecklists(discardUnsaved: true);
        Assert.Empty(_workspace.Documents);
    }

    [Fact]
    public void AmbiguousVulnIdAcrossDocumentsNeedsDocumentId()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl("a.ckl"), WriteSampleCkl("b.ckl") });

        Assert.Throws<McpException>(() => _tools.GetFinding("V-220697"));

        var finding = Parse(_tools.GetFinding("V-220697", documentId: "doc-2"));
        Assert.Equal("doc-2", finding.GetProperty("documentId").GetString());
    }

    [Fact]
    public void CompareChecklistsReportsStatusChanges()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl("a.ckl"), WriteSampleCkl("b.ckl") });
        _tools.UpdateFinding("V-220697", documentId: "doc-2", status: "NotAFinding");

        var diff = Parse(_tools.CompareChecklists("doc-1", "doc-2"));
        var changed = diff.GetProperty("statusChanged");
        Assert.Equal(1, changed.GetArrayLength());
        Assert.Equal("V-220697", changed[0].GetProperty("vulnId").GetString());
        Assert.Equal("Open", changed[0].GetProperty("from").GetString());
        Assert.Equal("NotAFinding", changed[0].GetProperty("to").GetString());
    }

    [Fact]
    public void LoadChecklistsRoundTripsThroughExcelExport()
    {
        _tools.LoadChecklists(new[] { WriteSampleCkl() });

        var reportPath = Path.Combine(_dir, "report.xlsx");
        _tools.ExportExcelReport(reportPath);
        _tools.CloseChecklists(discardUnsaved: true);

        var loaded = Parse(_tools.LoadChecklists(new[] { reportPath }));
        Assert.Equal(1, loaded.GetArrayLength());
        var doc = loaded[0];
        Assert.Equal(3, doc.GetProperty("totalFindings").GetInt32());
        Assert.True(doc.GetProperty("unsavedChanges").GetBoolean());

        var open = Parse(_tools.ListFindings(status: "Open"));
        Assert.Equal(1, open.GetProperty("total").GetInt32());
        Assert.Equal("V-220697", open.GetProperty("findings")[0].GetProperty("vulnId").GetString());

        // An import has no source file, so save_checklist requires an explicit path.
        Assert.Throws<McpException>(() => _tools.SaveChecklist());
        var savedPath = Path.Combine(_dir, "reimported.ckl");
        _tools.SaveChecklist(path: savedPath);
        Assert.True(File.Exists(savedPath));
    }

    [Fact]
    public void MergePriorAssessmentCarriesStatusesAndMarksTargetDirty()
    {
        // doc-1: prior assessment; doc-2: fresh checklist of the same STIG with one rule's text changed.
        var prior = SampleData.BuildChecklist();
        var fresh = SampleData.BuildChecklist();
        foreach (var v in fresh.AllVulnerabilities)
        {
            v.Status = FindingStatus.NotReviewed;
            v.FindingDetails = string.Empty;
            v.Comments = string.Empty;
        }

        fresh.AllVulnerabilities.Single(v => v.VulnId == "V-220706").CheckContent = "Rewritten check text.";

        var priorPath = Path.Combine(_dir, "prior.ckl");
        var freshPath = Path.Combine(_dir, "fresh.ckl");
        CklWriter.WriteFile(prior, priorPath);
        CklWriter.WriteFile(fresh, freshPath);
        _tools.LoadChecklists(new[] { priorPath, freshPath });

        var outcome = Parse(_tools.MergePriorAssessment("doc-2", "doc-1"));
        Assert.Equal(3, outcome.GetProperty("carried").GetInt32());
        Assert.Equal(1, outcome.GetProperty("changedRuleText").GetInt32());
        Assert.True(_workspace.Documents[1].Dirty);

        var merged = _workspace.Documents[1].Document.AllVulnerabilities.ToDictionary(v => v.VulnId);
        Assert.Equal(FindingStatus.Open, merged["V-220697"].Status);
        Assert.Equal("System is running Windows 10 Pro.", merged["V-220697"].FindingDetails);
        Assert.Equal(FindingStatus.NotAFinding, merged["V-220706"].Status);
        Assert.Contains("re-verify", merged["V-220706"].FindingDetails);

        Assert.Throws<McpException>(() => _tools.MergePriorAssessment("doc-2", "doc-2"));
    }

    [Fact]
    public void MergePriorAssessmentResetsChangedRulesWhenAsked()
    {
        var prior = SampleData.BuildChecklist();
        var fresh = SampleData.BuildChecklist();
        fresh.AllVulnerabilities.Single(v => v.VulnId == "V-220697").FixText = "New fix procedure.";

        var priorPath = Path.Combine(_dir, "prior.ckl");
        var freshPath = Path.Combine(_dir, "fresh.ckl");
        CklWriter.WriteFile(prior, priorPath);
        CklWriter.WriteFile(fresh, freshPath);
        _tools.LoadChecklists(new[] { priorPath, freshPath });

        _tools.MergePriorAssessment("doc-2", "doc-1", resetChangedRules: true);

        var vuln = _workspace.Documents[1].Document.AllVulnerabilities.Single(v => v.VulnId == "V-220697");
        Assert.Equal(FindingStatus.NotReviewed, vuln.Status);
        Assert.Contains("status reset to Not Reviewed", vuln.FindingDetails);
    }

    [Fact]
    public void ReadOnlyModeBlocksEditsButAllowsExport()
    {
        var readOnlyTools = new ChecklistTools(_workspace, ServerOptions.Parse(new[] { "--read-only" }));
        readOnlyTools.LoadChecklists(new[] { WriteSampleCkl() });

        Assert.Throws<McpException>(() => readOnlyTools.UpdateFinding("V-220697", status: "Open"));
        Assert.Throws<McpException>(() => readOnlyTools.SaveChecklist());

        var report = Path.Combine(_dir, "report.xlsx");
        readOnlyTools.ExportExcelReport(report);
        Assert.True(File.Exists(report));
    }

    [Fact]
    public void RootRestrictionBlocksOutsidePaths()
    {
        var inside = WriteSampleCkl();
        var outside = Path.Combine(Path.GetTempPath(), "ckl-mcp-outside-" + Guid.NewGuid().ToString("N") + ".ckl");
        CklWriter.WriteFile(SampleData.BuildChecklist(), outside);
        try
        {
            var rooted = new ChecklistTools(_workspace, ServerOptions.Parse(new[] { "--root", _dir }));
            rooted.LoadChecklists(new[] { inside });
            Assert.Throws<McpException>(() => rooted.LoadChecklists(new[] { outside }));
        }
        finally
        {
            File.Delete(outside);
        }
    }
}

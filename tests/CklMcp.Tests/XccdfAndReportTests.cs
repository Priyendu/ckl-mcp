using System.IO;
using ClosedXML.Excel;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Reports;
using Xunit;

namespace CklViewer.Tests;

public class XccdfAndReportTests
{
    [Fact]
    public void ScapResultsUpdateStatusesByRuleVersion()
    {
        var document = SampleData.BuildChecklist();
        var xccdfPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-test-{Guid.NewGuid():N}.xml");
        File.WriteAllText(xccdfPath, SampleData.XccdfResult);

        try
        {
            var outcome = XccdfResultApplier.Apply(document, xccdfPath);

            Assert.Equal(3, outcome.TotalResults);
            Assert.Equal(3, outcome.Matched);
            Assert.Equal(3, outcome.Updated);

            var vulns = document.Stigs[0].Vulnerabilities;
            Assert.Equal(FindingStatus.NotAFinding, vulns.First(v => v.RuleVersion == "WN10-00-000005").Status);
            Assert.Equal(FindingStatus.Open, vulns.First(v => v.RuleVersion == "WN10-00-000040").Status);
            Assert.Equal(FindingStatus.NotApplicable, vulns.First(v => v.RuleVersion == "WN10-00-000045").Status);
            Assert.Contains("SCAP result 'fail'", vulns.First(v => v.RuleVersion == "WN10-00-000040").FindingDetails);
        }
        finally
        {
            File.Delete(xccdfPath);
        }
    }

    [Fact]
    public void ExcelReportContainsExpectedSheetsAndRows()
    {
        var document = SampleData.BuildChecklist();
        var reportPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-test-{Guid.NewGuid():N}.xlsx");

        try
        {
            ExcelReportGenerator.WriteReport(new[] { document }, reportPath);

            using var workbook = new XLWorkbook(reportPath);
            Assert.True(workbook.Worksheets.Contains("Executive Summary"));
            Assert.True(workbook.Worksheets.Contains("POA&M"));
            Assert.True(workbook.Worksheets.Contains("Vulnerability Details"));

            // POA&M contains the Open and Not Reviewed findings, but not the Not a Finding one.
            var poam = workbook.Worksheet("POA&M");
            var securityChecks = poam.Column(2).CellsUsed().Skip(1).Select(c => c.GetString()).ToList();
            Assert.Equal(2, securityChecks.Count);
            Assert.Contains(securityChecks, c => c.Contains("V-220697"));
            Assert.Contains(securityChecks, c => c.Contains("V-220710"));

            // Details sheet has one row per finding plus the header.
            var details = workbook.Worksheet("Vulnerability Details");
            Assert.Equal(4, details.Column(3).CellsUsed().Count());
        }
        finally
        {
            File.Delete(reportPath);
        }
    }

    [Fact]
    public void ExcelReportAggregatesMultipleChecklists()
    {
        var first = SampleData.BuildChecklist();
        var second = SampleData.BuildChecklist();
        second.Asset.HostName = "SECOND-HOST";
        var reportPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-test-{Guid.NewGuid():N}.xlsx");

        try
        {
            ExcelReportGenerator.WriteReport(new[] { first, second }, reportPath);

            using var workbook = new XLWorkbook(reportPath);

            // Executive Summary has one row per asset/STIG pair.
            var summary = workbook.Worksheet("Executive Summary");
            var assets = summary.Column(1).CellsUsed()
                .Select(c => c.GetString())
                .Where(v => v is "SAMPLE-HOST" or "SECOND-HOST")
                .ToList();
            Assert.Equal(2, assets.Count);

            // Details sheet has rows for both assets (header + 3 findings each).
            var details = workbook.Worksheet("Vulnerability Details");
            Assert.Equal(7, details.Column(3).CellsUsed().Count());
            Assert.Contains(details.Column(1).CellsUsed(), c => c.GetString() == "SECOND-HOST");
        }
        finally
        {
            File.Delete(reportPath);
        }
    }
}

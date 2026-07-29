using System.IO;
using ClosedXML.Excel;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Reports;
using CklViewer.Writing;
using Xunit;

namespace CklViewer.Tests;

public class ExcelImportTests
{
    private static string TempPath(string extension) =>
        Path.Combine(Path.GetTempPath(), $"ckl-xlsx-{Guid.NewGuid():N}{extension}");

    [Fact]
    public void ReportRoundTripsBackIntoAChecklist()
    {
        var original = SampleData.BuildChecklist();
        var reportPath = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { original }, reportPath);

            var imported = Assert.Single(ExcelChecklistImporter.ImportFile(reportPath));

            Assert.Equal("SAMPLE-HOST", imported.Asset.HostName);
            var expected = original.AllVulnerabilities.ToList();
            var actual = imported.AllVulnerabilities.ToList();
            Assert.Equal(expected.Count, actual.Count);

            for (var i = 0; i < expected.Count; i++)
            {
                Assert.Equal(expected[i].VulnId, actual[i].VulnId);
                Assert.Equal(expected[i].RuleId, actual[i].RuleId);
                Assert.Equal(expected[i].RuleVersion, actual[i].RuleVersion);
                Assert.Equal(expected[i].RuleTitle, actual[i].RuleTitle);
                Assert.Equal(expected[i].Status, actual[i].Status);
                Assert.Equal(expected[i].Category, actual[i].Category);
                Assert.Equal(expected[i].Discussion, actual[i].Discussion);
                Assert.Equal(expected[i].CheckContent, actual[i].CheckContent);
                Assert.Equal(expected[i].FixText, actual[i].FixText);
                Assert.Equal(expected[i].FindingDetails, actual[i].FindingDetails);
                Assert.Equal(expected[i].Comments, actual[i].Comments);
                Assert.Equal(expected[i].Ccis, actual[i].Ccis);
            }

            // An import is unsaved, so Save must prompt rather than overwrite the workbook.
            Assert.Null(imported.SourcePath);
        }
        finally
        {
            File.Delete(reportPath);
        }
    }

    [Fact]
    public void ImportedChecklistSavesAsCklAndCklb()
    {
        var reportPath = TempPath(".xlsx");
        var cklPath = TempPath(".ckl");
        var cklbPath = TempPath(".cklb");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { SampleData.BuildChecklist() }, reportPath);
            var imported = ExcelChecklistImporter.ImportFile(reportPath).Single();

            CklWriter.WriteFile(imported, cklPath);
            CklbWriter.WriteFile(imported, cklbPath);

            var fromCkl = CklParser.ParseFile(cklPath);
            var fromCklb = CklbParser.ParseFile(cklbPath);

            Assert.Equal(3, fromCkl.AllVulnerabilities.Count());
            Assert.Equal(3, fromCklb.AllVulnerabilities.Count());
            Assert.Equal(FindingStatus.Open, fromCkl.AllVulnerabilities.First().Status);
            Assert.Equal(FindingStatus.Open, fromCklb.AllVulnerabilities.First().Status);
            Assert.Equal("SAMPLE-HOST", fromCklb.Asset.HostName);
        }
        finally
        {
            File.Delete(reportPath);
            File.Delete(cklPath);
            File.Delete(cklbPath);
        }
    }

    [Fact]
    public void MultipleAssetsBecomeSeparateChecklists()
    {
        var first = SampleData.BuildChecklist();
        var second = SampleData.BuildChecklist();
        second.Asset.HostName = "SECOND-HOST";

        var reportPath = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { first, second }, reportPath);

            var imported = ExcelChecklistImporter.ImportFile(reportPath);

            Assert.Equal(2, imported.Count);
            Assert.Contains(imported, d => d.Asset.HostName == "SAMPLE-HOST");
            Assert.Contains(imported, d => d.Asset.HostName == "SECOND-HOST");
            Assert.All(imported, d => Assert.Equal(3, d.AllVulnerabilities.Count()));
        }
        finally
        {
            File.Delete(reportPath);
        }
    }

    [Fact]
    public void HandBuiltSheetWithReorderedHeadersWorks()
    {
        var path = TempPath(".xlsx");
        try
        {
            using (var workbook = new XLWorkbook())
            {
                var sheet = workbook.Worksheets.Add("Sheet1");
                // Deliberately different order and a subset of columns.
                sheet.Cell(1, 1).Value = "Status";
                sheet.Cell(1, 2).Value = "Rule Version";
                sheet.Cell(1, 3).Value = "Rule Title";
                sheet.Cell(1, 4).Value = "Comments";
                sheet.Cell(2, 1).Value = "Not a Finding";
                sheet.Cell(2, 2).Value = "WN10-00-000005";
                sheet.Cell(2, 3).Value = "Some rule";
                sheet.Cell(2, 4).Value = "Verified by hand";
                workbook.SaveAs(path);
            }

            var imported = ExcelChecklistImporter.ImportFile(path).Single();
            var vuln = imported.AllVulnerabilities.Single();

            Assert.Equal(FindingStatus.NotAFinding, vuln.Status);
            Assert.Equal("WN10-00-000005", vuln.RuleVersion);
            Assert.Equal("Verified by hand", vuln.Comments);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SheetWithoutRequiredColumnsIsRejectedClearly()
    {
        var path = TempPath(".xlsx");
        try
        {
            using (var workbook = new XLWorkbook())
            {
                var sheet = workbook.Worksheets.Add("Sheet1");
                sheet.Cell(1, 1).Value = "Something";
                sheet.Cell(2, 1).Value = "else";
                workbook.SaveAs(path);
            }

            var ex = Assert.Throws<InvalidDataException>(() => ExcelChecklistImporter.ImportFile(path));
            Assert.Contains("Rule Version", ex.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LoaderRoutesXlsxToTheImporter()
    {
        var reportPath = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { SampleData.BuildChecklist() }, reportPath);

            Assert.True(ChecklistLoader.IsExcel(reportPath));
            Assert.Single(ChecklistLoader.LoadAll(reportPath));
            Assert.Equal(3, ChecklistLoader.Load(reportPath).AllVulnerabilities.Count());
        }
        finally
        {
            File.Delete(reportPath);
        }
    }
}

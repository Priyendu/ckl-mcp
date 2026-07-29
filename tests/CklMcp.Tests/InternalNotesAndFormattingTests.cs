using System.IO;
using ClosedXML.Excel;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Reports;
using CklViewer.Writing;
using Xunit;

namespace CklViewer.Tests;

public class InternalNotesAndFormattingTests
{
    private static readonly XLColor Green = XLColor.FromArgb(0x27, 0xAE, 0x60);
    private static readonly XLColor CatI = XLColor.FromArgb(192, 0, 0);

    private static string TempPath(string extension) =>
        Path.Combine(Path.GetTempPath(), $"ckl-notes-{Guid.NewGuid():N}{extension}");

    private static ChecklistDocument WithNotes()
    {
        var doc = SampleData.BuildChecklist();
        doc.AllVulnerabilities.First().InternalNotes = "Waiver requested; tracked in JIRA-1234.";
        return doc;
    }

    [Fact]
    public void StatusAndSeverityUseConditionalFormattingSoEditsRecolour()
    {
        var path = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { SampleData.BuildChecklist() }, path);

            using var workbook = new XLWorkbook(path);
            var details = workbook.Worksheet("Vulnerability Details");
            var formats = details.ConditionalFormats.ToList();

            // Colour comes from rules on the range, not fills baked into individual cells.
            Assert.Contains(formats, f => f.Style.Fill.BackgroundColor.Equals(Green));
            Assert.Contains(formats, f => f.Style.Fill.BackgroundColor.Equals(CatI));

            // A "Not a Finding" row must not carry a hard-coded green fill any more.
            Assert.Equal(XLFillPatternValues.None, details.Row(3).Cell(8).Style.Fill.PatternType);
            Assert.Equal(XLFillPatternValues.None, details.Row(3).Cell(6).Style.Fill.PatternType);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ChangingStatusInExcelPicksUpTheNewColour()
    {
        var path = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { SampleData.BuildChecklist() }, path);

            // Simulate the user editing the Status cell in Excel.
            using (var workbook = new XLWorkbook(path))
            {
                workbook.Worksheet("Vulnerability Details").Cell(2, 8).Value = "Not a Finding";
                workbook.Save();
            }

            using (var workbook = new XLWorkbook(path))
            {
                var details = workbook.Worksheet("Vulnerability Details");
                var cell = details.Cell(2, 8);

                // The edited cell is covered by the "Not a Finding" rule, so Excel renders it green.
                var matching = details.ConditionalFormats
                    .Where(f => f.Ranges.Any(r => r.Contains(cell)))
                    .Where(f => f.Values.Values.Any(v => v.Value?.Contains("Not a Finding") == true))
                    .ToList();

                Assert.NotEmpty(matching);
                Assert.Contains(matching, f => f.Style.Fill.BackgroundColor.Equals(Green));
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void InternalNotesColumnIsWrittenAndReadBack()
    {
        var path = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { WithNotes() }, path);

            using (var workbook = new XLWorkbook(path))
            {
                var details = workbook.Worksheet("Vulnerability Details");
                Assert.Equal(ExcelReportGenerator.InternalNotesHeader,
                    details.Cell(1, ExcelReportGenerator.InternalNotesColumn).GetString());
                Assert.Equal("Waiver requested; tracked in JIRA-1234.",
                    details.Cell(2, ExcelReportGenerator.InternalNotesColumn).GetString());
            }

            var imported = ExcelChecklistImporter.ImportFile(path).Single();
            Assert.Equal("Waiver requested; tracked in JIRA-1234.",
                imported.AllVulnerabilities.First().InternalNotes);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void InternalNotesColumnIsOmittedWhenDisabled()
    {
        var path = TempPath(".xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { WithNotes() }, path, includeInternalNotes: false);

            using var workbook = new XLWorkbook(path);
            var details = workbook.Worksheet("Vulnerability Details");
            Assert.NotEqual(ExcelReportGenerator.InternalNotesHeader,
                details.Cell(1, ExcelReportGenerator.InternalNotesColumn).GetString());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void InternalNotesNeverReachCklOrCklb()
    {
        const string secret = "Waiver requested; tracked in JIRA-1234.";
        var doc = WithNotes();
        var cklPath = TempPath(".ckl");
        var cklbPath = TempPath(".cklb");
        try
        {
            CklWriter.WriteFile(doc, cklPath);
            CklbWriter.WriteFile(doc, cklbPath);

            // The note must not appear anywhere in either shared file.
            Assert.DoesNotContain(secret, File.ReadAllText(cklPath), StringComparison.Ordinal);
            Assert.DoesNotContain(secret, File.ReadAllText(cklbPath), StringComparison.Ordinal);

            Assert.Equal(string.Empty, CklParser.ParseFile(cklPath).AllVulnerabilities.First().InternalNotes);
            Assert.Equal(string.Empty, CklbParser.ParseFile(cklbPath).AllVulnerabilities.First().InternalNotes);
        }
        finally
        {
            File.Delete(cklPath);
            File.Delete(cklbPath);
        }
    }
}

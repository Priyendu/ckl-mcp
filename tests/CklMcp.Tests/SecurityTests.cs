using System.IO;
using System.Text;
using System.Xml;
using ClosedXML.Excel;
using CklViewer.Parsing;
using CklViewer.Reports;
using CklViewer.Writing;
using Xunit;

namespace CklViewer.Tests;

public class SecurityTests
{
    [Fact]
    public void CklWithDoctypeIsRejected()
    {
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE CHECKLIST [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
            <CHECKLIST><ASSET><HOST_NAME>&xxe;</HOST_NAME></ASSET></CHECKLIST>
            """;

        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xxe));
        Assert.Throws<XmlException>(() => CklParser.Parse(stream));
    }

    [Fact]
    public void XccdfWithDoctypeIsRejected()
    {
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE Benchmark [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
            <Benchmark><TestResult><rule-result idref="&xxe;"><result>pass</result></rule-result></TestResult></Benchmark>
            """;

        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xxe));
        Assert.Throws<XmlException>(() => XccdfResultApplier.Parse(stream, out _));
    }

    [Fact]
    public void FormulaPayloadsInChecklistStayTextInReport()
    {
        var document = SampleData.BuildChecklist();
        var vuln = document.Stigs[0].Vulnerabilities[0];
        const string ddePayload = "=cmd|' /C calc'!A0";
        const string formulaPayload = "=HYPERLINK(\"http://evil.example\",\"click\")";
        vuln.FindingDetails = ddePayload;
        vuln.Comments = formulaPayload;

        var reportPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-sec-{Guid.NewGuid():N}.xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { document }, reportPath);

            using var workbook = new XLWorkbook(reportPath);
            var details = workbook.Worksheet("Vulnerability Details");
            var findingCell = details.Row(2).Cell(14);
            var commentsCell = details.Row(2).Cell(15);

            Assert.False(findingCell.HasFormula);
            Assert.False(commentsCell.HasFormula);
            Assert.Equal(ddePayload, findingCell.GetString());
            Assert.Equal(formulaPayload, commentsCell.GetString());
        }
        finally
        {
            File.Delete(reportPath);
        }
    }

    [Fact]
    public void OversizedFieldsDoNotBreakReportGeneration()
    {
        var document = SampleData.BuildChecklist();
        var vuln = document.Stigs[0].Vulnerabilities[0];
        vuln.Comments = new string('A', 100_000); // Excel's per-cell limit is 32,767 chars
        vuln.Mitigations = new string('B', 100_000);

        var reportPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-sec-{Guid.NewGuid():N}.xlsx");
        try
        {
            ExcelReportGenerator.WriteReport(new[] { document }, reportPath);

            using var workbook = new XLWorkbook(reportPath);
            var poam = workbook.Worksheet("POA&M");
            Assert.True(poam.Row(2).Cell(4).GetString().Length <= 32_767);
        }
        finally
        {
            File.Delete(reportPath);
        }
    }

    [Fact]
    public void ControlCharactersAreStrippedWhenSavingCkl()
    {
        var document = SampleData.BuildChecklist();
        var vuln = document.Stigs[0].Vulnerabilities[0];
        vuln.FindingDetails = "before\u0001after\nnew line kept"; // e.g. from a hostile CKLB (JSON allows control chars)
        document.Asset.HostName = "HOSTNAME";

        using var stream = new MemoryStream();
        CklWriter.Write(document, stream); // must not throw
        stream.Position = 0;
        var parsed = CklParser.Parse(stream);

        Assert.Equal("beforeafter\nnew line kept", parsed.Stigs[0].Vulnerabilities[0].FindingDetails);
        Assert.Equal("HOSTNAME", parsed.Asset.HostName);
    }
}

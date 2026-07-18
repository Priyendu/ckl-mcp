using System.IO;
using System.IO.Compression;
using System.Text;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Writing;
using Xunit;

namespace CklViewer.Tests;

public class BenchmarkImportTests
{
    // A minimal but structurally faithful DISA STIG XCCDF benchmark: two groups/rules,
    // escaped VulnDiscussion blobs, CCI + legacy idents, fix text, and check content.
    private const string Benchmark = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="xccdf_mil.disa.stig_benchmark_Sample_Windows_STIG">
          <title>Sample Windows STIG</title>
          <description>Sample benchmark for tests.</description>
          <version>1</version>
          <plain-text id="release-info">Release: 3 Benchmark Date: 01 Jan 2026</plain-text>
          <Group id="V-100001">
            <title>SRG-OS-000001</title>
            <description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
            <Rule id="SV-100001r1_rule" severity="high" weight="10.0">
              <version>SMPL-00-000010</version>
              <title>Sample rule one must be enabled.</title>
              <description>&lt;VulnDiscussion&gt;This is the discussion for rule one.&lt;/VulnDiscussion&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;&lt;IAControls&gt;&lt;/IAControls&gt;</description>
              <ident system="http://cyber.mil/cci">CCI-000015</ident>
              <ident system="http://cyber.mil/legacy">V-1111</ident>
              <fixtext fixref="F-1">Enable sample rule one.</fixtext>
              <check system="C-1">
                <check-content-ref href="Sample.xml" name="M" />
                <check-content>Verify sample rule one is enabled.</check-content>
              </check>
            </Rule>
          </Group>
          <Group id="V-100002">
            <title>SRG-OS-000002</title>
            <Rule id="SV-100002r1_rule" severity="medium" weight="10.0">
              <version>SMPL-00-000020</version>
              <title>Sample rule two must be configured.</title>
              <description>&lt;VulnDiscussion&gt;Discussion two.&lt;/VulnDiscussion&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;</description>
              <ident system="http://cyber.mil/cci">CCI-000016</ident>
              <fixtext fixref="F-2">Configure sample rule two.</fixtext>
              <check system="C-2">
                <check-content>Verify sample rule two.</check-content>
              </check>
            </Rule>
          </Group>
        </Benchmark>
        """;

    private static ChecklistDocument ParseBenchmark()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(Benchmark));
        return XccdfBenchmarkParser.Parse(stream);
    }

    [Fact]
    public void BenchmarkBecomesNotReviewedChecklist()
    {
        var doc = ParseBenchmark();

        Assert.Single(doc.Stigs);
        var stig = doc.Stigs[0];
        Assert.Equal("Sample Windows STIG", stig.Title);
        Assert.Equal("1", stig.Version);
        Assert.Contains("Release: 3", stig.ReleaseInfo);
        Assert.Equal(2, stig.Vulnerabilities.Count);
        Assert.All(stig.Vulnerabilities, v => Assert.Equal(FindingStatus.NotReviewed, v.Status));
    }

    [Fact]
    public void RuleMetadataIsMappedFromXccdf()
    {
        var vuln = ParseBenchmark().Stigs[0].Vulnerabilities[0];

        Assert.Equal("V-100001", vuln.VulnId);
        Assert.Equal("SV-100001r1_rule", vuln.RuleId);
        Assert.Equal("SMPL-00-000010", vuln.RuleVersion);
        Assert.Equal("Sample rule one must be enabled.", vuln.RuleTitle);
        Assert.Equal("CAT I", vuln.Category); // severity="high"
        Assert.Equal("This is the discussion for rule one.", vuln.Discussion);
        Assert.Equal("Enable sample rule one.", vuln.FixText);
        Assert.Equal("Verify sample rule one is enabled.", vuln.CheckContent);
        Assert.Contains("CCI-000015", vuln.Ccis);
        Assert.Contains("V-1111", vuln.LegacyIds);
        Assert.DoesNotContain("CCI-000015", vuln.LegacyIds);
    }

    [Fact]
    public void ImportedChecklistRoundTripsThroughBothFormats()
    {
        var doc = ParseBenchmark();

        using var cklStream = new MemoryStream();
        CklWriter.Write(doc, cklStream);
        cklStream.Position = 0;
        var fromCkl = CklParser.Parse(cklStream);
        Assert.Equal(2, fromCkl.Stigs[0].Vulnerabilities.Count);
        Assert.Equal("SMPL-00-000010", fromCkl.Stigs[0].Vulnerabilities[0].RuleVersion);
        Assert.Equal(FindingStatus.NotReviewed, fromCkl.Stigs[0].Vulnerabilities[0].Status);

        using var cklbStream = new MemoryStream();
        CklbWriter.Write(doc, cklbStream);
        cklbStream.Position = 0;
        var fromCklb = CklbParser.Parse(cklbStream);
        Assert.Equal("This is the discussion for rule one.", fromCklb.Stigs[0].Vulnerabilities[0].Discussion);
    }

    [Fact]
    public void BenchmarkInsideZipIsFound()
    {
        var zipPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-stig-{Guid.NewGuid():N}.zip");
        try
        {
            using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                // Include noise files a real STIG zip carries, plus the manual XCCDF.
                archive.CreateEntry("U_Sample_STIG_V1R3/U_Sample_STIG_V1R3_Overview.pdf");
                var entry = archive.CreateEntry("U_Sample_STIG_V1R3/U_Sample_Windows_STIG_V1R3_Manual-xccdf.xml");
                using var writer = new StreamWriter(entry.Open());
                writer.Write(Benchmark);
            }

            var doc = XccdfBenchmarkParser.ParseFile(zipPath);
            Assert.Equal(2, doc.Stigs[0].Vulnerabilities.Count);
            Assert.Null(doc.SourcePath); // a fresh, unsaved checklist
        }
        finally
        {
            File.Delete(zipPath);
        }
    }

    [Fact]
    public void LoaderRoutesBenchmarkXmlToImport()
    {
        var xmlPath = Path.Combine(Path.GetTempPath(), $"ckl-viewer-stig-{Guid.NewGuid():N}.xml");
        File.WriteAllText(xmlPath, Benchmark);
        try
        {
            var doc = ChecklistLoader.Load(xmlPath);
            Assert.Equal(2, doc.Stigs[0].Vulnerabilities.Count);
            Assert.All(doc.Stigs[0].Vulnerabilities, v => Assert.Equal(FindingStatus.NotReviewed, v.Status));
        }
        finally
        {
            File.Delete(xmlPath);
        }
    }
}

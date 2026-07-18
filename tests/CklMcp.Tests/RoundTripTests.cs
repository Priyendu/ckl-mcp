using System.IO;
using CklViewer.Models;
using CklViewer.Parsing;
using CklViewer.Writing;
using Xunit;

namespace CklViewer.Tests;

public class RoundTripTests
{
    [Fact]
    public void CklWriteThenParsePreservesFindings()
    {
        var original = SampleData.BuildChecklist();

        using var stream = new MemoryStream();
        CklWriter.Write(original, stream);
        stream.Position = 0;
        var parsed = CklParser.Parse(stream);

        AssertChecklistsMatch(original, parsed);
        Assert.Equal("UNCLASSIFIED", parsed.Stigs[0].InfoData["classification"]);
    }

    [Fact]
    public void CklbWriteThenParsePreservesFindings()
    {
        var original = SampleData.BuildChecklist();

        using var stream = new MemoryStream();
        CklbWriter.Write(original, stream);
        stream.Position = 0;
        var parsed = CklbParser.Parse(stream);

        AssertChecklistsMatch(original, parsed);
    }

    [Fact]
    public void CklConvertsToCklbAndBack()
    {
        var original = SampleData.BuildChecklist();

        using var cklbStream = new MemoryStream();
        CklbWriter.Write(original, cklbStream);
        cklbStream.Position = 0;
        var asCklb = CklbParser.Parse(cklbStream);

        using var cklStream = new MemoryStream();
        CklWriter.Write(asCklb, cklStream);
        cklStream.Position = 0;
        var backToCkl = CklParser.Parse(cklStream);

        AssertChecklistsMatch(original, backToCkl);
    }

    [Fact]
    public void SeverityOverrideSurvivesBothFormats()
    {
        var original = SampleData.BuildChecklist();
        original.Stigs[0].Vulnerabilities[0].SeverityOverride = Severity.High;
        original.Stigs[0].Vulnerabilities[0].SeverityJustification = "Exploited in the wild.";

        using var cklStream = new MemoryStream();
        CklWriter.Write(original, cklStream);
        cklStream.Position = 0;
        var fromCkl = CklParser.Parse(cklStream);
        Assert.Equal(Severity.High, fromCkl.Stigs[0].Vulnerabilities[0].SeverityOverride);
        Assert.Equal("CAT I", fromCkl.Stigs[0].Vulnerabilities[0].Category);

        using var cklbStream = new MemoryStream();
        CklbWriter.Write(original, cklbStream);
        cklbStream.Position = 0;
        var fromCklb = CklbParser.Parse(cklbStream);
        Assert.Equal(Severity.High, fromCklb.Stigs[0].Vulnerabilities[0].SeverityOverride);
        Assert.Equal("Exploited in the wild.", fromCklb.Stigs[0].Vulnerabilities[0].SeverityJustification);
    }

    private static void AssertChecklistsMatch(ChecklistDocument expected, ChecklistDocument actual)
    {
        Assert.Equal(expected.Asset.HostName, actual.Asset.HostName);
        Assert.Equal(expected.Asset.HostIp, actual.Asset.HostIp);
        Assert.Equal(expected.Asset.HostFqdn, actual.Asset.HostFqdn);
        Assert.Equal(expected.Stigs.Count, actual.Stigs.Count);

        for (var s = 0; s < expected.Stigs.Count; s++)
        {
            var expectedStig = expected.Stigs[s];
            var actualStig = actual.Stigs[s];
            Assert.Equal(expectedStig.StigId, actualStig.StigId);
            Assert.Equal(expectedStig.Title, actualStig.Title);
            Assert.Equal(expectedStig.Version, actualStig.Version);
            Assert.Equal(expectedStig.Vulnerabilities.Count, actualStig.Vulnerabilities.Count);

            for (var v = 0; v < expectedStig.Vulnerabilities.Count; v++)
            {
                var expectedVuln = expectedStig.Vulnerabilities[v];
                var actualVuln = actualStig.Vulnerabilities[v];
                Assert.Equal(expectedVuln.VulnId, actualVuln.VulnId);
                Assert.Equal(expectedVuln.RuleId, actualVuln.RuleId);
                Assert.Equal(expectedVuln.RuleVersion, actualVuln.RuleVersion);
                Assert.Equal(expectedVuln.RuleTitle, actualVuln.RuleTitle);
                Assert.Equal(expectedVuln.SeverityValue, actualVuln.SeverityValue);
                Assert.Equal(expectedVuln.Status, actualVuln.Status);
                Assert.Equal(expectedVuln.FindingDetails, actualVuln.FindingDetails);
                Assert.Equal(expectedVuln.Comments, actualVuln.Comments);
                Assert.Equal(expectedVuln.Ccis, actualVuln.Ccis);
            }
        }
    }
}

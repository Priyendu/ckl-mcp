using CklViewer.Merging;
using CklViewer.Models;
using Xunit;

namespace CklViewer.Tests;

public class MergeTests
{
    private static Vulnerability Rule(string version, FindingStatus status = FindingStatus.NotReviewed,
        string check = "check", string fix = "fix", string details = "", string comments = "") =>
        new()
        {
            VulnId = "V-" + version,
            RuleId = "SV-" + version + "_rule",
            RuleVersion = version,
            RuleTitle = "Rule " + version,
            SeverityValue = Severity.Medium,
            Status = status,
            CheckContent = check,
            FixText = fix,
            FindingDetails = details,
            Comments = comments
        };

    private static ChecklistDocument Doc(params Vulnerability[] vulns)
    {
        var doc = new ChecklistDocument { Title = "STIG" };
        var stig = new Stig { StigId = "SAMPLE_STIG", Title = "Sample STIG", Version = "1" };
        foreach (var v in vulns)
        {
            stig.Vulnerabilities.Add(v);
        }

        doc.Stigs.Add(stig);
        return doc;
    }

    [Fact]
    public void CarriesAssessmentForwardAndCategorizes()
    {
        // Old (source): assessed prior version.
        var source = Doc(
            Rule("WN10-00-000005", FindingStatus.Open, check: "check A", details: "old details", comments: "old comments"),
            Rule("WN10-00-000040", FindingStatus.NotAFinding, check: "check B"),
            Rule("WN10-00-000050", FindingStatus.NotApplicable)); // removed in the new version

        // New (target): fresh checklist for the new release.
        var target = Doc(
            Rule("WN10-00-000005", check: "check A"),          // unchanged text -> carried cleanly
            Rule("WN10-00-000040", check: "check B, revised"), // changed text -> carried + flagged
            Rule("WN10-00-000099"));                            // brand-new rule

        var outcome = ChecklistMerger.Merge(target, source, resetChangedRules: false);

        Assert.Equal(2, outcome.Carried);
        Assert.Equal(1, outcome.Unchanged);
        Assert.Equal(1, outcome.Changed);
        Assert.Equal(1, outcome.NewRules);
        Assert.Equal(1, outcome.Removed);

        var byVersion = target.AllVulnerabilities.ToDictionary(v => v.RuleVersion);
        Assert.Equal(FindingStatus.Open, byVersion["WN10-00-000005"].Status);
        Assert.Equal("old details", byVersion["WN10-00-000005"].FindingDetails);
        Assert.Equal("old comments", byVersion["WN10-00-000005"].Comments);

        var changed = byVersion["WN10-00-000040"];
        Assert.Equal(FindingStatus.NotAFinding, changed.Status);       // status carried
        Assert.Contains("rule text changed", changed.FindingDetails);  // but flagged

        Assert.Equal(FindingStatus.NotReviewed, byVersion["WN10-00-000099"].Status); // new rule untouched
    }

    [Fact]
    public void ResetChangedRules_SetsChangedRuleToNotReviewed()
    {
        var source = Doc(Rule("WN10-00-000040", FindingStatus.NotAFinding, check: "check B"));
        var target = Doc(Rule("WN10-00-000040", check: "check B, revised"));

        var outcome = ChecklistMerger.Merge(target, source, resetChangedRules: true);

        Assert.Equal(1, outcome.Changed);
        var vuln = target.AllVulnerabilities.Single();
        Assert.Equal(FindingStatus.NotReviewed, vuln.Status);
        Assert.Contains("reset to Not Reviewed", vuln.FindingDetails);
    }

    [Fact]
    public void MatchesByLegacyId_WhenRuleVersionDiffers()
    {
        var source = Doc(Rule("OLD-000010", FindingStatus.Open));
        source.Stigs[0].Vulnerabilities[0].LegacyIds.Add("V-9999");

        var target = Doc(Rule("NEW-000010"));
        target.Stigs[0].Vulnerabilities[0].LegacyIds.Add("V-9999");

        var outcome = ChecklistMerger.Merge(target, source, resetChangedRules: false);

        Assert.Equal(1, outcome.Carried);
        Assert.Equal(FindingStatus.Open, target.AllVulnerabilities.Single().Status);
    }

    [Fact]
    public void NoMatches_ReportsZeroCarried()
    {
        var source = Doc(Rule("AAA-1", FindingStatus.Open));
        var target = Doc(Rule("BBB-2"));

        var outcome = ChecklistMerger.Merge(target, source, resetChangedRules: false);

        Assert.Equal(0, outcome.Carried);
        Assert.Equal(1, outcome.NewRules);
        Assert.Equal(1, outcome.Removed);
        Assert.Equal(FindingStatus.NotReviewed, target.AllVulnerabilities.Single().Status);
    }
}

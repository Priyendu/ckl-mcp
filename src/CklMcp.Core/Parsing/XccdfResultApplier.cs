using System.IO;
using System.Xml;
using System.Xml.Linq;
using CklViewer.Models;

namespace CklViewer.Parsing;

public record XccdfRuleResult(string RuleIdRef, string RuleVersion, string Result);

public record XccdfApplyOutcome(int Matched, int Updated, int TotalResults, string BenchmarkId);

/// <summary>
/// Reads SCAP XCCDF result XML and applies pass/fail results to checklist findings,
/// matching by rule version (e.g. WN10-00-000005) or rule id (SV-…_rule).
/// </summary>
public static class XccdfResultApplier
{
    public static List<XccdfRuleResult> ParseFile(string path, out string benchmarkId)
    {
        using var stream = File.OpenRead(path);
        return Parse(stream, out benchmarkId);
    }

    public static List<XccdfRuleResult> Parse(Stream stream, out string benchmarkId)
    {
        using var reader = XmlReader.Create(stream, SafeXml.ReaderSettings);
        var xml = XDocument.Load(reader);
        var root = xml.Root ?? throw new InvalidDataException("Empty XCCDF document.");

        var testResults = root.Descendants().Where(e => e.Name.LocalName == "TestResult").ToList();
        if (testResults.Count == 0)
        {
            throw new InvalidDataException("No <TestResult> element found — this XCCDF file has no scan results.");
        }

        benchmarkId = testResults[0].Descendants().FirstOrDefault(e => e.Name.LocalName == "benchmark")
                          ?.Attribute("id")?.Value
                      ?? root.Attribute("id")?.Value
                      ?? "XCCDF scan";

        var results = new List<XccdfRuleResult>();
        foreach (var ruleResult in testResults.SelectMany(t => t.Elements().Where(e => e.Name.LocalName == "rule-result")))
        {
            var idref = ruleResult.Attribute("idref")?.Value ?? string.Empty;
            var version = ruleResult.Elements().FirstOrDefault(e => e.Name.LocalName == "version")?.Value ?? string.Empty;
            var result = ruleResult.Elements().FirstOrDefault(e => e.Name.LocalName == "result")?.Value ?? string.Empty;
            if (idref.Length > 0 || version.Length > 0)
            {
                results.Add(new XccdfRuleResult(idref, version, result.Trim().ToLowerInvariant()));
            }
        }

        return results;
    }

    public static XccdfApplyOutcome Apply(ChecklistDocument document, string xccdfPath)
    {
        var results = ParseFile(xccdfPath, out var benchmarkId);

        // Index checklist rules by rule version and by rule id (with and without the _rule suffix).
        var byKey = new Dictionary<string, Vulnerability>(StringComparer.OrdinalIgnoreCase);
        foreach (var vuln in document.AllVulnerabilities)
        {
            if (!string.IsNullOrWhiteSpace(vuln.RuleVersion))
            {
                byKey.TryAdd(vuln.RuleVersion, vuln);
            }

            if (!string.IsNullOrWhiteSpace(vuln.RuleId))
            {
                byKey.TryAdd(vuln.RuleId, vuln);
                byKey.TryAdd(TrimRuleSuffix(vuln.RuleId), vuln);
            }
        }

        int matched = 0, updated = 0;
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
        foreach (var result in results)
        {
            var vuln = Lookup(byKey, result.RuleVersion) ?? Lookup(byKey, result.RuleIdRef) ??
                       Lookup(byKey, TrimRuleSuffix(result.RuleIdRef));
            if (vuln is null)
            {
                continue;
            }

            matched++;
            FindingStatus? status = result.Result switch
            {
                "pass" or "fixed" => FindingStatus.NotAFinding,
                "fail" => FindingStatus.Open,
                "notapplicable" => FindingStatus.NotApplicable,
                _ => null // error, unknown, notchecked, notselected, informational: leave as-is
            };

            if (status is null)
            {
                continue;
            }

            vuln.Status = status.Value;
            var note = $"[{timestamp}] SCAP result '{result.Result}' applied from {benchmarkId}.";
            vuln.FindingDetails = string.IsNullOrWhiteSpace(vuln.FindingDetails)
                ? note
                : $"{vuln.FindingDetails}\n{note}";
            updated++;
        }

        return new XccdfApplyOutcome(matched, updated, results.Count, benchmarkId);
    }

    private static Vulnerability? Lookup(Dictionary<string, Vulnerability> index, string key) =>
        key.Length > 0 && index.TryGetValue(key, out var vuln) ? vuln : null;

    private static string TrimRuleSuffix(string ruleId)
    {
        // XCCDF idrefs often look like "xccdf_mil.disa.stig_rule_SV-220697r569187_rule".
        var id = ruleId;
        if (id.EndsWith("_rule", StringComparison.OrdinalIgnoreCase))
        {
            id = id[..^5];
        }

        var lastUnderscore = id.LastIndexOf('_');
        if (lastUnderscore >= 0 && id.Contains("xccdf", StringComparison.OrdinalIgnoreCase))
        {
            id = id[(lastUnderscore + 1)..];
        }

        return id;
    }
}

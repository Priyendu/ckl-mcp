using System.IO;
using System.IO.Compression;
using System.Xml;
using System.Xml.Linq;
using CklViewer.Models;

namespace CklViewer.Parsing;

/// <summary>
/// Builds a fresh checklist from a DISA STIG XCCDF benchmark — the "Manual"
/// <c>*-xccdf.xml</c> file, or the <c>.zip</c> it ships in. Every rule becomes a
/// Not Reviewed finding, populated with its discussion, check, fix, CCIs, and
/// severity, ready to assess and then save as .ckl / .cklb.
/// </summary>
public static class XccdfBenchmarkParser
{
    public static ChecklistDocument ParseFile(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        ChecklistDocument document;

        if (extension == ".zip")
        {
            using var xccdf = ExtractXccdf(path)
                ?? throw new InvalidDataException("No XCCDF benchmark (a *-xccdf.xml file) was found inside the zip.");
            document = Parse(xccdf);
        }
        else
        {
            using var stream = File.OpenRead(path);
            document = Parse(stream);
        }

        // A benchmark import is a brand-new, unsaved checklist — no source file to overwrite.
        document.SourcePath = null;
        document.Title ??= Path.GetFileNameWithoutExtension(path);
        return document;
    }

    public static ChecklistDocument Parse(Stream stream)
    {
        using var reader = XmlReader.Create(stream, SafeXml.ReaderSettings);
        var xml = XDocument.Load(reader);

        // Manual STIGs have a <Benchmark> root; SCAP source data streams wrap it deeper.
        var benchmark = (xml.Root?.Name.LocalName == "Benchmark" ? xml.Root : null)
                        ?? xml.Descendants().FirstOrDefault(e => e.Name.LocalName == "Benchmark")
                        ?? throw new InvalidDataException("No <Benchmark> element found — this is not an XCCDF STIG benchmark.");

        if (!benchmark.Elements().Any(e => e.Name.LocalName == "Group"))
        {
            throw new InvalidDataException("This XCCDF benchmark contains no rules to import.");
        }

        var document = new ChecklistDocument { SourceFormat = ChecklistFormat.Ckl };
        var stig = BuildStig(benchmark);
        document.Stigs.Add(stig);
        document.Title = string.IsNullOrWhiteSpace(stig.Title) ? null : stig.Title;
        return document;
    }

    private static Stig BuildStig(XElement benchmark)
    {
        string Child(string name) =>
            benchmark.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value ?? string.Empty;

        var title = Child("title");
        var version = Child("version");
        var releaseInfo = benchmark.Elements()
            .FirstOrDefault(e => e.Name.LocalName == "plain-text" && (string?)e.Attribute("id") == "release-info")
            ?.Value ?? string.Empty;

        var stig = new Stig
        {
            StigId = CleanStigId((string?)benchmark.Attribute("id") ?? string.Empty),
            Title = title,
            DisplayName = title,
            Version = version,
            ReleaseInfo = releaseInfo
        };

        // Seed the STIG_INFO block the CKL writer round-trips.
        stig.InfoData["title"] = title;
        stig.InfoData["version"] = version;
        stig.InfoData["releaseinfo"] = releaseInfo;
        stig.InfoData["stigid"] = stig.StigId;
        stig.InfoData["uuid"] = stig.Uuid;

        var stigRef = $"{title} :: Version {version}"
                      + (string.IsNullOrWhiteSpace(releaseInfo) ? string.Empty : $", {releaseInfo}");

        foreach (var group in benchmark.Elements().Where(e => e.Name.LocalName == "Group"))
        {
            var rule = group.Elements().FirstOrDefault(e => e.Name.LocalName == "Rule");
            if (rule is not null)
            {
                stig.Vulnerabilities.Add(BuildVuln(group, rule, stig, stigRef));
            }
        }

        return stig;
    }

    private static Vulnerability BuildVuln(XElement group, XElement rule, Stig stig, string stigRef)
    {
        string RuleChild(string name) =>
            rule.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value ?? string.Empty;

        var description = RuleChild("description");
        var check = rule.Elements().FirstOrDefault(e => e.Name.LocalName == "check");
        var checkContent = check?.Elements().FirstOrDefault(e => e.Name.LocalName == "check-content")?.Value ?? string.Empty;
        var checkRefName = (string?)check?.Elements()
            .FirstOrDefault(e => e.Name.LocalName == "check-content-ref")?.Attribute("name");

        var vuln = new Vulnerability
        {
            StigUuid = stig.Uuid,
            VulnId = (string?)group.Attribute("id") ?? string.Empty,
            RuleId = (string?)rule.Attribute("id") ?? string.Empty,
            RuleVersion = RuleChild("version"),
            RuleTitle = RuleChild("title"),
            GroupTitle = group.Elements().FirstOrDefault(e => e.Name.LocalName == "title")?.Value ?? string.Empty,
            SeverityValue = Severity.Normalize((string?)rule.Attribute("severity")),
            Weight = OrDefault((string?)rule.Attribute("weight"), "10.0"),
            Discussion = ExtractTag(description, "VulnDiscussion"),
            FalsePositives = ExtractTag(description, "FalsePositives"),
            FalseNegatives = ExtractTag(description, "FalseNegatives"),
            Documentable = OrDefault(ExtractTag(description, "Documentable"), "false"),
            Mitigations = ExtractTag(description, "Mitigations"),
            PotentialImpact = ExtractTag(description, "PotentialImpacts"),
            ThirdPartyTools = ExtractTag(description, "ThirdPartyTools"),
            MitigationControl = ExtractTag(description, "MitigationControl"),
            Responsibility = ExtractTag(description, "Responsibility"),
            IaControls = ExtractTag(description, "IAControls"),
            SecurityOverrideGuidance = ExtractTag(description, "SeverityOverrideGuidance"),
            FixText = RuleChild("fixtext"),
            CheckContent = checkContent,
            CheckContentRef = OrDefault(checkRefName, "M"),
            StigRef = stigRef,
            Status = FindingStatus.NotReviewed
        };

        foreach (var ident in rule.Elements().Where(e => e.Name.LocalName == "ident"))
        {
            var value = ident.Value?.Trim() ?? string.Empty;
            if (value.Length == 0)
            {
                continue;
            }

            if (value.StartsWith("CCI", StringComparison.OrdinalIgnoreCase))
            {
                vuln.Ccis.Add(value);
            }
            else
            {
                vuln.LegacyIds.Add(value);
            }
        }

        return vuln;
    }

    /// <summary>
    /// STIG rule descriptions embed pseudo-XML (VulnDiscussion, Documentable, …) whose
    /// inner text often contains unescaped &amp; and &lt; — so extract by tag boundaries
    /// rather than re-parsing it as XML.
    /// </summary>
    private static string ExtractTag(string blob, string tag)
    {
        if (string.IsNullOrEmpty(blob))
        {
            return string.Empty;
        }

        var open = $"<{tag}>";
        var start = blob.IndexOf(open, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return string.Empty;
        }

        start += open.Length;
        var end = blob.IndexOf($"</{tag}>", start, StringComparison.OrdinalIgnoreCase);
        return end < 0 ? string.Empty : blob[start..end].Trim();
    }

    private static string CleanStigId(string benchmarkId)
    {
        const string prefix = "xccdf_mil.disa.stig_benchmark_";
        return benchmarkId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? benchmarkId[prefix.Length..]
            : benchmarkId;
    }

    private static string OrDefault(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    /// <summary>Finds and returns the first XCCDF benchmark XML inside a STIG zip (one level of nesting).</summary>
    private static MemoryStream? ExtractXccdf(string zipPath)
    {
        using var archive = ZipFile.OpenRead(zipPath);
        return FindXccdf(archive, depth: 0);
    }

    private static MemoryStream? FindXccdf(ZipArchive archive, int depth)
    {
        var xmlEntries = archive.Entries
            .Where(e => e.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            .ToList();

        // Prefer the human-authored "Manual" benchmark; fall back to any xccdf-named xml.
        var match = xmlEntries.FirstOrDefault(e => e.Name.Contains("Manual-xccdf", StringComparison.OrdinalIgnoreCase))
                    ?? xmlEntries.FirstOrDefault(e => e.Name.Contains("xccdf", StringComparison.OrdinalIgnoreCase));

        if (match is not null)
        {
            var ms = new MemoryStream();
            using (var entryStream = match.Open())
            {
                entryStream.CopyTo(ms);
            }

            ms.Position = 0;
            return ms;
        }

        if (depth < 1)
        {
            foreach (var nested in archive.Entries.Where(e => e.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)))
            {
                using var buffer = new MemoryStream();
                using (var nestedStream = nested.Open())
                {
                    nestedStream.CopyTo(buffer);
                }

                buffer.Position = 0;
                using var innerArchive = new ZipArchive(buffer, ZipArchiveMode.Read);
                var found = FindXccdf(innerArchive, depth + 1);
                if (found is not null)
                {
                    return found;
                }
            }
        }

        return null;
    }
}

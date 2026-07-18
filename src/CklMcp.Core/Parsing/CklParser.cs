using System.IO;
using System.Xml;
using System.Xml.Linq;
using CklViewer.Models;

namespace CklViewer.Parsing;

/// <summary>Parses DISA STIG Viewer 2.x checklist (.ckl) XML files.</summary>
public static class CklParser
{
    public static ChecklistDocument ParseFile(string path)
    {
        using var stream = File.OpenRead(path);
        var document = Parse(stream);
        document.SourcePath = path;
        document.Title = Path.GetFileNameWithoutExtension(path);
        return document;
    }

    public static ChecklistDocument Parse(Stream stream)
    {
        using var reader = XmlReader.Create(stream, SafeXml.ReaderSettings);
        var xml = XDocument.Load(reader);
        var root = xml.Root ?? throw new InvalidDataException("Empty CKL document.");
        if (root.Name.LocalName != "CHECKLIST")
        {
            throw new InvalidDataException($"Expected a CHECKLIST root element but found <{root.Name.LocalName}>. Is this a CKL file?");
        }

        var document = new ChecklistDocument { SourceFormat = ChecklistFormat.Ckl };
        ParseAsset(root.Element("ASSET"), document.Asset);

        foreach (var istig in root.Elements("STIGS").Elements("iSTIG"))
        {
            document.Stigs.Add(ParseStig(istig));
        }

        return document;
    }

    private static void ParseAsset(XElement? assetElement, Asset asset)
    {
        if (assetElement is null)
        {
            return;
        }

        string Value(string name) => assetElement.Element(name)?.Value ?? string.Empty;

        asset.Role = ValueOr(Value("ROLE"), "None");
        asset.AssetType = ValueOr(Value("ASSET_TYPE"), "Computing");
        asset.Marking = Value("MARKING");
        asset.HostName = Value("HOST_NAME");
        asset.HostIp = Value("HOST_IP");
        asset.HostMac = Value("HOST_MAC");
        asset.HostFqdn = Value("HOST_FQDN");
        asset.TargetComment = Value("TARGET_COMMENT");
        asset.TechArea = Value("TECH_AREA");
        asset.TargetKey = Value("TARGET_KEY");
        asset.WebOrDatabase = string.Equals(Value("WEB_OR_DATABASE"), "true", StringComparison.OrdinalIgnoreCase);
        asset.WebDbSite = Value("WEB_DB_SITE");
        asset.WebDbInstance = Value("WEB_DB_INSTANCE");
    }

    private static Stig ParseStig(XElement istig)
    {
        var stig = new Stig();

        foreach (var siData in istig.Elements("STIG_INFO").Elements("SI_DATA"))
        {
            var name = siData.Element("SID_NAME")?.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            stig.InfoData[name] = siData.Element("SID_DATA")?.Value ?? string.Empty;
        }

        stig.StigId = stig.InfoData.GetValueOrDefault("stigid", string.Empty);
        stig.Title = stig.InfoData.GetValueOrDefault("title", string.Empty);
        stig.DisplayName = stig.Title;
        stig.Version = stig.InfoData.GetValueOrDefault("version", string.Empty);
        stig.ReleaseInfo = stig.InfoData.GetValueOrDefault("releaseinfo", string.Empty);
        if (stig.InfoData.TryGetValue("uuid", out var uuid) && !string.IsNullOrWhiteSpace(uuid))
        {
            stig.Uuid = uuid;
        }

        foreach (var vulnElement in istig.Elements("VULN"))
        {
            stig.Vulnerabilities.Add(ParseVuln(vulnElement, stig));
        }

        return stig;
    }

    private static Vulnerability ParseVuln(XElement vulnElement, Stig stig)
    {
        var attributes = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var stigData in vulnElement.Elements("STIG_DATA"))
        {
            var name = stigData.Element("VULN_ATTRIBUTE")?.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            if (!attributes.TryGetValue(name, out var values))
            {
                attributes[name] = values = new List<string>();
            }

            values.Add(stigData.Element("ATTRIBUTE_DATA")?.Value ?? string.Empty);
        }

        string First(string name) => attributes.TryGetValue(name, out var values) && values.Count > 0 ? values[0] : string.Empty;

        var vuln = new Vulnerability
        {
            StigUuid = stig.Uuid,
            VulnId = First("Vuln_Num"),
            RuleId = First("Rule_ID"),
            RuleVersion = First("Rule_Ver"),
            RuleTitle = First("Rule_Title"),
            GroupTitle = First("Group_Title"),
            SeverityValue = Severity.Normalize(First("Severity")),
            Discussion = First("Vuln_Discuss"),
            CheckContent = First("Check_Content"),
            FixText = First("Fix_Text"),
            IaControls = First("IA_Controls"),
            FalsePositives = First("False_Positives"),
            FalseNegatives = First("False_Negatives"),
            Documentable = ValueOr(First("Documentable"), "false"),
            Mitigations = First("Mitigations"),
            PotentialImpact = First("Potential_Impact"),
            ThirdPartyTools = First("Third_Party_Tools"),
            MitigationControl = First("Mitigation_Control"),
            Responsibility = First("Responsibility"),
            SecurityOverrideGuidance = First("Security_Override_Guidance"),
            CheckContentRef = ValueOr(First("Check_Content_Ref"), "M"),
            Weight = ValueOr(First("Weight"), "10.0"),
            Classification = First("Class"),
            StigRef = First("STIGRef"),
            TargetKey = First("TargetKey"),
            Status = FindingStatusExtensions.Parse(vulnElement.Element("STATUS")?.Value),
            FindingDetails = vulnElement.Element("FINDING_DETAILS")?.Value ?? string.Empty,
            Comments = vulnElement.Element("COMMENTS")?.Value ?? string.Empty,
            SeverityJustification = vulnElement.Element("SEVERITY_JUSTIFICATION")?.Value ?? string.Empty
        };

        var severityOverride = vulnElement.Element("SEVERITY_OVERRIDE")?.Value;
        vuln.SeverityOverride = string.IsNullOrWhiteSpace(severityOverride) ? string.Empty : Severity.Normalize(severityOverride);

        var stigUuid = First("STIG_UUID");
        if (!string.IsNullOrWhiteSpace(stigUuid))
        {
            vuln.StigUuid = stigUuid;
        }

        if (attributes.TryGetValue("CCI_REF", out var ccis))
        {
            vuln.Ccis.AddRange(ccis.Where(c => !string.IsNullOrWhiteSpace(c)));
        }

        if (attributes.TryGetValue("LEGACY_ID", out var legacyIds))
        {
            vuln.LegacyIds.AddRange(legacyIds.Where(id => !string.IsNullOrWhiteSpace(id)));
        }

        return vuln;
    }

    private static string ValueOr(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}

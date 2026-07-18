using System.IO;
using System.Text;
using System.Xml.Linq;
using CklViewer.Models;

namespace CklViewer.Writing;

/// <summary>Writes checklists back out as DISA STIG Viewer 2.x (.ckl) XML.</summary>
public static class CklWriter
{
    public static void WriteFile(ChecklistDocument document, string path)
    {
        using var stream = File.Create(path);
        Write(document, stream);
    }

    /// <summary>
    /// Drops characters that are not legal in XML 1.0 (e.g. control characters that
    /// JSON-based CKLB files may contain) so saving as CKL cannot fail mid-write.
    /// </summary>
    private static string XmlSafe(string value) =>
        value.Any(c => c is < ' ' and not ('\t' or '\n' or '\r'))
            ? new string(value.Where(c => c is >= ' ' or '\t' or '\n' or '\r').ToArray())
            : value;

    public static void Write(ChecklistDocument document, Stream stream)
    {
        var asset = document.Asset;
        var root = new XElement("CHECKLIST",
            new XElement("ASSET",
                new XElement("ROLE", XmlSafe(asset.Role)),
                new XElement("ASSET_TYPE", XmlSafe(asset.AssetType)),
                new XElement("MARKING", XmlSafe(asset.Marking)),
                new XElement("HOST_NAME", XmlSafe(asset.HostName)),
                new XElement("HOST_IP", XmlSafe(asset.HostIp)),
                new XElement("HOST_MAC", XmlSafe(asset.HostMac)),
                new XElement("HOST_FQDN", XmlSafe(asset.HostFqdn)),
                new XElement("TARGET_COMMENT", XmlSafe(asset.TargetComment)),
                new XElement("TECH_AREA", XmlSafe(asset.TechArea)),
                new XElement("TARGET_KEY", XmlSafe(asset.TargetKey)),
                new XElement("WEB_OR_DATABASE", asset.WebOrDatabase ? "true" : "false"),
                new XElement("WEB_DB_SITE", XmlSafe(asset.WebDbSite)),
                new XElement("WEB_DB_INSTANCE", XmlSafe(asset.WebDbInstance))),
            new XElement("STIGS", document.Stigs.Select(BuildStig)));

        var xml = new XDocument(new XDeclaration("1.0", "UTF-8", null),
            new XComment("Ckl-viewer :: DISA STIG checklist"),
            root);

        using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        xml.Save(writer);
    }

    private static XElement BuildStig(Stig stig)
    {
        // Preserve original SI_DATA when present, but make sure the core names exist.
        var info = new Dictionary<string, string>(stig.InfoData, StringComparer.OrdinalIgnoreCase);
        info.TryAdd("version", stig.Version);
        info.TryAdd("stigid", stig.StigId);
        info.TryAdd("title", stig.Title);
        info.TryAdd("releaseinfo", stig.ReleaseInfo);
        info.TryAdd("uuid", stig.Uuid);
        info["version"] = stig.Version;
        info["stigid"] = stig.StigId;
        info["title"] = stig.Title;
        info["releaseinfo"] = stig.ReleaseInfo;
        info["uuid"] = stig.Uuid;

        return new XElement("iSTIG",
            new XElement("STIG_INFO", info.Select(pair =>
                new XElement("SI_DATA",
                    new XElement("SID_NAME", XmlSafe(pair.Key)),
                    new XElement("SID_DATA", XmlSafe(pair.Value))))),
            stig.Vulnerabilities.Select(v => BuildVuln(v, stig)));
    }

    private static XElement BuildVuln(Vulnerability vuln, Stig stig)
    {
        var vulnElement = new XElement("VULN");

        void Add(string attribute, string value) =>
            vulnElement.Add(new XElement("STIG_DATA",
                new XElement("VULN_ATTRIBUTE", attribute),
                new XElement("ATTRIBUTE_DATA", XmlSafe(value))));

        Add("Vuln_Num", vuln.VulnId);
        Add("Severity", Severity.Normalize(vuln.SeverityValue));
        Add("Group_Title", vuln.GroupTitle);
        Add("Rule_ID", vuln.RuleId);
        Add("Rule_Ver", vuln.RuleVersion);
        Add("Rule_Title", vuln.RuleTitle);
        Add("Vuln_Discuss", vuln.Discussion);
        Add("IA_Controls", vuln.IaControls);
        Add("Check_Content", vuln.CheckContent);
        Add("Fix_Text", vuln.FixText);
        Add("False_Positives", vuln.FalsePositives);
        Add("False_Negatives", vuln.FalseNegatives);
        Add("Documentable", vuln.Documentable);
        Add("Mitigations", vuln.Mitigations);
        Add("Potential_Impact", vuln.PotentialImpact);
        Add("Third_Party_Tools", vuln.ThirdPartyTools);
        Add("Mitigation_Control", vuln.MitigationControl);
        Add("Responsibility", vuln.Responsibility);
        Add("Security_Override_Guidance", vuln.SecurityOverrideGuidance);
        Add("Check_Content_Ref", vuln.CheckContentRef);
        Add("Weight", vuln.Weight);
        Add("Class", vuln.Classification);
        Add("STIGRef", vuln.StigRef);
        Add("TargetKey", vuln.TargetKey);
        Add("STIG_UUID", string.IsNullOrWhiteSpace(vuln.StigUuid) ? stig.Uuid : vuln.StigUuid);

        foreach (var legacyId in vuln.LegacyIds)
        {
            Add("LEGACY_ID", legacyId);
        }

        foreach (var cci in vuln.Ccis)
        {
            Add("CCI_REF", cci);
        }

        vulnElement.Add(
            new XElement("STATUS", vuln.Status.ToCklString()),
            new XElement("FINDING_DETAILS", XmlSafe(vuln.FindingDetails)),
            new XElement("COMMENTS", XmlSafe(vuln.Comments)),
            new XElement("SEVERITY_OVERRIDE", vuln.SeverityOverride),
            new XElement("SEVERITY_JUSTIFICATION", XmlSafe(vuln.SeverityJustification)));

        return vulnElement;
    }
}

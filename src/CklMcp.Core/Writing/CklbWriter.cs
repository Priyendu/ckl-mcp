using System.IO;
using System.Text.Json;
using CklViewer.Models;

namespace CklViewer.Writing;

/// <summary>Writes checklists as DISA STIG Viewer 3.x (.cklb) JSON.</summary>
public static class CklbWriter
{
    public static void WriteFile(ChecklistDocument document, string path)
    {
        using var stream = File.Create(path);
        Write(document, stream);
    }

    public static void Write(ChecklistDocument document, Stream stream)
    {
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartObject();
        writer.WriteString("title", document.Title ?? document.Asset.HostName);
        writer.WriteString("id", document.Uuid);
        writer.WriteBoolean("active", false);
        writer.WriteNumber("mode", 1);
        writer.WriteBoolean("has_path", true);

        WriteTargetData(writer, document.Asset);

        writer.WriteStartArray("stigs");
        foreach (var stig in document.Stigs)
        {
            WriteStig(writer, stig);
        }
        writer.WriteEndArray();

        writer.WriteString("cklb_version", "1.0");
        writer.WriteEndObject();
    }

    private static void WriteTargetData(Utf8JsonWriter writer, Asset asset)
    {
        writer.WriteStartObject("target_data");
        writer.WriteString("target_type", asset.AssetType);
        writer.WriteString("host_name", asset.HostName);
        writer.WriteString("ip_address", asset.HostIp);
        writer.WriteString("mac_address", asset.HostMac);
        writer.WriteString("fqdn", asset.HostFqdn);
        writer.WriteString("comments", asset.TargetComment);
        writer.WriteString("role", asset.Role);
        writer.WriteBoolean("is_web_database", asset.WebOrDatabase);
        writer.WriteString("technology_area", asset.TechArea);
        writer.WriteString("web_db_site", asset.WebDbSite);
        writer.WriteString("web_db_instance", asset.WebDbInstance);
        writer.WriteString("marking", asset.Marking);
        writer.WriteString("target_key", asset.TargetKey);
        writer.WriteEndObject();
    }

    private static void WriteStig(Utf8JsonWriter writer, Stig stig)
    {
        writer.WriteStartObject();
        writer.WriteString("stig_name", stig.Title);
        writer.WriteString("display_name", string.IsNullOrWhiteSpace(stig.DisplayName) ? stig.Title : stig.DisplayName);
        writer.WriteString("stig_id", stig.StigId);
        writer.WriteString("release_info", stig.ReleaseInfo);
        writer.WriteString("version", stig.Version);
        writer.WriteString("uuid", stig.Uuid);
        writer.WriteString("reference_identifier", stig.ReferenceIdentifier);
        writer.WriteNumber("size", stig.Vulnerabilities.Count);

        writer.WriteStartArray("rules");
        foreach (var vuln in stig.Vulnerabilities)
        {
            WriteRule(writer, vuln, stig);
        }
        writer.WriteEndArray();

        writer.WriteEndObject();
    }

    private static void WriteRule(Utf8JsonWriter writer, Vulnerability vuln, Stig stig)
    {
        writer.WriteStartObject();
        writer.WriteString("uuid", vuln.Uuid);
        writer.WriteString("stig_uuid", string.IsNullOrWhiteSpace(vuln.StigUuid) ? stig.Uuid : vuln.StigUuid);
        writer.WriteString("target_key", vuln.TargetKey);
        writer.WriteString("group_id", vuln.VulnId);
        writer.WriteString("group_id_src", vuln.VulnId);
        writer.WriteString("group_title", vuln.GroupTitle);
        writer.WriteString("rule_id", vuln.RuleId);
        writer.WriteString("rule_id_src", vuln.RuleId);
        writer.WriteString("rule_version", vuln.RuleVersion);
        writer.WriteString("rule_title", vuln.RuleTitle);
        writer.WriteString("severity", Severity.Normalize(vuln.SeverityValue));
        writer.WriteString("weight", vuln.Weight);
        writer.WriteString("classification", vuln.Classification);
        writer.WriteString("discussion", vuln.Discussion);
        writer.WriteString("check_content", vuln.CheckContent);
        writer.WriteString("fix_text", vuln.FixText);
        writer.WriteString("false_positives", vuln.FalsePositives);
        writer.WriteString("false_negatives", vuln.FalseNegatives);
        writer.WriteString("documentable", vuln.Documentable);
        writer.WriteString("mitigations", vuln.Mitigations);
        writer.WriteString("potential_impacts", vuln.PotentialImpact);
        writer.WriteString("third_party_tools", vuln.ThirdPartyTools);
        writer.WriteString("mitigation_control", vuln.MitigationControl);
        writer.WriteString("responsibility", vuln.Responsibility);
        writer.WriteString("security_override_guidance", vuln.SecurityOverrideGuidance);
        writer.WriteString("ia_controls", vuln.IaControls);

        writer.WriteStartObject("check_content_ref");
        writer.WriteString("href", string.Empty);
        writer.WriteString("name", vuln.CheckContentRef);
        writer.WriteEndObject();

        writer.WriteStartArray("legacy_ids");
        foreach (var legacyId in vuln.LegacyIds)
        {
            writer.WriteStringValue(legacyId);
        }
        writer.WriteEndArray();

        writer.WriteStartArray("ccis");
        foreach (var cci in vuln.Ccis)
        {
            writer.WriteStringValue(cci);
        }
        writer.WriteEndArray();

        writer.WriteStartArray("group_tree");
        writer.WriteStartObject();
        writer.WriteString("id", vuln.VulnId);
        writer.WriteString("title", vuln.GroupTitle);
        writer.WriteString("description", "<GroupDescription></GroupDescription>");
        writer.WriteEndObject();
        writer.WriteEndArray();

        writer.WriteString("status", vuln.Status.ToCklbString());

        writer.WriteStartObject("overrides");
        if (!string.IsNullOrWhiteSpace(vuln.SeverityOverride))
        {
            writer.WriteStartObject("severity");
            writer.WriteString("severity", vuln.SeverityOverride);
            writer.WriteString("reason", vuln.SeverityJustification);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();

        writer.WriteString("comments", vuln.Comments);
        writer.WriteString("finding_details", vuln.FindingDetails);
        writer.WriteEndObject();
    }
}

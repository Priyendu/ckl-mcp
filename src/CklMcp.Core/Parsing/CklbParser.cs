using System.IO;
using System.Text.Json;
using CklViewer.Models;

namespace CklViewer.Parsing;

/// <summary>Parses DISA STIG Viewer 3.x checklist (.cklb) JSON files.</summary>
public static class CklbParser
{
    public static ChecklistDocument ParseFile(string path)
    {
        using var stream = File.OpenRead(path);
        var document = Parse(stream);
        document.SourcePath = path;
        document.Title ??= Path.GetFileNameWithoutExtension(path);
        return document;
    }

    public static ChecklistDocument Parse(Stream stream)
    {
        using var json = JsonDocument.Parse(stream);
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("stigs", out _))
        {
            throw new InvalidDataException("This does not look like a CKLB checklist (no \"stigs\" array).");
        }

        var document = new ChecklistDocument
        {
            SourceFormat = ChecklistFormat.Cklb,
            Title = GetString(root, "title"),
            Uuid = GetString(root, "id") is { Length: > 0 } id ? id : Guid.NewGuid().ToString()
        };

        if (root.TryGetProperty("target_data", out var target) && target.ValueKind == JsonValueKind.Object)
        {
            var asset = document.Asset;
            asset.AssetType = ValueOr(GetString(target, "target_type"), "Computing");
            asset.HostName = GetString(target, "host_name") ?? string.Empty;
            asset.HostIp = GetString(target, "ip_address") ?? string.Empty;
            asset.HostMac = GetString(target, "mac_address") ?? string.Empty;
            asset.HostFqdn = GetString(target, "fqdn") ?? string.Empty;
            asset.TargetComment = GetString(target, "comments") ?? string.Empty;
            asset.Role = ValueOr(GetString(target, "role"), "None");
            asset.TechArea = GetString(target, "technology_area") ?? string.Empty;
            asset.TargetKey = GetString(target, "target_key") ?? string.Empty;
            asset.WebDbSite = GetString(target, "web_db_site") ?? string.Empty;
            asset.WebDbInstance = GetString(target, "web_db_instance") ?? string.Empty;
            asset.Marking = GetString(target, "marking") ?? string.Empty;
            asset.WebOrDatabase = target.TryGetProperty("is_web_database", out var webDb) && webDb.ValueKind == JsonValueKind.True;
        }

        if (root.TryGetProperty("stigs", out var stigs) && stigs.ValueKind == JsonValueKind.Array)
        {
            foreach (var stigElement in stigs.EnumerateArray())
            {
                document.Stigs.Add(ParseStig(stigElement));
            }
        }

        return document;
    }

    private static Stig ParseStig(JsonElement element)
    {
        var stig = new Stig
        {
            StigId = GetString(element, "stig_id") ?? string.Empty,
            Title = ValueOr(GetString(element, "stig_name"), GetString(element, "display_name") ?? string.Empty),
            DisplayName = GetString(element, "display_name") ?? string.Empty,
            ReleaseInfo = GetString(element, "release_info") ?? string.Empty,
            ReferenceIdentifier = GetString(element, "reference_identifier") ?? string.Empty
        };

        if (element.TryGetProperty("version", out var version))
        {
            stig.Version = version.ValueKind == JsonValueKind.Number ? version.GetRawText() : version.GetString() ?? string.Empty;
        }

        if (GetString(element, "uuid") is { Length: > 0 } uuid)
        {
            stig.Uuid = uuid;
        }

        if (element.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Array)
        {
            foreach (var rule in rules.EnumerateArray())
            {
                stig.Vulnerabilities.Add(ParseRule(rule, stig));
            }
        }

        return stig;
    }

    private static Vulnerability ParseRule(JsonElement rule, Stig stig)
    {
        var vuln = new Vulnerability
        {
            Uuid = ValueOr(GetString(rule, "uuid"), Guid.NewGuid().ToString()),
            StigUuid = ValueOr(GetString(rule, "stig_uuid"), stig.Uuid),
            VulnId = GetString(rule, "group_id") ?? string.Empty,
            RuleId = GetString(rule, "rule_id") ?? string.Empty,
            RuleVersion = GetString(rule, "rule_version") ?? string.Empty,
            RuleTitle = GetString(rule, "rule_title") ?? string.Empty,
            GroupTitle = GetString(rule, "group_title") ?? string.Empty,
            SeverityValue = Severity.Normalize(GetString(rule, "severity")),
            Discussion = GetString(rule, "discussion") ?? string.Empty,
            CheckContent = GetString(rule, "check_content") ?? string.Empty,
            FixText = GetString(rule, "fix_text") ?? string.Empty,
            IaControls = GetString(rule, "ia_controls") ?? string.Empty,
            FalsePositives = GetString(rule, "false_positives") ?? string.Empty,
            FalseNegatives = GetString(rule, "false_negatives") ?? string.Empty,
            Documentable = ValueOr(GetString(rule, "documentable"), "false"),
            Mitigations = GetString(rule, "mitigations") ?? string.Empty,
            PotentialImpact = GetString(rule, "potential_impacts") ?? string.Empty,
            ThirdPartyTools = GetString(rule, "third_party_tools") ?? string.Empty,
            MitigationControl = GetString(rule, "mitigation_control") ?? string.Empty,
            Responsibility = GetString(rule, "responsibility") ?? string.Empty,
            SecurityOverrideGuidance = GetString(rule, "security_override_guidance") ?? string.Empty,
            Weight = ValueOr(GetString(rule, "weight"), "10.0"),
            Classification = GetString(rule, "classification") ?? string.Empty,
            StigRef = ValueOr(GetString(rule, "stig_ref"), stig.Title),
            TargetKey = GetString(rule, "target_key") ?? string.Empty,
            Status = FindingStatusExtensions.Parse(GetString(rule, "status")),
            FindingDetails = GetString(rule, "finding_details") ?? string.Empty,
            Comments = GetString(rule, "comments") ?? string.Empty
        };

        if (rule.TryGetProperty("check_content_ref", out var checkRef) && checkRef.ValueKind == JsonValueKind.Object)
        {
            vuln.CheckContentRef = ValueOr(GetString(checkRef, "name"), "M");
        }

        if (rule.TryGetProperty("ccis", out var ccis) && ccis.ValueKind == JsonValueKind.Array)
        {
            vuln.Ccis.AddRange(ccis.EnumerateArray()
                .Where(c => c.ValueKind == JsonValueKind.String)
                .Select(c => c.GetString()!)
                .Where(c => !string.IsNullOrWhiteSpace(c)));
        }

        if (rule.TryGetProperty("legacy_ids", out var legacyIds) && legacyIds.ValueKind == JsonValueKind.Array)
        {
            vuln.LegacyIds.AddRange(legacyIds.EnumerateArray()
                .Where(c => c.ValueKind == JsonValueKind.String)
                .Select(c => c.GetString()!)
                .Where(c => !string.IsNullOrWhiteSpace(c)));
        }

        if (rule.TryGetProperty("overrides", out var overrides) && overrides.ValueKind == JsonValueKind.Object &&
            overrides.TryGetProperty("severity", out var severityOverride) && severityOverride.ValueKind == JsonValueKind.Object)
        {
            vuln.SeverityOverride = Severity.Normalize(GetString(severityOverride, "severity"));
            vuln.SeverityJustification = GetString(severityOverride, "reason") ?? string.Empty;
        }

        return vuln;
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string ValueOr(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}

using CklViewer.Models;

namespace CklViewer.Merging;

/// <summary>The result of merging a prior-version checklist into a new-version one.</summary>
public record MergeOutcome(int Carried, int Unchanged, int Changed, int NewRules, int Removed);

/// <summary>
/// Carries a prior assessment forward into a new STIG release. The new-version checklist
/// (<c>target</c>) is authoritative on which rules exist; the old checklist (<c>source</c>)
/// supplies the assessment — status, finding details, comments, and severity override —
/// matched by rule version (then Vuln ID, then legacy IDs).
///
/// Rules whose check/fix text changed between versions are flagged with an audit note so the
/// assessor knows to re-verify, or reset to Not Reviewed when <c>resetChangedRules</c> is set.
/// </summary>
public static class ChecklistMerger
{
    public static MergeOutcome Merge(ChecklistDocument target, ChecklistDocument source, bool resetChangedRules)
    {
        var index = BuildIndex(source);
        var matchedSource = new HashSet<Vulnerability>();
        var stamp = DateTime.Now.ToString("yyyy-MM-dd");

        int carried = 0, unchanged = 0, changed = 0, newRules = 0;

        foreach (var targetVuln in target.AllVulnerabilities)
        {
            var sourceVuln = Lookup(index, targetVuln);
            if (sourceVuln is null)
            {
                newRules++;
                continue;
            }

            matchedSource.Add(sourceVuln);

            targetVuln.Status = sourceVuln.Status;
            targetVuln.FindingDetails = sourceVuln.FindingDetails;
            targetVuln.Comments = sourceVuln.Comments;
            targetVuln.SeverityOverride = sourceVuln.SeverityOverride;
            targetVuln.SeverityJustification = sourceVuln.SeverityJustification;
            carried++;

            if (RuleTextChanged(targetVuln, sourceVuln))
            {
                changed++;
                if (resetChangedRules)
                {
                    targetVuln.Status = FindingStatus.NotReviewed;
                    targetVuln.FindingDetails = Prepend(
                        $"[merge {stamp}] Rule text changed since the prior version; status reset to Not Reviewed for re-assessment.",
                        targetVuln.FindingDetails);
                }
                else
                {
                    targetVuln.FindingDetails = Append(
                        targetVuln.FindingDetails,
                        $"[merge {stamp}] Carried from the prior version; rule text changed — re-verify.");
                }
            }
            else
            {
                unchanged++;
            }
        }

        var removed = source.AllVulnerabilities.Count(v => !matchedSource.Contains(v));
        return new MergeOutcome(carried, unchanged, changed, newRules, removed);
    }

    private sealed class SourceIndex
    {
        public Dictionary<string, Vulnerability> ByRuleVersion { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Vulnerability> ByVulnId { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Vulnerability> ByLegacyId { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static SourceIndex BuildIndex(ChecklistDocument source)
    {
        var index = new SourceIndex();
        foreach (var vuln in source.AllVulnerabilities)
        {
            Add(index.ByRuleVersion, vuln.RuleVersion, vuln);
            Add(index.ByVulnId, vuln.VulnId, vuln);
            foreach (var legacy in vuln.LegacyIds)
            {
                Add(index.ByLegacyId, legacy, vuln);
            }
        }

        return index;
    }

    private static void Add(Dictionary<string, Vulnerability> map, string key, Vulnerability vuln)
    {
        if (!string.IsNullOrWhiteSpace(key))
        {
            map.TryAdd(key, vuln);
        }
    }

    // Match priority: rule version (stable across releases) → Vuln ID → any legacy ID.
    private static Vulnerability? Lookup(SourceIndex index, Vulnerability target)
    {
        if (Get(index.ByRuleVersion, target.RuleVersion) is { } byVersion)
        {
            return byVersion;
        }

        if (Get(index.ByVulnId, target.VulnId) is { } byVulnId)
        {
            return byVulnId;
        }

        foreach (var legacy in target.LegacyIds)
        {
            if (Get(index.ByLegacyId, legacy) is { } byLegacy)
            {
                return byLegacy;
            }
        }

        return null;
    }

    private static Vulnerability? Get(Dictionary<string, Vulnerability> map, string key) =>
        !string.IsNullOrWhiteSpace(key) && map.TryGetValue(key, out var vuln) ? vuln : null;

    private static bool RuleTextChanged(Vulnerability a, Vulnerability b) =>
        !Normalize(a.CheckContent).Equals(Normalize(b.CheckContent), StringComparison.Ordinal) ||
        !Normalize(a.FixText).Equals(Normalize(b.FixText), StringComparison.Ordinal);

    // Collapse whitespace so trivial reformatting isn't reported as a rule-text change.
    private static string Normalize(string value) =>
        string.Join(' ', (value ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static string Append(string existing, string note) =>
        string.IsNullOrWhiteSpace(existing) ? note : $"{existing}\n{note}";

    private static string Prepend(string note, string existing) =>
        string.IsNullOrWhiteSpace(existing) ? note : $"{note}\n{existing}";
}

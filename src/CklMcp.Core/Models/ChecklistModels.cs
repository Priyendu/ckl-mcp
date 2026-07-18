using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace CklViewer.Models;

public enum ChecklistFormat
{
    Ckl,
    Cklb
}

public enum FindingStatus
{
    NotReviewed,
    Open,
    NotAFinding,
    NotApplicable
}

public static class FindingStatusExtensions
{
    public static string ToCklString(this FindingStatus status) => status switch
    {
        FindingStatus.Open => "Open",
        FindingStatus.NotAFinding => "NotAFinding",
        FindingStatus.NotApplicable => "Not_Applicable",
        _ => "Not_Reviewed"
    };

    public static string ToCklbString(this FindingStatus status) => status switch
    {
        FindingStatus.Open => "open",
        FindingStatus.NotAFinding => "not_a_finding",
        FindingStatus.NotApplicable => "not_applicable",
        _ => "not_reviewed"
    };

    public static string ToDisplayString(this FindingStatus status) => status switch
    {
        FindingStatus.Open => "Open",
        FindingStatus.NotAFinding => "Not a Finding",
        FindingStatus.NotApplicable => "Not Applicable",
        _ => "Not Reviewed"
    };

    public static FindingStatus Parse(string? value)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant().Replace("_", "").Replace(" ", "");
        return normalized switch
        {
            "open" => FindingStatus.Open,
            "notafinding" => FindingStatus.NotAFinding,
            "notapplicable" => FindingStatus.NotApplicable,
            _ => FindingStatus.NotReviewed
        };
    }
}

public static class Severity
{
    public const string High = "high";
    public const string Medium = "medium";
    public const string Low = "low";

    public static string Normalize(string? value)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "high" or "cat i" or "cat_i" or "1" => High,
            "low" or "cat iii" or "cat_iii" or "3" => Low,
            _ => Medium
        };
    }

    public static string ToCategory(string? severity) => Normalize(severity) switch
    {
        High => "CAT I",
        Low => "CAT III",
        _ => "CAT II"
    };
}

public class ChecklistDocument
{
    public Asset Asset { get; set; } = new();
    public List<Stig> Stigs { get; } = new();
    public string? SourcePath { get; set; }
    public ChecklistFormat SourceFormat { get; set; }
    public string? Title { get; set; }
    public string Uuid { get; set; } = Guid.NewGuid().ToString();

    public IEnumerable<Vulnerability> AllVulnerabilities => Stigs.SelectMany(s => s.Vulnerabilities);
}

public class Asset : INotifyPropertyChanged
{
    private string _role = "None";
    private string _assetType = "Computing";
    private string _marking = "CUI";
    private string _hostName = string.Empty;
    private string _hostIp = string.Empty;
    private string _hostMac = string.Empty;
    private string _hostFqdn = string.Empty;
    private string _targetComment = string.Empty;
    private string _techArea = string.Empty;
    private string _targetKey = string.Empty;
    private bool _webOrDatabase;
    private string _webDbSite = string.Empty;
    private string _webDbInstance = string.Empty;

    public string Role { get => _role; set => Set(ref _role, value); }
    public string AssetType { get => _assetType; set => Set(ref _assetType, value); }
    public string Marking { get => _marking; set => Set(ref _marking, value); }
    public string HostName { get => _hostName; set => Set(ref _hostName, value); }
    public string HostIp { get => _hostIp; set => Set(ref _hostIp, value); }
    public string HostMac { get => _hostMac; set => Set(ref _hostMac, value); }
    public string HostFqdn { get => _hostFqdn; set => Set(ref _hostFqdn, value); }
    public string TargetComment { get => _targetComment; set => Set(ref _targetComment, value); }
    public string TechArea { get => _techArea; set => Set(ref _techArea, value); }
    public string TargetKey { get => _targetKey; set => Set(ref _targetKey, value); }
    public bool WebOrDatabase { get => _webOrDatabase; set => Set(ref _webOrDatabase, value); }
    public string WebDbSite { get => _webDbSite; set => Set(ref _webDbSite, value); }
    public string WebDbInstance { get => _webDbInstance; set => Set(ref _webDbInstance, value); }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (!EqualityComparer<T>.Default.Equals(field, value))
        {
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}

public class Stig
{
    public string StigId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string ReleaseInfo { get; set; } = string.Empty;
    public string Uuid { get; set; } = Guid.NewGuid().ToString();
    public string ReferenceIdentifier { get; set; } = string.Empty;

    /// <summary>Raw STIG_INFO SI_DATA name/value pairs preserved for CKL round-trips.</summary>
    public Dictionary<string, string> InfoData { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ObservableCollection<Vulnerability> Vulnerabilities { get; } = new();
}

public class Vulnerability : INotifyPropertyChanged
{
    private FindingStatus _status = FindingStatus.NotReviewed;
    private string _findingDetails = string.Empty;
    private string _comments = string.Empty;
    private string _severityOverride = string.Empty;
    private string _severityJustification = string.Empty;

    public string Uuid { get; set; } = Guid.NewGuid().ToString();
    public string StigUuid { get; set; } = string.Empty;
    public string VulnId { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string RuleVersion { get; set; } = string.Empty;
    public string RuleTitle { get; set; } = string.Empty;
    public string GroupTitle { get; set; } = string.Empty;
    public string SeverityValue { get; set; } = Severity.Medium;
    public string Discussion { get; set; } = string.Empty;
    public string CheckContent { get; set; } = string.Empty;
    public string FixText { get; set; } = string.Empty;
    public string IaControls { get; set; } = string.Empty;
    public string FalsePositives { get; set; } = string.Empty;
    public string FalseNegatives { get; set; } = string.Empty;
    public string Documentable { get; set; } = "false";
    public string Mitigations { get; set; } = string.Empty;
    public string PotentialImpact { get; set; } = string.Empty;
    public string ThirdPartyTools { get; set; } = string.Empty;
    public string MitigationControl { get; set; } = string.Empty;
    public string Responsibility { get; set; } = string.Empty;
    public string SecurityOverrideGuidance { get; set; } = string.Empty;
    public string CheckContentRef { get; set; } = "M";
    public string Weight { get; set; } = "10.0";
    public string Classification { get; set; } = string.Empty;
    public string StigRef { get; set; } = string.Empty;
    public string TargetKey { get; set; } = string.Empty;
    public List<string> LegacyIds { get; } = new();
    public List<string> Ccis { get; } = new();

    public FindingStatus Status { get => _status; set => Set(ref _status, value, alsoNotify: nameof(StatusDisplay)); }
    public string FindingDetails { get => _findingDetails; set => Set(ref _findingDetails, value); }
    public string Comments { get => _comments; set => Set(ref _comments, value); }

    /// <summary>Empty, or a normalized severity ("low"/"medium"/"high") overriding <see cref="SeverityValue"/>.</summary>
    public string SeverityOverride
    {
        get => _severityOverride;
        set => Set(ref _severityOverride, value, alsoNotify: nameof(Category));
    }

    public string SeverityJustification { get => _severityJustification; set => Set(ref _severityJustification, value); }

    public string EffectiveSeverity => string.IsNullOrWhiteSpace(SeverityOverride) ? SeverityValue : SeverityOverride;
    public string Category => Severity.ToCategory(EffectiveSeverity);
    public string StatusDisplay => Status.ToDisplayString();
    public string CciDisplay => string.Join(", ", Ccis);

    /// <summary>
    /// Sort key for the Status column so a header click surfaces the findings that
    /// need action first: Open, then Not Reviewed, then Not a Finding, then Not Applicable.
    /// </summary>
    public int StatusSortOrder => Status switch
    {
        FindingStatus.Open => 0,
        FindingStatus.NotReviewed => 1,
        FindingStatus.NotAFinding => 2,
        FindingStatus.NotApplicable => 3,
        _ => 4
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null, string? alsoNotify = null)
    {
        if (!EqualityComparer<T>.Default.Equals(field, value))
        {
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
            if (alsoNotify is not null)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(alsoNotify));
            }
        }
    }
}

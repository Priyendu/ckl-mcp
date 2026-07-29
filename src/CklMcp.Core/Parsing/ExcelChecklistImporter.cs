using System.IO;
using ClosedXML.Excel;
using CklViewer.Models;

namespace CklViewer.Parsing;

/// <summary>What an Excel import produced, for reporting back to the user.</summary>
public record ExcelImportOutcome(IReadOnlyList<ChecklistDocument> Documents, int Rows, int TruncatedFields);

/// <summary>
/// Rebuilds checklists from an Excel report's "Vulnerability Details" sheet, so an
/// assessment edited in Excel can be saved back out as .ckl / .cklb.
///
/// Columns are located by header name rather than position, so a hand-built or
/// re-ordered spreadsheet works as long as the headers match. Rows are grouped into
/// one checklist per Asset, and one STIG per distinct STIG name within that asset.
/// </summary>
public static class ExcelChecklistImporter
{
    private const string DetailsSheetName = "Vulnerability Details";
    private const string SummarySheetName = "Executive Summary";

    /// <summary>Marker appended by the report writer when a cell hit Excel's length limit.</summary>
    internal const string TruncationMarker = " …";

    public static IReadOnlyList<ChecklistDocument> ImportFile(string path) => Import(path).Documents;

    public static ExcelImportOutcome Import(string path)
    {
        using var workbook = new XLWorkbook(path);
        var sheet = FindDetailsSheet(workbook)
                    ?? throw new InvalidDataException(
                        $"No usable sheet found. Expected a \"{DetailsSheetName}\" sheet (or any sheet with " +
                        "\"Rule Version\"/\"Vuln ID\" and \"Status\" columns). The POA&M sheet alone is not enough — " +
                        "it only lists open findings.");

        var columns = MapHeaders(sheet);
        RequireColumn(columns, "status", "Status");
        if (!columns.ContainsKey("ruleversion") && !columns.ContainsKey("vulnid"))
        {
            throw new InvalidDataException("The sheet needs a \"Rule Version\" or \"Vuln ID\" column to identify each rule.");
        }

        var versions = ReadVersionLookup(workbook);

        // Preserve the sheet's ordering of assets, STIGs, and rules.
        var documents = new List<ChecklistDocument>();
        var byAsset = new Dictionary<string, ChecklistDocument>(StringComparer.OrdinalIgnoreCase);
        var stigsByKey = new Dictionary<(string Asset, string Stig), Stig>();
        int rows = 0, truncated = 0;

        var headerRow = sheet.FirstRowUsed()?.RowNumber() ?? 1;
        var lastRow = sheet.LastRowUsed()?.RowNumber() ?? headerRow;

        for (var r = headerRow + 1; r <= lastRow; r++)
        {
            string Cell(string key) =>
                columns.TryGetValue(key, out var col) ? sheet.Cell(r, col).GetString().Trim() : string.Empty;

            var ruleVersion = Cell("ruleversion");
            var vulnId = Cell("vulnid");
            if (ruleVersion.Length == 0 && vulnId.Length == 0)
            {
                continue; // blank or spacer row
            }

            var assetName = Fallback(Cell("asset"), "(unnamed asset)");
            var stigName = Fallback(Cell("stig"), "Imported STIG");

            if (!byAsset.TryGetValue(assetName, out var document))
            {
                document = new ChecklistDocument
                {
                    Title = assetName,
                    SourceFormat = ChecklistFormat.Ckl
                    // SourcePath stays null: an import is unsaved, so Save prompts for a location.
                };
                document.Asset.HostName = assetName == "(unnamed asset)" ? string.Empty : assetName;
                byAsset[assetName] = document;
                documents.Add(document);
            }

            var stigKey = (assetName, stigName);
            if (!stigsByKey.TryGetValue(stigKey, out var stig))
            {
                versions.TryGetValue((assetName, stigName), out var versionInfo);
                stig = new Stig
                {
                    Title = stigName,
                    DisplayName = stigName,
                    StigId = stigName,
                    Version = versionInfo.Version ?? string.Empty,
                    ReleaseInfo = versionInfo.Release ?? string.Empty
                };
                stigsByKey[stigKey] = stig;
                document.Stigs.Add(stig);
            }

            var vuln = new Vulnerability
            {
                StigUuid = stig.Uuid,
                VulnId = vulnId,
                RuleId = Cell("ruleid"),
                RuleVersion = ruleVersion,
                RuleTitle = Cell("ruletitle"),
                GroupTitle = ruleVersion,
                SeverityValue = Severity.Normalize(Fallback(Cell("severity"), Severity.Medium)),
                Status = FindingStatusExtensions.Parse(Cell("status")),
                Discussion = Cell("discussion"),
                CheckContent = Cell("checkcontent"),
                FixText = Cell("fixtext"),
                FindingDetails = Cell("findingdetails"),
                Comments = Cell("comments"),
                StigRef = stigName
            };

            var severityOverride = Cell("severityoverride");
            vuln.SeverityOverride = severityOverride.Length == 0 ? string.Empty : Severity.Normalize(severityOverride);

            foreach (var cci in Cell("ccireferences").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                vuln.Ccis.Add(cci);
            }

            truncated += CountTruncated(vuln);
            stig.Vulnerabilities.Add(vuln);
            rows++;
        }

        if (rows == 0)
        {
            throw new InvalidDataException("The sheet has headers but no finding rows to import.");
        }

        return new ExcelImportOutcome(documents, rows, truncated);
    }

    private static IXLWorksheet? FindDetailsSheet(XLWorkbook workbook)
    {
        var named = workbook.Worksheets.FirstOrDefault(w =>
            string.Equals(w.Name, DetailsSheetName, StringComparison.OrdinalIgnoreCase));
        if (named is not null && HasRequiredHeaders(named))
        {
            return named;
        }

        return workbook.Worksheets.FirstOrDefault(HasRequiredHeaders);
    }

    private static bool HasRequiredHeaders(IXLWorksheet sheet)
    {
        var columns = MapHeaders(sheet);
        return columns.ContainsKey("status") &&
               (columns.ContainsKey("ruleversion") || columns.ContainsKey("vulnid"));
    }

    /// <summary>Maps normalized header text ("Rule Version" → "ruleversion") to its column number.</summary>
    private static Dictionary<string, int> MapHeaders(IXLWorksheet sheet)
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        var headerRow = sheet.FirstRowUsed();
        if (headerRow is null)
        {
            return map;
        }

        foreach (var cell in headerRow.CellsUsed())
        {
            var key = Normalize(cell.GetString());
            if (key.Length > 0)
            {
                map.TryAdd(key, cell.Address.ColumnNumber);
            }
        }

        return map;
    }

    private static string Normalize(string header) =>
        new(header.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());

    private static void RequireColumn(Dictionary<string, int> columns, string key, string display)
    {
        if (!columns.ContainsKey(key))
        {
            throw new InvalidDataException($"The sheet is missing a \"{display}\" column.");
        }
    }

    /// <summary>
    /// Reads the Executive Summary (when present) so imported STIGs keep their version and
    /// release info, which the details rows don't carry.
    /// </summary>
    private static Dictionary<(string Asset, string Stig), (string? Version, string? Release)> ReadVersionLookup(XLWorkbook workbook)
    {
        var lookup = new Dictionary<(string, string), (string?, string?)>();
        var sheet = workbook.Worksheets.FirstOrDefault(w =>
            string.Equals(w.Name, SummarySheetName, StringComparison.OrdinalIgnoreCase));
        if (sheet is null)
        {
            return lookup;
        }

        try
        {
            foreach (var row in sheet.RowsUsed())
            {
                var asset = row.Cell(1).GetString().Trim();
                var stig = row.Cell(2).GetString().Trim();
                var versionRelease = row.Cell(3).GetString().Trim();
                if (asset.Length == 0 || stig.Length == 0 || versionRelease.Length == 0 ||
                    string.Equals(asset, "Asset", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Written as "V2 Release: 8 Benchmark Date: 09 Nov 2023".
                var text = versionRelease.TrimStart('V', 'v');
                var split = text.IndexOf(' ');
                var version = split < 0 ? text : text[..split];
                var release = split < 0 ? string.Empty : text[(split + 1)..].Trim();
                lookup.TryAdd((asset, stig), (version, release));
            }
        }
        catch
        {
            // A non-standard summary sheet just means no version info; never block the import.
        }

        return lookup;
    }

    /// <summary>Counts fields that were cut short by the report's cell limit (older reports capped text harder).</summary>
    public static int CountTruncatedFields(ChecklistDocument document) =>
        document.AllVulnerabilities.Sum(CountTruncated);

    private static int CountTruncated(Vulnerability vuln)
    {
        var fields = new[]
        {
            vuln.RuleTitle, vuln.Discussion, vuln.CheckContent, vuln.FixText,
            vuln.FindingDetails, vuln.Comments
        };
        return fields.Count(f => f.EndsWith(TruncationMarker, StringComparison.Ordinal));
    }

    private static string Fallback(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}

using CklViewer.Models;

namespace CklViewer.Tests;

public static class SampleData
{
    public static ChecklistDocument BuildChecklist()
    {
        var document = new ChecklistDocument
        {
            Title = "SAMPLE-HOST Windows 10 STIG",
            SourceFormat = ChecklistFormat.Ckl
        };

        document.Asset.HostName = "SAMPLE-HOST";
        document.Asset.HostIp = "10.0.0.5";
        document.Asset.HostFqdn = "sample-host.example.mil";
        document.Asset.Marking = "CUI";

        var stig = new Stig
        {
            StigId = "MS_Windows_10_STIG",
            Title = "Microsoft Windows 10 Security Technical Implementation Guide",
            Version = "2",
            ReleaseInfo = "Release: 8 Benchmark Date: 09 Nov 2023"
        };
        stig.InfoData["classification"] = "UNCLASSIFIED";

        var open = new Vulnerability
        {
            VulnId = "V-220697",
            RuleId = "SV-220697r569187_rule",
            RuleVersion = "WN10-00-000005",
            RuleTitle = "Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version.",
            GroupTitle = "WN10-00-000005",
            SeverityValue = Severity.Medium,
            Discussion = "Features such as Credential Guard use virtualization based security to protect information.",
            CheckContent = "Verify domain-joined systems are using Windows 10 Enterprise Edition 64-bit.",
            FixText = "Use Windows 10 Enterprise 64-bit version for domain-joined systems.",
            StigRef = "Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 8",
            Status = FindingStatus.Open,
            FindingDetails = "System is running Windows 10 Pro.",
            Comments = "Upgrade scheduled."
        };
        open.Ccis.Add("CCI-000366");
        open.LegacyIds.Add("V-63319");

        var catI = new Vulnerability
        {
            VulnId = "V-220706",
            RuleId = "SV-220706r569187_rule",
            RuleVersion = "WN10-00-000040",
            RuleTitle = "Windows 10 systems must be maintained at a supported servicing level.",
            GroupTitle = "WN10-00-000040",
            SeverityValue = Severity.High,
            Discussion = "Systems at unsupported servicing levels will not receive security updates.",
            CheckContent = "Run winver.exe and verify the servicing level.",
            FixText = "Update systems to a supported servicing level.",
            Status = FindingStatus.NotAFinding
        };
        catI.Ccis.Add("CCI-000366");

        var notReviewed = new Vulnerability
        {
            VulnId = "V-220710",
            RuleId = "SV-220710r569187_rule",
            RuleVersion = "WN10-00-000045",
            RuleTitle = "Windows 10 must employ automated mechanisms to determine the state of system components.",
            GroupTitle = "WN10-00-000045",
            SeverityValue = Severity.Low,
            Discussion = "Timely patching is critical.",
            CheckContent = "Verify the ESS software is installed and running.",
            FixText = "Install the ESS software.",
            Status = FindingStatus.NotReviewed
        };

        stig.Vulnerabilities.Add(open);
        stig.Vulnerabilities.Add(catI);
        stig.Vulnerabilities.Add(notReviewed);
        document.Stigs.Add(stig);
        return document;
    }

    public const string XccdfResult = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_mil.disa.stig_benchmark_MS_Windows_10_STIG">
          <TestResult id="xccdf_mil.disa.stig_testresult_scap_mil.disa_comp_MS_Windows_10_STIG">
            <benchmark href="benchmark.xml" id="xccdf_mil.disa.stig_benchmark_MS_Windows_10_STIG" />
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-220697r569187_rule" time="2026-07-15T09:00:00">
              <result>pass</result>
              <version>WN10-00-000005</version>
            </rule-result>
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-220706r569187_rule" time="2026-07-15T09:00:00">
              <result>fail</result>
              <version>WN10-00-000040</version>
            </rule-result>
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-220710r569187_rule" time="2026-07-15T09:00:00">
              <result>notapplicable</result>
              <version>WN10-00-000045</version>
            </rule-result>
          </TestResult>
        </Benchmark>
        """;
}

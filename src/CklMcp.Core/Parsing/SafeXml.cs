using System.Xml;

namespace CklViewer.Parsing;

/// <summary>
/// Hardened XML reader settings for untrusted checklist and scan-result files:
/// DTDs are rejected (blocks XXE and entity-expansion attacks) and external
/// resources are never resolved. .NET defaults already prohibit DTDs, but this
/// makes the guarantee explicit so a refactor cannot silently regress it.
/// </summary>
public static class SafeXml
{
    public static XmlReaderSettings ReaderSettings { get; } = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        CloseInput = false
    };
}

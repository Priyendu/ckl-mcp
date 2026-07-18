using System.IO;
using System.Xml;
using CklViewer.Models;

namespace CklViewer.Parsing;

/// <summary>
/// Loads a checklist from disk, detecting the format by extension and content:
/// CKL (XML checklist), CKLB (JSON checklist), or an XCCDF STIG benchmark
/// (.xml / .zip) which is imported into a fresh Not-Reviewed checklist.
/// </summary>
public static class ChecklistLoader
{
    public static ChecklistDocument Load(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        switch (extension)
        {
            case ".cklb":
            case ".json":
                return CklbParser.ParseFile(path);
            case ".zip":
                return XccdfBenchmarkParser.ParseFile(path);
            case ".ckl":
                return CklParser.ParseFile(path);
        }

        // .xml or unknown: an XCCDF benchmark and a CKL checklist are both XML,
        // so decide by the root element name.
        var root = PeekRootLocalName(path);
        if (string.Equals(root, "Benchmark", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(root, "data-stream-collection", StringComparison.OrdinalIgnoreCase))
        {
            return XccdfBenchmarkParser.ParseFile(path);
        }

        if (string.Equals(root, "CHECKLIST", StringComparison.OrdinalIgnoreCase))
        {
            return CklParser.ParseFile(path);
        }

        if (root is null)
        {
            // Not XML: sniff for a JSON checklist by its opening brace.
            using var reader = new StreamReader(path);
            int ch;
            while ((ch = reader.Read()) != -1 && char.IsWhiteSpace((char)ch))
            {
            }

            if (ch == '{')
            {
                return CklbParser.ParseFile(path);
            }
        }

        return CklParser.ParseFile(path);
    }

    /// <summary>Returns the local name of the first element in an XML file, or null if it isn't XML.</summary>
    private static string? PeekRootLocalName(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = XmlReader.Create(stream, SafeXml.ReaderSettings);
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    return reader.LocalName;
                }
            }
        }
        catch (XmlException)
        {
            // Not well-formed XML — fall through to the non-XML handling.
        }

        return null;
    }
}

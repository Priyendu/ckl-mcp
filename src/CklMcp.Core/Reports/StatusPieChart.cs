using System.IO;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;

namespace CklViewer.Reports;

/// <summary>
/// Injects a native Excel pie chart of the finding statuses onto the Executive Summary
/// sheet, referencing the status-totals block that <see cref="ExcelReportGenerator"/> writes.
/// ClosedXML has no chart support, so the chart part XML is authored directly.
/// </summary>
internal static class StatusPieChart
{
    private const string SpreadsheetDrawingNs = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing";
    private const string ChartNs = "http://schemas.openxmlformats.org/drawingml/2006/chart";
    private const string DrawingNs = "http://schemas.openxmlformats.org/drawingml/2006/main";
    private const string RelNs = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

    // Slice colors, in the same order as the totals block (Open, NAF, N/A, NR) — the donut palette.
    private static readonly string[] SliceColors = { "E74C3C", "27AE60", "9AA7AD", "F0B400" };

    public static byte[] Inject(byte[] workbookBytes)
    {
        using var stream = new MemoryStream();
        stream.Write(workbookBytes, 0, workbookBytes.Length);
        stream.Position = 0;

        using (var document = SpreadsheetDocument.Open(stream, isEditable: true))
        {
            var workbookPart = document.WorkbookPart!;
            var sheet = workbookPart.Workbook.Descendants<Sheet>()
                .FirstOrDefault(s => s.Name == ExcelReportGenerator.SummarySheetName);
            if (sheet?.Id?.Value is null)
            {
                return workbookBytes;
            }

            var worksheetPart = (WorksheetPart)workbookPart.GetPartById(sheet.Id.Value);

            var drawingsPart = worksheetPart.AddNewPart<DrawingsPart>();
            var chartPart = drawingsPart.AddNewPart<ChartPart>();
            var chartRelId = drawingsPart.GetIdOfPart(chartPart);

            WriteXml(chartPart, ChartXml());
            WriteXml(drawingsPart, DrawingXml(chartRelId));

            var drawingRelId = worksheetPart.GetIdOfPart(drawingsPart);
            var worksheet = worksheetPart.Worksheet;
            var drawing = new Drawing { Id = drawingRelId };

            // In CT_Worksheet, <drawing> must precede these trailing elements. Insert it there
            // rather than appending, or the package fails schema validation and Excel repairs it.
            var trailing = worksheet.Elements().FirstOrDefault(e =>
                e is TableParts or ExtensionList or LegacyDrawing or Picture or OleObjects
                  or DocumentFormat.OpenXml.Spreadsheet.Controls or WebPublishItems);
            if (trailing is not null)
            {
                worksheet.InsertBefore(drawing, trailing);
            }
            else
            {
                worksheet.Append(drawing);
            }

            worksheet.Save();
        }

        return stream.ToArray();
    }

    private static void WriteXml(OpenXmlPart part, string xml)
    {
        using var partStream = part.GetStream(FileMode.Create, FileAccess.Write);
        using var writer = new StreamWriter(partStream);
        writer.Write(xml);
    }

    private static string ChartXml()
    {
        var labels = $"'{ExcelReportGenerator.SummarySheetName}'!$M${ExcelReportGenerator.StatusTotalsRow}:$M${ExcelReportGenerator.StatusTotalsRow + 3}";
        var values = $"'{ExcelReportGenerator.SummarySheetName}'!$N${ExcelReportGenerator.StatusTotalsRow}:$N${ExcelReportGenerator.StatusTotalsRow + 3}";

        var dataPoints = string.Concat(SliceColors.Select((color, i) =>
            $"<c:dPt><c:idx val=\"{i}\"/><c:bubble3D val=\"0\"/>" +
            $"<c:spPr><a:solidFill><a:srgbClr val=\"{color}\"/></a:solidFill></c:spPr></c:dPt>"));

        return
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            $"<c:chartSpace xmlns:c=\"{ChartNs}\" xmlns:a=\"{DrawingNs}\" xmlns:r=\"{RelNs}\">" +
            "<c:chart>" +
            "<c:title><c:tx><c:rich><a:bodyPr/><a:p><a:r><a:t>Findings by status</a:t></a:r></a:p></c:rich></c:tx><c:overlay val=\"0\"/></c:title>" +
            "<c:autoTitleDeleted val=\"0\"/>" +
            "<c:plotArea><c:layout/>" +
            "<c:pieChart><c:varyColors val=\"1\"/>" +
            "<c:ser><c:idx val=\"0\"/><c:order val=\"0\"/>" +
            dataPoints +
            $"<c:cat><c:strRef><c:f>{labels}</c:f></c:strRef></c:cat>" +
            $"<c:val><c:numRef><c:f>{values}</c:f></c:numRef></c:val>" +
            "</c:ser>" +
            "<c:firstSliceAng val=\"0\"/>" +
            "</c:pieChart>" +
            "</c:plotArea>" +
            "<c:legend><c:legendPos val=\"r\"/><c:overlay val=\"0\"/></c:legend>" +
            "<c:plotVisOnly val=\"1\"/>" +
            "</c:chart>" +
            "</c:chartSpace>";
    }

    private static string DrawingXml(string chartRelId) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
        $"<xdr:wsDr xmlns:xdr=\"{SpreadsheetDrawingNs}\" xmlns:a=\"{DrawingNs}\" xmlns:r=\"{RelNs}\" xmlns:c=\"{ChartNs}\">" +
        "<xdr:twoCellAnchor>" +
        "<xdr:from><xdr:col>12</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>9</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>" +
        "<xdr:to><xdr:col>20</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>27</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>" +
        "<xdr:graphicFrame macro=\"\">" +
        "<xdr:nvGraphicFramePr><xdr:cNvPr id=\"2\" name=\"Findings by status\"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr>" +
        "<xdr:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/></xdr:xfrm>" +
        "<a:graphic><a:graphicData uri=\"" + ChartNs + "\">" +
        $"<c:chart xmlns:c=\"{ChartNs}\" r:id=\"{chartRelId}\"/>" +
        "</a:graphicData></a:graphic>" +
        "</xdr:graphicFrame>" +
        "<xdr:clientData/>" +
        "</xdr:twoCellAnchor>" +
        "</xdr:wsDr>";
}

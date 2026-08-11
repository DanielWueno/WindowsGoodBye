using System.Drawing;
using System.Drawing.Drawing2D;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Draws the tray's own brand icon at runtime (Cyan-to-Core gradient rounded square with a "W"
/// monogram) instead of the generic <c>SystemIcons.Shield</c> the tray used before. Drawn in code
/// rather than shipped as an .ico asset because this environment has no outbound network access to
/// source/design one (see docs/implementation_progress_push_auth_v2.md, "network block") — swap this
/// for a real designed .ico later by loading it from an embedded resource instead.
/// </summary>
internal static class TrayIcon
{
    public static Icon Load()
    {
        using var bitmap = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bitmap);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;

        using var bgBrush = new LinearGradientBrush(
            new Rectangle(0, 0, 32, 32),
            ColorTranslator.FromHtml("#0381FF"),
            ColorTranslator.FromHtml("#1920F7"),
            45f);
        using var path = RoundedRect(new Rectangle(1, 1, 30, 30), 8);
        g.FillPath(bgBrush, path);

        using var font = new Font(FontFamily.GenericSansSerif, 16f, FontStyle.Bold, GraphicsUnit.Pixel);
        const string text = "W";
        var size = g.MeasureString(text, font);
        g.DrawString(text, font, Brushes.White, (32 - size.Width) / 2f, (32 - size.Height) / 2f - 1);

        // GetHicon() hands back a raw HICON that technically should be released with DestroyIcon —
        // acceptable leak here since this runs once for the tray icon's whole process lifetime.
        return Icon.FromHandle(bitmap.GetHicon());
    }

    private static GraphicsPath RoundedRect(Rectangle bounds, int radius)
    {
        var diameter = radius * 2;
        var path = new GraphicsPath();
        var arc = new Rectangle(bounds.Location, new Size(diameter, diameter));

        path.AddArc(arc, 180, 90);
        arc.X = bounds.Right - diameter;
        path.AddArc(arc, 270, 90);
        arc.Y = bounds.Bottom - diameter;
        path.AddArc(arc, 0, 90);
        arc.X = bounds.Left;
        path.AddArc(arc, 90, 90);
        path.CloseFigure();
        return path;
    }
}

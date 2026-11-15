using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;

namespace Breccia.WPF;

public partial class MainWindow : Window
{
    private static readonly SolidColorBrush[] ToneBrushes =
    {
        B("#E9EDF5"), // Normal
        B("#4F8CFF"), // Accent
        B("#EF4444"), // Danger
        B("#F59E0B"), // Warn
        B("#3DDC97"), // Safe
        B("#7C879E")  // Muted
    };

    private static readonly SolidColorBrush Accent = B("#4F8CFF");
    private static readonly SolidColorBrush IdleBorder = B("#243049");
    private static readonly SolidColorBrush IdleBg = B("#0C1220");
    private static readonly SolidColorBrush ActiveBg = B("#111A2E");

    private AnalysisReport? _report;
    private bool _hover;
    private bool _dragOver;

    public MainWindow()
    {
        InitializeComponent();
        RenderReport();
    }

    private static SolidColorBrush B(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)!);
        brush.Freeze();
        return brush;
    }

    private static SolidColorBrush ToneBrush(Tone tone) => ToneBrushes[(int)tone];

    public void LoadFile(string path) => Analyze(path);

    // ---- rendering ----

    private static TreeViewItem Render(ReportNode n, bool expandAll)
    {
        var header = new TextBlock
        {
            Text = n.Text,
            Foreground = ToneBrush(n.Tone),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12.5,
            FontWeight = n.Bold ? FontWeights.SemiBold : FontWeights.Normal
        };
        var item = new TreeViewItem
        {
            Header = header,
            Foreground = ToneBrush(n.Tone),
            IsExpanded = expandAll,
            Tag = n
        };
        foreach (var child in n.Children) item.Items.Add(Render(child, expandAll));
        return item;
    }

    private void RenderReport(string? filter = null)
    {
        ReportTree.Items.Clear();
        if (_report is null)
        {
            ReportTree.Items.Add(Render(new ReportNode { Text = "// AWAITING FILE ...", Tone = Tone.Muted }, false));
            FilterCount.Text = "";
            return;
        }

        bool searching = !string.IsNullOrWhiteSpace(filter);
        var nodes = searching ? Filter(_report.Nodes, filter!.Trim()) : _report.Nodes;
        int index = 0;
        foreach (var n in nodes)
        {
            var item = Render(n, searching);
            item.IsExpanded = searching || index < 2;
            ReportTree.Items.Add(item);
            index++;
        }
        FilterCount.Text = searching ? $"{nodes.Sum(Count)} matches" : "";
    }

    private static List<ReportNode> Filter(List<ReportNode> nodes, string query)
    {
        var result = new List<ReportNode>();
        foreach (var n in nodes)
        {
            bool selfMatch = n.Text.Contains(query, StringComparison.OrdinalIgnoreCase);
            var children = selfMatch ? n.Children : Filter(n.Children, query);
            if (selfMatch || children.Count > 0)
                result.Add(new ReportNode
                {
                    Text = n.Text, Tone = n.Tone, Bold = n.Bold, Children = children
                });
        }
        return result;
    }

    private static int Count(ReportNode n) => 1 + n.Children.Sum(Count);

    // ---- analysis ----

    private void Analyze(string path)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            _report = PeAnalyzer.Analyze(path);
            sw.Stop();
            RenderReport(SearchBox.Text);
            DropTitle.Text = _report.FileName;
            DropHint.Text = $"{_report.FileSize:N0} bytes  |  {_report.Architecture}  |  RISK {_report.RiskLevel} ({_report.RiskScore}/100)  |  drop another file to reload";
            ReportMeta.Text = $"{_report.Nodes.Count} groups  |  {_report.Findings.Count} findings  |  {_report.ImportCount} imports  |  {_report.ExportCount} exports";
            StatusLeft.Text = _report.FilePath;
            StatusRight.Text = $"{_report.FileSize:N0} B  |  risk {_report.RiskScore}/100 {_report.RiskLevel}  |  {sw.ElapsedMilliseconds} ms";
        }
        catch (Exception ex)
        {
            _report = null;
            ReportTree.Items.Clear();
            ReportTree.Items.Add(Render(
                new ReportNode { Text = "PARSE FAILED: " + ex.Message, Tone = Tone.Danger, Bold = true }, false));
            DropTitle.Text = "PARSE FAILED";
            DropHint.Text = Path.GetFileName(path) + "  |  drop another file to retry";
            ReportMeta.Text = "error";
            StatusLeft.Text = path;
            StatusRight.Text = "error";
        }
    }

    // ---- commands ----

    private void OpenFile()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Open PE image",
            Filter = "PE files (*.exe;*.dll;*.sys;*.drv)|*.exe;*.dll;*.sys;*.drv|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true) Analyze(dlg.FileName);
    }

    private void Export(bool json)
    {
        if (_report is null)
        {
            StatusRight.Text = "nothing to export";
            return;
        }
        var dlg = new SaveFileDialog
        {
            Title = "Export analysis report",
            Filter = json ? "JSON report (*.json)|*.json" : "Text report (*.txt)|*.txt",
            FileName = $"Breccia_{Path.GetFileNameWithoutExtension(_report.FileName)}_{DateTime.Now:yyyyMMdd_HHmmss}" +
                       (json ? ".json" : ".txt")
        };
        if (dlg.ShowDialog(this) != true) return;
        string content = json
            ? JsonSerializer.Serialize(_report, new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            })
            : ToPlainText(_report);
        File.WriteAllText(dlg.FileName, content, Encoding.UTF8);
        StatusRight.Text = "exported -> " + dlg.FileName;
    }

    private static string ToPlainText(AnalysisReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("BRECCIA // PE STRUCTURE & SECURITY REPORT");
        sb.AppendLine($"Generated  : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"File       : {r.FilePath}");
        sb.AppendLine($"Size       : {r.FileSize:N0} bytes");
        sb.AppendLine($"Type       : {r.ImageType} / {r.Architecture} / {(r.IsDotNet ? ".NET" : "native")}");
        sb.AppendLine($"CompileTime: {r.CompileTime}");
        sb.AppendLine($"EntryPoint : {r.EntryPoint}");
        sb.AppendLine($"SHA256     : {r.Sha256}");
        sb.AppendLine($"SHA1       : {r.Sha1}");
        sb.AppendLine($"MD5        : {r.Md5}");
        sb.AppendLine($"ImpHash    : {r.ImpHash ?? "n/a"}");
        sb.AppendLine($"Risk       : {r.RiskScore}/100 [{r.RiskLevel}]");
        sb.AppendLine();

        void Walk(ReportNode n, int depth)
        {
            sb.AppendLine(new string(' ', depth * 2) + n.Text);
            foreach (var c in n.Children) Walk(c, depth + 1);
        }
        foreach (var n in r.Nodes) Walk(n, 0);
        return sb.ToString();
    }

    private void SetExpanded(bool value)
    {
        foreach (var o in ReportTree.Items)
            if (o is TreeViewItem item) WalkItems(item, value);
    }

    private static void WalkItems(TreeViewItem item, bool value)
    {
        item.IsExpanded = value;
        foreach (var o in item.Items)
            if (o is TreeViewItem child) WalkItems(child, value);
    }

    private void CopySelected(bool subtree)
    {
        if (ReportTree.SelectedItem is not TreeViewItem item || item.Tag is not ReportNode node) return;
        string text = subtree ? Flatten(node) : node.Text;
        try
        {
            Clipboard.SetText(text);
            StatusRight.Text = subtree ? "copied subtree to clipboard" : "copied node to clipboard";
        }
        catch (Exception ex)
        {
            StatusRight.Text = "clipboard error: " + ex.Message;
        }
    }

    private static string Flatten(ReportNode n)
    {
        var sb = new StringBuilder();
        void Walk(ReportNode x, int depth)
        {
            sb.AppendLine(new string(' ', depth * 2) + x.Text);
            foreach (var c in x.Children) Walk(c, depth + 1);
        }
        Walk(n, 0);
        return sb.ToString();
    }

    // ---- event handlers ----

    private void Open_Click(object sender, RoutedEventArgs e) => OpenFile();
    private void ExportJson_Click(object sender, RoutedEventArgs e) => Export(true);
    private void ExportTxt_Click(object sender, RoutedEventArgs e) => Export(false);
    private void ExpandAll_Click(object sender, RoutedEventArgs e) => SetExpanded(true);
    private void CollapseAll_Click(object sender, RoutedEventArgs e) => SetExpanded(false);
    private void CopyNode_Click(object sender, RoutedEventArgs e) => CopySelected(false);
    private void CopySubtree_Click(object sender, RoutedEventArgs e) => CopySelected(true);
    private void DropZone_Click(object sender, MouseButtonEventArgs e) => OpenFile();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchPlaceholder.Visibility = string.IsNullOrEmpty(SearchBox.Text)
            ? Visibility.Visible
            : Visibility.Collapsed;
        RenderReport(SearchBox.Text);
    }

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.KeyboardDevice.Modifiers != ModifierKeys.Control) return;
        switch (e.Key)
        {
            case Key.O:
                OpenFile();
                e.Handled = true;
                break;
            case Key.S:
                Export(true);
                e.Handled = true;
                break;
            case Key.F:
                SearchBox.Focus();
                SearchBox.SelectAll();
                e.Handled = true;
                break;
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void DropZone_MouseEnter(object sender, MouseEventArgs e)
    {
        _hover = true;
        ApplyDropStyle();
    }

    private void DropZone_MouseLeave(object sender, MouseEventArgs e)
    {
        _hover = false;
        ApplyDropStyle();
    }

    private void DropZone_DragEnter(object sender, DragEventArgs e)
    {
        _dragOver = e.Data.GetDataPresent(DataFormats.FileDrop);
        ApplyDropStyle();
        e.Effects = _dragOver ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_DragLeave(object sender, DragEventArgs e)
    {
        _dragOver = false;
        ApplyDropStyle();
    }

    private void DropZone_Drop(object sender, DragEventArgs e)
    {
        _dragOver = false;
        ApplyDropStyle();
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
            Analyze(paths[0]);
        e.Handled = true;
    }

    private void ApplyDropStyle()
    {
        bool active = _hover || _dragOver;
        DropZone.BorderBrush = active ? Accent : IdleBorder;
        DropZone.Background = active ? ActiveBg : IdleBg;
    }
}

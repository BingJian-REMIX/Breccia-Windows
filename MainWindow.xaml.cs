using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using PeNet;

namespace Breccia.WPF;

public partial class MainWindow : Window
{
    private static readonly SolidColorBrush Fg = B("#E9EDF5");
    private static readonly SolidColorBrush Accent = B("#4F8CFF");
    private static readonly SolidColorBrush Danger = B("#EF4444");
    private static readonly SolidColorBrush Muted = B("#7C879E");
    private static readonly SolidColorBrush Safe = B("#3DDC97");
    private static readonly SolidColorBrush IdleBorder = B("#243049");
    private static readonly SolidColorBrush IdleBg = B("#0C1220");
    private static readonly SolidColorBrush ActiveBg = B("#111A2E");

    private static readonly string[] PackerMarkers =
        { "UPX0", "UPX1", ".VMP", ".ASPACK", ".THEMIDA", ".NSP" };

    private static readonly HashSet<string> SensitiveApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "VirtualAllocEx", "VirtualAllocExNuma",
        "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "NtSetContextThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection"
    };

    private bool _hover;
    private bool _dragOver;

    public MainWindow()
    {
        InitializeComponent();
        ReportTree.Items.Add(Node("// AWAITING FILE ...", Muted));
        ReportMeta.Text = "no file loaded";
    }

    private static SolidColorBrush B(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)!);
        brush.Freeze();
        return brush;
    }

    private static TreeViewItem Node(string text, Brush? color = null, bool bold = false)
    {
        var c = color ?? Fg;
        var header = new TextBlock
        {
            Text = text,
            Foreground = c,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12.5,
            FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal
        };
        return new TreeViewItem { Header = header, Foreground = c };
    }

    private static bool IsPackerSection(string name) =>
        PackerMarkers.Any(m => name.StartsWith(m, StringComparison.OrdinalIgnoreCase));

    // ---- chrome ----

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    // ---- drop zone ----

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

    // ---- analysis ----

    private void Analyze(string path)
    {
        try
        {
            byte[] bytes = File.ReadAllBytes(path);
            var pe = new PeFile(bytes);
            var nt = pe.ImageNtHeaders;
            if (nt is null || nt.Signature != 0x00004550 || nt.FileHeader is null || nt.OptionalHeader is null)
                throw new InvalidDataException("不是有效的 PE 映像（MZ / PE 头缺失）");

            BuildReport(pe, bytes, path);
        }
        catch (Exception ex)
        {
            ReportTree.Items.Clear();
            ReportTree.Items.Add(Node("PARSE FAILED: " + ex.Message, Danger, true));
            DropTitle.Text = "PARSE FAILED";
            DropHint.Text = Path.GetFileName(path) + "  ·  drop another file to retry";
            ReportMeta.Text = "error";
        }
    }

    private void BuildReport(PeFile pe, byte[] bytes, string path)
    {
        var nt = pe.ImageNtHeaders!;
        var fh = nt.FileHeader;
        var oh = nt.OptionalHeader;

        uint machine = Convert.ToUInt32(fh.Machine);
        string arch = machine switch
        {
            0x014C => "x86   (I386 / 32-bit)",
            0x8664 => "x64   (AMD64 / 64-bit)",
            0xAA64 => "ARM64 (AArch64)",
            0x01C0 or 0x01C4 => "ARM   (32-bit)",
            0x0200 => "IA64",
            _ => $"UNKNOWN (0x{machine:X4})"
        };

        long stamp = fh.TimeDateStamp;
        string compiled = stamp is > 0 and < 253402300799
            ? DateTimeOffset.FromUnixTimeSeconds(stamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz")
            : "N/A  (timestamp 0 / invalid)";

        string sha256 = Convert.ToHexString(SHA256.HashData(bytes));

        // 1. basic info
        var basic = Node("BASIC INFO / 基本信息", Accent, true);
        basic.IsExpanded = true;
        basic.Items.Add(Node($"Architecture   : {arch}"));
        basic.Items.Add(Node($"Compile Time   : {compiled}"));
        basic.Items.Add(Node($"EntryPoint     : 0x{oh.AddressOfEntryPoint:X8}  (RVA)"));
        basic.Items.Add(Node($"SHA256         : {sha256}"));

        // 2. sections + packer markers
        var sections = pe.ImageSectionHeaders;
        var names = new List<string>();
        var sectionRoot = Node("SECTIONS / 节区", Accent, true);
        if (sections is not null)
        {
            foreach (var s in sections)
            {
                string name = (s.Name ?? "?").TrimEnd('\0', ' ');
                names.Add(name);
                bool flagged = IsPackerSection(name);
                sectionRoot.Items.Add(Node(
                    $"{name,-10}  VA 0x{s.VirtualAddress:X8}  VSIZE 0x{s.VirtualSize:X8}",
                    flagged ? Danger : Fg));
            }
        }
        if (names.Count == 0) sectionRoot.Items.Add(Node("(no sections)", Muted));

        string[] hits = names.Where(IsPackerSection)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var packerRoot = Node("PACKER DETECTION / 查壳", hits.Length > 0 ? Danger : Accent, true);
        packerRoot.IsExpanded = true;
        packerRoot.Items.Add(hits.Length > 0
            ? Node($"检测到加壳  →  {string.Join(", ", hits)}", Danger, true)
            : Node("未检测到常见加壳特征", Safe));

        // 3. imports
        var imports = pe.ImportedFunctions;
        var importRoot = Node("IMPORTS / 导入表", Accent, true);
        importRoot.IsExpanded = true;
        int sensitiveCount = 0;

        if (imports is null || imports.Length == 0)
        {
            importRoot.Items.Add(Node("(无导入表 / no imports)", Muted));
        }
        else
        {
            foreach (var g in imports
                         .GroupBy(f => string.IsNullOrWhiteSpace(f.DLL) ? "<unknown>" : f.DLL!,
                             StringComparer.OrdinalIgnoreCase)
                         .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                var apis = g.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();
                bool hasSensitive = apis.Any(f => SensitiveApis.Contains(f.Name ?? ""));
                var dllNode = Node(
                    hasSensitive ? $"{g.Key}   [{apis.Count}]   [!]" : $"{g.Key}   [{apis.Count}]",
                    hasSensitive ? Danger : Fg);

                foreach (var f in apis)
                {
                    string api = string.IsNullOrWhiteSpace(f.Name) ? "<ordinal>" : f.Name!;
                    bool sensitive = SensitiveApis.Contains(api);
                    if (sensitive) sensitiveCount++;
                    dllNode.Items.Add(Node(
                        sensitive ? $"{api}   <- SENSITIVE" : api,
                        sensitive ? Danger : Fg));
                }
                importRoot.Items.Add(dllNode);
            }
        }

        if (sensitiveCount > 0)
            importRoot.Items.Insert(0,
                Node($"检测到 {sensitiveCount} 个敏感 API 调用 (injection surface)", Danger, true));

        ReportTree.Items.Clear();
        ReportTree.Items.Add(basic);
        ReportTree.Items.Add(sectionRoot);
        ReportTree.Items.Add(packerRoot);
        ReportTree.Items.Add(importRoot);

        DropTitle.Text = Path.GetFileName(path);
        DropHint.Text = $"{bytes.Length:N0} bytes  ·  {arch}  ·  drop another file to reload";
        ReportMeta.Text = $"{names.Count} sections  |  {imports?.Length ?? 0} imports  |  " +
                          $"{imports?.Select(f => f.DLL).Distinct(StringComparer.OrdinalIgnoreCase).Count() ?? 0} DLLs";
    }
}

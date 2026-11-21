using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Breccia.WPF.Dyn;
using Microsoft.Win32;

namespace Breccia.WPF;

/// <summary>DYNAMIC tab: debugger UI. Engine lives in <see cref="DebugSession"/>; this file only renders and forwards commands.</summary>
public partial class MainWindow
{
    private DebugSession? _session;
    private DispatcherTimer? _dynTimer;
    private int _lastRev = -1;
    private ulong? _cursor;
    private string _dynNotice = "";
    private List<DynImport> _dynImports = new();
    private string _disasmSig = "", _memSig = "", _regSig = "";
    private string _treeSig = "";

    public sealed class DynLineVm
    {
        public string Text { get; init; } = "";
        public Brush Brush { get; init; } = Brushes.White;
    }

    // ---- tab plumbing ----

    private void TabDynamic_Click(object sender, RoutedEventArgs e) => SetTab(2);

    private void ApplyTabLayout()
    {
        bool dyn = _activeTab == 2;
        DynamicPanel.Visibility = dyn ? Visibility.Visible : Visibility.Collapsed;
        ReportTree.Visibility = dyn ? Visibility.Collapsed : Visibility.Visible;
        SearchBox.IsEnabled = !dyn;
        if (!dyn) _dynTimer?.Stop();
    }

    private void StartDynPolling()
    {
        if (_dynTimer is null)
        {
            _dynTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(160) };
            _dynTimer.Tick += (_, _) => RefreshDynamic();
        }
        if (!_dynTimer.IsEnabled) _dynTimer.Start();
        RefreshDynamic();
    }

    private void RefreshDynamic()
    {
        if (_activeTab != 2) return;
        if (_session is null)
        {
            RenderDynIdle();
            return;
        }

        DynSnapshot snap;
        try { snap = _session.BuildSnapshot(_cursor); }
        catch (Exception ex)
        {
            _dynNotice = "snapshot error: " + ex.Message;
            return;
        }

        RenderDynTexts(snap);
        int rev = _session.Revision;
        // State / stop reason can flip without a revision bump from the debug thread:
        // include them in the signature so the left tree never shows a stale state.
        string treeSig = $"{rev}|{snap.State}|{snap.StopReason}|{_dynNotice}|{_dynImports.Count}";
        if (treeSig != _treeSig)
        {
            _treeSig = treeSig;
            _lastRev = rev;
            RenderDynTree(snap);
        }
        StatusLeft.Text = snap.TargetPath;
        StatusRight.Text =
            $"pid {snap.Pid}  |  {(snap.Bitness == 32 ? "x86" : "x64")}  |  {snap.State}" +
            (snap.StopReason.Length > 0 ? $"  |  {snap.StopReason}" : "") +
            $"  |  {snap.Breakpoints.Count} bp";
    }

    private void RenderDynIdle()
    {
        if (_disasmSig != "idle")
        {
            _disasmSig = "idle";
            DynDisasmList.ItemsSource = null;
            DynDisasmCaption.Text = "";
            DynMemText.Text = "// no session";
            DynRegText.Text = "// no session";
            DynFlagText.Text = "EFLAGS —";
            DynMemCaption.Text = "";
            DynRegCaption.Text = "";
        }
        if (_treeSig == "idle") return;
        _treeSig = "idle";
        _lastRev = 0;
        _dynImports.Clear();
        _dynNotice = "";

        var root = new ReportNode { Text = "// NO DEBUG SESSION", Tone = Tone.Muted };
        root.Add("LAUNCH  调试已加载文件，断在 OEP", Tone.Accent);
        root.Add("ATTACH  接管运行中的 pid", Tone.Accent);
        var warn = root.Group("执行提醒", Tone.Warn);
        warn.Add("LAUNCH 会真实执行目标，样本请放虚拟机", Tone.Warn);
        warn.Add("断点用 0xCC 改写代码页，可移除还原", Tone.Muted);
        var keys = root.Group("快捷键", Tone.Muted);
        keys.Add("F5 运行  F7 单步  F8 步过  F9 断点", Tone.Muted);
        keys.Add("地址栏留空 GO = 回到 RIP", Tone.Muted);
        DynTree.Items.Clear();
        DynTree.Items.Add(Render(root, true));
    }

    private void RenderDynTexts(DynSnapshot snap)
    {
        string disasmSig = $"{snap.State}|{snap.Cursor:X}|{snap.Disasm.Count}|{snap.StopReason}|{snap.InstructionCount}";
        if (disasmSig != _disasmSig)
        {
            _disasmSig = disasmSig;
            int width = snap.Bitness == 32 ? 8 : 16;
            var lines = new List<DynLineVm>();
            foreach (var l in snap.Disasm)
            {
                string addr = width == 8 ? l.Address.ToString("X8") : l.Address.ToString("X16");
                string text = $"{addr}  {l.Bytes,-16} {l.Text}";
                Brush brush = l.Current ? Accent
                    : l.Text.Contains("int3", StringComparison.OrdinalIgnoreCase) ? ToneBrush(Tone.Warn)
                    : l.Text.Contains("syscall", StringComparison.OrdinalIgnoreCase) ? ToneBrush(Tone.Warn)
                    : ToneBrush(Tone.Normal);
                if (l.Current) text += "   <=";
                lines.Add(new DynLineVm { Text = text, Brush = brush });
            }
            if (lines.Count == 0)
                lines.Add(new DynLineVm { Text = "// cannot read code at cursor", Brush = Muted });
            DynDisasmList.ItemsSource = lines;
            DynDisasmCaption.Text =
                $"@ 0x{snap.Cursor:X}  {(snap.CursorIsPc ? "(RIP)" : "(manual)")}" +
                (snap.State == DynState.Paused ? "" : "  — target running, view is stale");
        }

        string memSig = $"{snap.Cursor:X}|{snap.Memory.Count}|{snap.Memory.FirstOrDefault()?.Hex}";
        if (memSig != _memSig)
        {
            _memSig = memSig;
            int width = snap.Bitness == 32 ? 8 : 16;
            var sb = new StringBuilder();
            foreach (var line in snap.Memory)
            {
                string addr = width == 8 ? line.Address.ToString("X8") : line.Address.ToString("X16");
                sb.AppendLine($"{addr}  {line.Hex,-47} |{line.Ascii}|");
            }
            DynMemText.Text = sb.Length == 0 ? "// unreadable region (guard page?)" : sb.ToString().TrimEnd();
            DynMemCaption.Text = snap.Memory.Count == 0
                ? ""
                : $"0x{snap.Memory[0].Address:X} — 0x{snap.Memory[^1].Address + 16:X}  ({snap.Memory.Count * 16} B)";
        }

        string regSig = snap.State == DynState.Paused
            ? string.Join(",", snap.Registers.Select(r => r.Value)) + snap.Flags
            : snap.State.ToString();
        if (regSig != _regSig)
        {
            _regSig = regSig;
            if (snap.Registers.Count == 0)
            {
                DynRegText.Text = snap.State == DynState.Paused
                    ? "// registers unavailable"
                    : "// target running";
                DynFlagText.Text = "EFLAGS —";
            }
            else
            {
                var sb = new StringBuilder();
                foreach (var (name, value) in snap.Registers) sb.AppendLine($"{name}  {value}");
                DynRegText.Text = sb.ToString().TrimEnd();
                DynFlagText.Text = "EFLAGS  " + snap.Flags;
            }
            DynRegCaption.Text = snap.Threads.FirstOrDefault(t => t.IsStopped) is { } stopped
                ? $"thread {stopped.Id}"
                : $"{snap.Threads.Count} threads";
        }
    }

    private void RenderDynTree(DynSnapshot snap)
    {
        DynTree.Items.Clear();
        var root = new ReportNode { Text = snap.TargetPath.Length > 0 ? Path.GetFileName(snap.TargetPath) : "session", Tone = Tone.Accent, Bold = true };

        var session = root.Group($"SESSION  pid {snap.Pid}", Tone.Accent);
        session.Add($"state : {snap.State}" + (snap.StopReason.Length > 0 ? $"  {snap.StopReason}" : ""));
        session.Add($"arch  : {(snap.Bitness == 32 ? "x86 (WOW64)" : "x64")}");
        session.Add($"target: {Path.GetFileName(snap.TargetPath)}");
        session.Add($"cursor: 0x{snap.Cursor:X}" + (snap.CursorIsPc ? "  RIP" : "  manual"));
        if (_session is not null) session.Add($"mode        : {(_session.IsLaunched ? "launched" : "attached")}");
        if (_dynNotice.Length > 0) session.Add(_dynNotice, Tone.Danger, true);

        var modules = root.Group($"MODULES  {snap.Modules.Count}", Tone.Normal);
        foreach (var m in snap.Modules)
        {
            var node = new ReportNode
            {
                Text = $"0x{m.Base:X12}  0x{m.Size:X8}  {m.Name}{(m.IsMain ? "   [main]" : "")}",
                Tone = m.IsMain ? Tone.Accent : Tone.Normal,
                Tag = m.Base
            };
            modules.Children.Add(node);
        }

        var threads = root.Group($"THREADS  {snap.Threads.Count}", Tone.Normal);
        foreach (var t in snap.Threads)
            threads.Add($"tid {t.Id,6}  {(t.IsMain ? "main" : "     ")}  {(t.IsStopped ? "<== current" : "")}",
                t.IsStopped ? Tone.Warn : Tone.Normal);

        var bps = root.Group($"BREAKPOINTS  {snap.Breakpoints.Count}", snap.Breakpoints.Count > 0 ? Tone.Warn : Tone.Muted);
        if (snap.Breakpoints.Count == 0) bps.Add("no breakpoints — F9 at the cursor to plant one", Tone.Muted);
        foreach (var b in snap.Breakpoints)
        {
            bps.Children.Add(new ReportNode
            {
                Text = $"0x{b.Address:X}  {b.Label,-10} {(b.Armed ? "armed" : "disarmed")}{(b.Temp ? "  (temp)" : "")}",
                Tone = b.Temp ? Tone.Muted : Tone.Warn,
                Tag = b.Address
            });
        }

        if (_dynImports.Count > 0)
        {
            int redirected = _dynImports.Count(i => i.Redirected);
            var iat = root.Group($"IAT (dynamic)  {_dynImports.Count} slots  |  {redirected} out-of-module",
                redirected > 0 ? Tone.Warn : Tone.Normal);
            iat.Add("out-of-module = 解析到的地址不在声明 DLL 里（转发导出或 hook，逐条看）", Tone.Muted);
            foreach (var g in _dynImports.GroupBy(i => i.Dll).OrderBy(g => g.Key))
            {
                var dllNode = iat.Group($"{g.Key}  ({g.Count()})", Tone.Normal, false);
                foreach (var imp in g.Take(200))
                {
                    dllNode.Add(
                        $"0x{imp.Resolved:X}  {imp.Api,-32} slot 0x{imp.Slot:X}  -> {imp.Owner}",
                        imp.Redirected ? Tone.Warn : Tone.Muted);
                }
            }
        }

        var events = root.Group($"EVENTS  {snap.Log.Count}", Tone.Muted);
        foreach (var line in snap.Log.AsEnumerable().Reverse().Take(60))
            events.Add(line, line.Contains("exception", StringComparison.OrdinalIgnoreCase) ? Tone.Warn : Tone.Muted);

        var item = Render(root, false);
        item.IsExpanded = true;
        if (item.Items.OfType<TreeViewItem>().FirstOrDefault(x => x.HasItems) is { } first) first.IsExpanded = true;
        DynTree.Items.Add(item);
    }

    // ---- commands ----

    private void DynLaunch_Click(object sender, RoutedEventArgs e)
    {
        string? path = _report?.FilePath;
        if (path is null || !File.Exists(path))
        {
            var dlg = new OpenFileDialog
            {
                Title = "Select a PE image to debug-launch",
                Filter = "PE files (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*"
            };
            if (dlg.ShowDialog(this) != true) return;
            path = dlg.FileName;
        }

        _session?.Dispose();
        _session = new DebugSession();
        _cursor = null;
        _dynImports.Clear();
        _lastRev = -1;
        _dynNotice = "";
        var err = _session.Launch(path);
        if (err.Length != 0)
        {
            _dynNotice = "launch failed: " + err;
            _session.Dispose();
            _session = null;
            _lastRev = -1;
            RenderDynIdle();
            return;
        }
        StartDynPolling();
    }

    private void DynAttach_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(DynPidBox.Text.Trim(), out int pid) || pid <= 0)
        {
            _dynNotice = "enter a numeric pid first";
            _lastRev = -1;
            if (_session is not null) RefreshDynamic(); else RenderDynIdle();
            return;
        }
        _session?.Dispose();
        _session = new DebugSession();
        _cursor = null;
        _dynImports.Clear();
        _lastRev = -1;
        _dynNotice = "";
        var err = _session.Attach(pid);
        if (err.Length != 0)
        {
            _dynNotice = "attach failed: " + err;
            _session.Dispose();
            _session = null;
            _lastRev = -1;
            RenderDynIdle();
            return;
        }
        StartDynPolling();
    }

    private void DynRun_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) { DynLaunch_Click(sender, e); return; }
        DynCommand(s => s.Run());
    }
    private void DynStep_Click(object sender, RoutedEventArgs e) => DynCommand(s => s.Step());
    private void DynOver_Click(object sender, RoutedEventArgs e) => DynCommand(s => s.StepOver());

    private void DynCommand(Func<DebugSession, string> action)
    {
        if (_session is null) { _dynNotice = "no session"; _lastRev = -1; RenderDynIdle(); return; }
        var err = action(_session);
        _dynNotice = err;
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynPause_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        _session.Pause();
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynKill_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        _session.Kill();
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynGo_Click(object sender, RoutedEventArgs e)
    {
        var text = DynAddrBox.Text.Trim();
        if (text.Length == 0)
        {
            _cursor = null;
        }
        else if (TryParseAddress(text, out ulong addr))
        {
            _cursor = addr;
        }
        else
        {
            _dynNotice = "cannot parse address: " + text;
        }
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynIat_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) { _dynNotice = "no session"; _lastRev = -1; RenderDynIdle(); return; }
        var list = _session.ResolveImports(out var err);
        _dynNotice = err.Length > 0 ? "IAT: " + err : $"IAT: {list.Count} slots resolved";
        _dynImports = list;
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynDump_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) { _dynNotice = "no session"; _lastRev = -1; RenderDynIdle(); return; }
        ulong addr = _cursor ?? _session.Pc;
        var dlg = new SaveFileDialog
        {
            Title = "Dump committed region",
            Filter = "Binary (*.bin)|*.bin|All files (*.*)|*.*",
            FileName = $"dump_{_session.Pid}_0x{addr:X}.bin"
        };
        if (dlg.ShowDialog(this) != true) return;
        var err = _session.Dump(addr, dlg.FileName, out long size);
        _dynNotice = err.Length > 0 ? "dump: " + err : $"dumped {size:N0} bytes -> {Path.GetFileName(dlg.FileName)}";
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynToggleBreakpoint()
    {
        if (_session is null) { _dynNotice = "no session"; _lastRev = -1; RenderDynIdle(); return; }
        ulong addr = _cursor ?? _session.Pc;
        var existing = _session.Breakpoints().FirstOrDefault(b => b.Address == addr && !b.Temp);
        _dynNotice = existing is not null
            ? (_session.RemoveBreakpoint(addr) ? $"breakpoint removed @ 0x{addr:X}" : "cannot remove breakpoint")
            : _session.AddBreakpoint(addr) is { Length: > 0 } err ? err : $"breakpoint set @ 0x{addr:X}";
        if (existing is null && _dynNotice.StartsWith("breakpoint set", StringComparison.Ordinal)) _dynNotice = "";
        _lastRev = -1;
        RefreshDynamic();
    }

    private void DynCopyNode_Click(object sender, RoutedEventArgs e)
    {
        if (DynTree.SelectedItem is not TreeViewItem item || item.Tag is not ReportNode node) return;
        try { Clipboard.SetText(Flatten(node)); } catch { /* clipboard busy */ }
    }

    private void DynTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not TreeViewItem item || item.Tag is not ReportNode node) return;
        if (node.Tag is ulong address)
        {
            _cursor = address;
            DynAddrBox.Text = $"0x{address:X}";
            _lastRev = -1;
            RefreshDynamic();
        }
    }

    // ---- helpers ----

    private static bool TryParseAddress(string text, out ulong value)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out value);
    }

    private void DisposeDynamicSession()
    {
        _dynTimer?.Stop();
        _session?.Dispose();
        _session = null;
    }
}

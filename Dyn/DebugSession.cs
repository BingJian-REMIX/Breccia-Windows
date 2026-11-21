using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Iced.Intel;
using IcedDecoder = Iced.Intel.Decoder;
using PeNet;

namespace Breccia.WPF.Dyn;

public enum DynState { Idle, Running, Paused, Exited, Failed }

public sealed class BreakpointInfo
{
    public ulong Address { get; set; }
    public bool Armed { get; set; }
    public bool Temp { get; set; }
    public string Label { get; set; } = "";
}

public sealed class ThreadInfo
{
    public int Id { get; set; }
    public ulong Start { get; set; }
    public bool IsMain { get; set; }
    public bool IsStopped { get; set; }
}

public sealed class ModuleInfo2
{
    public ulong Base { get; set; }
    public uint Size { get; set; }
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public bool IsMain { get; set; }
    public ulong End => Base + Size;
}

public sealed class DynImport
{
    public string Dll { get; set; } = "";
    public string Api { get; set; } = "";
    public ulong Slot { get; set; }
    public ulong Resolved { get; set; }
    public string Owner { get; set; } = "";
    public bool Redirected { get; set; }
}

public sealed class DisasmLine
{
    public ulong Address { get; set; }
    public string Bytes { get; set; } = "";
    public string Text { get; set; } = "";
    public bool Current { get; set; }
    public int Length { get; set; }
}

public sealed class MemLine
{
    public ulong Address { get; set; }
    public string Hex { get; set; } = "";
    public string Ascii { get; set; } = "";
}

public sealed class DynSnapshot
{
    public DynState State { get; set; }
    public string StateText { get; set; } = "";
    public string StopReason { get; set; } = "";
    public int Pid { get; set; }
    public int Bitness { get; set; }
    public string TargetPath { get; set; } = "";
    public ulong Pc { get; set; }
    public ulong Cursor { get; set; }
    public bool CursorIsPc { get; set; }
    public List<(string Name, string Value)> Registers { get; set; } = new();
    public string Flags { get; set; } = "";
    public List<DisasmLine> Disasm { get; set; } = new();
    public List<MemLine> Memory { get; set; } = new();
    public List<ModuleInfo2> Modules { get; set; } = new();
    public List<ThreadInfo> Threads { get; set; } = new();
    public List<BreakpointInfo> Breakpoints { get; set; } = new();
    public List<string> Log { get; set; } = new();
    public int InstructionCount { get; set; }
}

/// <summary>Interactive debugger built on the Win32 debug API. Static-only targets stay untouched.</summary>
public sealed class DebugSession : IDisposable
{
    private enum Cmd { None, Run, Step, StepOver, Kill }
    private enum Phase { None, StepPastRun, StepPastStep }

    private sealed class Bp
    {
        public ulong Address;
        public byte Original;
        public bool Armed;
        public bool Temp;
        public string Label = "";
    }

    private const int MaxLog = 500;
    private const int SnapshotDisasmLines = 22;
    private const int SnapshotMemBytes = 256;

    private readonly object _lock = new();
    private readonly List<string> _log = new();
    private readonly HashSet<int> _threadIds = new();
    private readonly Dictionary<ulong, Bp> _bps = new();

    private Thread? _loop;
    private volatile bool _shutdown;
    private bool _exitSeen;
    private uint _status = Native.DBG_CONTINUE;

    private IntPtr _process = IntPtr.Zero;
    private bool _launched;
    private Cmd _cmd;
    private Phase _phase;

    private ulong? _reArmAt;
    private Bp? _reArmBp;
    private bool _initialBreakPending;
    private int _stopTid;

    private ulong _imageBase;
    private uint _entryRva;
    private string _stopReason = "";
    private ulong _exceptionCode;
    private bool _exceptionFirstChance;
    private ulong _exceptionAddress;
    private readonly Stopwatch _runClock = new();

    public DynState State { get; private set; } = DynState.Idle;
    public int Pid { get; private set; }
    public int Bitness { get; private set; }
    public ulong Pc { get; private set; }
    public string TargetPath { get; private set; } = "";
    public int Revision { get; private set; }
    public int InstructionCount { get; private set; }

    public bool HasSession => Pid != 0 && State != DynState.Exited && State != DynState.Failed;

    // ---- lifecycle ----

    public string Launch(string path)
    {
        if (HasSession) return "a session is already active";

        int bitness = 0;
        uint entryRva = 0;
        try
        {
            var pe = new PeFile(path);
            var machine = pe.ImageNtHeaders?.FileHeader.Machine;
            int machineId = machine.HasValue ? (ushort)machine.Value : 0;
            bitness = machineId == 0x8664 ? 64 : machineId == 0x014C ? 32 : 0;
            entryRva = pe.ImageNtHeaders?.OptionalHeader.AddressOfEntryPoint ?? 0;
        }
        catch (Exception ex)
        {
            return "not a PE image: " + ex.Message;
        }
        if (bitness == 0) return "unsupported architecture for dynamic analysis";

        Bitness = bitness;
        _entryRva = entryRva;
        TargetPath = path;
        _launchPath = path;
        State = DynState.Running;
        StartLoop();
        _startGate.Wait(10000);
        if (_startError.Length != 0) { State = DynState.Failed; return _startError; }
        return "";
    }

    public string Attach(int pid)
    {
        if (HasSession) return "a session is already active";
        if (pid <= 0) return "invalid pid";
        _attachPid = pid;
        State = DynState.Running;
        StartLoop();
        _startGate.Wait(10000);
        if (_startError.Length != 0) { State = DynState.Failed; return _startError; }
        return "";
    }

    private string? _launchPath;
    private int _attachPid;
    private readonly ManualResetEventSlim _startGate = new(false);
    private string _startError = "";

    /// <summary>CreateProcess / DebugActiveProcess must run on the debug thread that services events.</summary>
    private bool CreateTarget(string path)
    {
        var si = new Native.STARTUPINFO { cb = Marshal.SizeOf<Native.STARTUPINFO>() };
        if (!Native.CreateProcessW(path, null, IntPtr.Zero, IntPtr.Zero, false,
                Native.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, Path.GetDirectoryName(path)!,
                ref si, out var pi))
        {
            _startError = Native.LastError("CreateProcess");
            return false;
        }
        _process = pi.hProcess;
        if (pi.hThread != IntPtr.Zero) Native.CloseHandle(pi.hThread);
        _mainThreadId = pi.dwThreadId;
        _launched = true;
        Pid = pi.dwProcessId;
        lock (_lock) _threadIds.Add(pi.dwThreadId);
        Log($"process created  pid {Pid}  bitness {Bitness}  entry rva 0x{_entryRva:X}");
        return true;
    }

    private bool AttachTarget(int pid)
    {
        IntPtr process = Native.OpenProcess(0x1FFFFF, false, pid);
        if (process == IntPtr.Zero) { _startError = Native.LastError("OpenProcess"); return false; }
        _process = process;

        int bitness = 64;
        if (Native.IsWow64Process(process, out bool wow64) && wow64) bitness = 32;
        Bitness = bitness;

        var sb = new StringBuilder(1024);
        int len = 1024;
        if (Native.QueryFullProcessImageNameW(process, 0, sb, ref len))
        {
            TargetPath = sb.ToString();
            try
            {
                var pe = new PeFile(TargetPath);
                _entryRva = pe.ImageNtHeaders?.OptionalHeader.AddressOfEntryPoint ?? 0;
            }
            catch { /* locked or packed image */ }
        }

        if (!Native.DebugActiveProcess(pid))
        {
            _startError = Native.LastError("DebugActiveProcess (SeDebugPrivilege needed for other users' processes)");
            Native.CloseHandle(process);
            _process = IntPtr.Zero;
            return false;
        }
        Native.DebugSetProcessKillOnExit(false);
        Pid = pid;
        Log($"attached  pid {pid}  bitness {bitness}");
        return true;
    }

    private void StartLoop()
    {
        _runClock.Restart();
        Bump();
        _loop = new Thread(Loop) { IsBackground = true, Name = "breccia-dbg" };
        _loop.Start();
    }

    // ---- commands ----

    public string Run() => Send(Cmd.Run);
    public string Step() => Send(Cmd.Step);
    public string StepOver() => Send(Cmd.StepOver);

    public void Pause()
    {
        if (State != DynState.Running || _process == IntPtr.Zero) return;
        Native.DebugBreakProcess(_process);
        Log("break request sent");
    }

    private string Send(Cmd cmd)
    {
        if (!HasSession) return "no active session";
        if (State != DynState.Paused) return "target is not stopped";
        lock (_lock)
        {
            _cmd = cmd;
            State = DynState.Running;
            Bump();
            Monitor.PulseAll(_lock);
        }
        return "";
    }

    public void Kill()
    {
        if (!HasSession) return;
        if (_launched)
        {
            Native.TerminateProcess(_process, 1);
            Log("terminate requested");
        }
        else
        {
            Native.DebugActiveProcessStop(Pid);
            Log("detached from target");
            _shutdown = true;
            State = DynState.Exited;
            Bump();
        }
        lock (_lock)
        {
            _cmd = Cmd.Kill;
            Monitor.PulseAll(_lock);
        }
    }

    // ---- breakpoints ----

    private string AddBreakpointCore(ulong address)
    {
        var bp = _bps[address];
        return WriteCode(address, 0xCC) ? SetArmed(bp) : "failed to write breakpoint byte";
    }

    private string SetArmed(Bp bp)
    {
        bp.Armed = true;
        Bump();
        return "";
    }

    public string AddBreakpoint(ulong address)
    {
        if (State != DynState.Paused) return "target must be stopped to plant a breakpoint";
        if (address < 0x1000) return "invalid address";
        if (_bps.ContainsKey(address)) return "breakpoint already set";
        var bytes = ReadMem(address, 1);
        if (bytes is null || bytes.Length == 0) return "cannot read target memory at that address";
        var bp = new Bp { Address = address, Original = bytes[0], Label = "user" };
        _bps[address] = bp;
        return AddBreakpointCore(address);
    }

    public bool RemoveBreakpoint(ulong address)
    {
        if (!_bps.TryGetValue(address, out var bp)) return false;
        if (bp.Armed) WriteCode(address, bp.Original);
        _bps.Remove(address);
        if (_reArmAt == address) { _reArmAt = null; _reArmBp = null; }
        Bump();
        return true;
    }

    public List<BreakpointInfo> Breakpoints()
    {
        lock (_lock)
            return _bps.Values.OrderBy(b => b.Address)
                .Select(b => new BreakpointInfo { Address = b.Address, Armed = b.Armed, Temp = b.Temp, Label = b.Label })
                .ToList();
    }

    // ---- inspection ----

    public List<ModuleInfo2> Modules()
    {
        if (_process == IntPtr.Zero) return new List<ModuleInfo2>();
        var result = new List<ModuleInfo2>();
        var handles = new IntPtr[1024];
        if (!Native.EnumProcessModulesEx(_process, handles, handles.Length * IntPtr.Size, out int needed, Native.LIST_MODULES_ALL))
            return result;
        int count = Math.Min(needed / IntPtr.Size, handles.Length);
        var name = new StringBuilder(1024);
        for (int i = 0; i < count; i++)
        {
            if (!Native.GetModuleInformation(_process, handles[i], out var mi, Marshal.SizeOf<Native.MODULEINFO>()))
                continue;
            name.Clear();
            Native.GetModuleFileNameExW(_process, handles[i], name, name.Capacity);
            ulong b = (ulong)mi.lpBaseOfDll;
            result.Add(new ModuleInfo2
            {
                Base = b,
                Size = mi.SizeOfImage,
                Path = name.ToString(),
                Name = Path.GetFileName(name.ToString()),
                IsMain = b == _imageBase || (i == 0)
            });
        }
        return result.OrderBy(m => m.Base).ToList();
    }

    public List<ThreadInfo> Threads()
    {
        lock (_lock)
            return _threadIds.OrderBy(t => t)
                .Select(t => new ThreadInfo { Id = t, IsMain = t == _mainThreadId, IsStopped = State == DynState.Paused && t == _stopTid })
                .ToList();
    }

    private int _mainThreadId;

    public DynSnapshot BuildSnapshot(ulong? cursor = null)
    {
        var snap = new DynSnapshot
        {
            State = State,
            Pid = Pid,
            Bitness = Bitness,
            TargetPath = TargetPath,
            Pc = Pc,
            StopReason = _stopReason,
            InstructionCount = InstructionCount,
            Flags = ""
        };
        lock (_lock) snap.Log = _log.ToList();
        snap.Breakpoints = Breakpoints();
        snap.Modules = Modules();
        snap.Threads = Threads();

        ulong target = cursor ?? Pc;
        snap.Cursor = target;
        snap.CursorIsPc = cursor is null || cursor == Pc;

        if (State != DynState.Paused) { snap.StateText = State.ToString().ToUpperInvariant(); return snap; }

        snap.StateText = "PAUSED";
        var ctx = ReadContext(_stopTid);
        if (ctx is not null)
        {
            var c = ctx.Value;
            if (Bitness == 64)
            {
                snap.Pc = c.Rip;
                snap.Registers = new List<(string, string)>
                {
                    ("RAX", $"{c.Rax:X16}"), ("RBX", $"{c.Rbx:X16}"),
                    ("RCX", $"{c.Rcx:X16}"), ("RDX", $"{c.Rdx:X16}"),
                    ("RSI", $"{c.Rsi:X16}"), ("RDI", $"{c.Rdi:X16}"),
                    ("RSP", $"{c.Rsp:X16}"), ("RBP", $"{c.Rbp:X16}"),
                    ("R8 ", $"{c.R8:X16}"),  ("R9 ", $"{c.R9:X16}"),
                    ("R10", $"{c.R10:X16}"), ("R11", $"{c.R11:X16}"),
                    ("R12", $"{c.R12:X16}"), ("R13", $"{c.R13:X16}"),
                    ("R14", $"{c.R14:X16}"), ("R15", $"{c.R15:X16}"),
                    ("RIP", $"{c.Rip:X16}"), ("RFL", $"{c.EFlags:X16}")
                };
                snap.Flags = DecodeFlags64(c.EFlags);
            }
            else
            {
                snap.Pc = c.Eip;
                snap.Registers = new List<(string, string)>
                {
                    ("EAX", $"{c.Eax:X8}"), ("EBX", $"{c.Ebx:X8}"),
                    ("ECX", $"{c.Ecx:X8}"), ("EDX", $"{c.Edx:X8}"),
                    ("ESI", $"{c.Esi:X8}"), ("EDI", $"{c.Edi:X8}"),
                    ("ESP", $"{c.Esp:X8}"), ("EBP", $"{c.Ebp:X8}"),
                    ("EIP", $"{c.Eip:X8}"), ("EFL", $"{c.EFlags:X8}"),
                    ("CS ", $"{c.SegCs & 0xFFFF:X4}"), ("SS ", $"{c.SegSs & 0xFFFF:X4}"),
                    ("DS ", $"{c.SegDs & 0xFFFF:X4}"), ("ES ", $"{c.SegEs & 0xFFFF:X4}"),
                    ("FS ", $"{c.SegFs & 0xFFFF:X4}"), ("GS ", $"{c.SegGs & 0xFFFF:X4}")
                };
                snap.Flags = DecodeFlags32(c.EFlags);
            }
        }

        snap.Disasm = Disassemble(snap.CursorIsPc ? snap.Pc : target, SnapshotDisasmLines, snap.Pc);
        snap.Memory = HexDump(target, SnapshotMemBytes);
        return snap;
    }

    public List<DynImport> ResolveImports(out string error)
    {
        error = "";
        var list = new List<DynImport>();
        if (State != DynState.Paused) { error = "target must be stopped"; return list; }
        if (_imageBase == 0) { error = "image base unknown"; return list; }

        var head = ReadMem(_imageBase, 0x2000);
        if (head is null || head.Length < 0x200) { error = "cannot read image headers"; return list; }
        int lfanew = BitConverter.ToInt32(head, 0x3C);
        if (lfanew <= 0 || lfanew + 0x120 > head.Length) { error = "bad e_lfanew"; return list; }
        int opt = lfanew + 24;
        ushort magic = BitConverter.ToUInt16(head, opt);
        bool pe32Plus = magic == 0x20B;
        if (!pe32Plus && magic != 0x10B) { error = "bad optional header magic"; return list; }
        int ddOff = pe32Plus ? 0x70 : 0x60;
        int dirRva = BitConverter.ToInt32(head, opt + ddOff + 8);
        int dirSize = BitConverter.ToInt32(head, opt + ddOff + 12);
        if (dirRva == 0) { error = "no import directory"; return list; }

        int ptrSize = pe32Plus ? 8 : 4;
        var modules = Modules();
        var desc = ReadMem(_imageBase + (ulong)dirRva, Math.Min(20 * 64, Math.Max(20, dirSize)));
        if (desc is null) { error = "cannot read import descriptors"; return list; }

        for (int off = 0; off + 20 <= desc.Length; off += 20)
        {
            uint oft = BitConverter.ToUInt32(desc, off);
            uint nameRva = BitConverter.ToUInt32(desc, off + 12);
            uint ft = BitConverter.ToUInt32(desc, off + 16);
            if (oft == 0 && nameRva == 0 && ft == 0) break;
            string dll = ReadAscii(_imageBase + nameRva, 256) ?? "";
            uint lookup = oft != 0 ? oft : ft;
            for (int i = 0; i < 4096; i++)
            {
                var raw = ReadMem(_imageBase + lookup + (ulong)(i * ptrSize), ptrSize);
                if (raw is null || raw.Length < ptrSize) break;
                ulong thunk = ptrSize == 8 ? BitConverter.ToUInt64(raw, 0) : BitConverter.ToUInt32(raw, 0);
                if (thunk == 0) break;
                string api;
                if ((thunk & (ptrSize == 8 ? 0x8000000000000000UL : 0x80000000UL)) != 0)
                    api = $"#{thunk & 0xFFFF}";
                else
                {
                    var nameBuf = ReadMem(_imageBase + (ulong)((uint)thunk & 0x7FFFFFFF) + 2, 128);
                    api = nameBuf is null ? "?" : Encoding.ASCII.GetString(nameBuf).Split('\0')[0];
                }
                ulong slot = _imageBase + ft + (ulong)(i * ptrSize);
                var slotBytes = ReadMem(slot, ptrSize);
                ulong resolved = slotBytes is null || slotBytes.Length < ptrSize ? 0
                    : ptrSize == 8 ? BitConverter.ToUInt64(slotBytes, 0) : BitConverter.ToUInt32(slotBytes, 0);
                var owner = modules.FirstOrDefault(m => resolved >= m.Base && resolved < m.End);
                bool redirected = owner is not null && !string.Equals(owner.Name, dll, StringComparison.OrdinalIgnoreCase);
                list.Add(new DynImport
                {
                    Dll = dll, Api = api, Slot = slot, Resolved = resolved,
                    Owner = owner?.Name ?? "<unmapped>", Redirected = redirected
                });
            }
        }
        if (list.Count == 0) error = "no imports resolved";
        return list;
    }

    public string Dump(ulong address, string path, out long dumped)
    {
        dumped = 0;
        if (State != DynState.Paused) return "target must be stopped";
        if (!QueryRegion(address, out ulong regionSize, out _)) return "no committed memory at that address";
        long size = (long)Math.Min(regionSize, 64L * 1024 * 1024);
        // do not walk past the end of the region even if the VAD claims more
        var buffer = ReadMem(address, (int)Math.Min(size, int.MaxValue));
        if (buffer is null) return "cannot read target memory";
        try
        {
            File.WriteAllBytes(path, buffer);
            dumped = buffer.Length;
            Log($"dumped 0x{buffer.Length:X} bytes @ 0x{address:X} -> {Path.GetFileName(path)}");
            return "";
        }
        catch (Exception ex) { return ex.Message; }
    }

    // ---- debug loop ----

    private void Loop()
    {
        if (_launchPath is not null)
        {
            if (!CreateTarget(_launchPath)) { _startGate.Set(); return; }
        }
        else if (_attachPid != 0)
        {
            if (!AttachTarget(_attachPid)) { _startGate.Set(); return; }
        }
        _startGate.Set();

        while (!_shutdown)
        {
            if (!Native.WaitForDebugEventEx(out var ev, 120))
                continue;

            _status = Native.DBG_CONTINUE;
            bool stop;
            try { stop = Handle(ev); }
            catch (Exception ex)
            {
                Log("debugger internal error: " + ex.Message);
                stop = false;
            }

            if (stop && !_shutdown) WaitForCommand((int)ev.dwThreadId);

            Native.ContinueDebugEvent((int)ev.dwProcessId, (int)ev.dwThreadId, _status);

            if (ev.dwDebugEventCode == Native.EXIT_PROCESS_DEBUG_EVENT) break;
        }
        Cleanup();
    }

    /// <returns>true when the target should stay stopped until a user command arrives.</returns>
    private bool Handle(Native.DEBUG_EVENT ev)
    {
        switch (ev.dwDebugEventCode)
        {
            case Native.CREATE_PROCESS_DEBUG_EVENT:
            {
                _imageBase = (ulong)ev.u.CpBaseOfImage;
                _mainThreadId = (int)ev.dwThreadId;
                if (ev.u.CpThread != IntPtr.Zero) Native.CloseHandle(ev.u.CpThread);
                if (ev.u.CpFile != IntPtr.Zero) Native.CloseHandle(ev.u.CpFile);
                lock (_lock) _threadIds.Add((int)ev.dwThreadId);
                Log($"image base 0x{_imageBase:X}  main thread {ev.dwThreadId}");
                if (_entryRva != 0)
                {
                    ulong ep = _imageBase + _entryRva;
                    lock (_lock)
                        if (!_bps.ContainsKey(ep))
                            _bps[ep] = new Bp { Address = ep, Original = 0, Label = "OEP", Armed = false };
                    _oepPending = ep;
                }
                _initialBreakPending = true;
                Bump();
                return false;
            }

            case Native.CREATE_THREAD_DEBUG_EVENT:
                if (ev.u.CtThread != IntPtr.Zero) Native.CloseHandle(ev.u.CtThread);
                lock (_lock) _threadIds.Add((int)ev.dwThreadId);
                Log($"thread created {ev.dwThreadId} @ 0x{(ulong)ev.u.CtStartAddress:X}");
                Bump();
                return false;

            case Native.EXIT_THREAD_DEBUG_EVENT:
                lock (_lock) _threadIds.Remove((int)ev.dwThreadId);
                Log($"thread exited {ev.dwThreadId} code 0x{ev.u.ExitCode:X}");
                Bump();
                return false;

            case Native.LOAD_DLL_DEBUG_EVENT:
            {
                if (ev.u.LdFile != IntPtr.Zero) Native.CloseHandle(ev.u.LdFile);
                ulong b = (ulong)ev.u.LdBaseOfDll;
                string? name = TryModuleName(b);
                Log($"dll loaded  0x{b:X}  {name ?? "<unknown>"}");
                Bump();
                return false;
            }

            case Native.UNLOAD_DLL_DEBUG_EVENT:
                Log($"dll unloaded 0x{(ulong)ev.u.LdBaseOfDll:X}");
                Bump();
                return false;

            case Native.OUTPUT_DEBUG_STRING_EVENT:
            {
                int len = Math.Min((int)ev.u.DbgStringLength, 512);
                string text = "";
                if (len > 0)
                {
                    var buf = ReadMem((ulong)ev.u.DbgStringAddress, len);
                    if (buf is not null)
                        text = ev.u.DbgStringUnicode != 0
                            ? Encoding.Unicode.GetString(buf).TrimEnd('\0')
                            : Encoding.ASCII.GetString(buf).TrimEnd('\0');
                }
                Log($"debug string: {text.Replace("\r", "").Replace("\n", " | ")}");
                Bump();
                return false;
            }

            case Native.RIP_EVENT:
                Log($"RIP event reason {ev.u.RipReason} error {ev.u.RipError}");
                return false;

            case Native.EXIT_PROCESS_DEBUG_EVENT:
                _exitSeen = true;
                State = DynState.Exited;
                _stopReason = $"process exited (code 0x{ev.u.ExitCode:X})";
                Log(_stopReason);
                Bump();
                return false;

            case Native.EXCEPTION_DEBUG_EVENT:
                return HandleException(ev);
        }
        return false;
    }

    private ulong? _oepPending;
    private ulong _oepAddress;
    private int _systemBreaks;

    private bool HandleException(Native.DEBUG_EVENT ev)
    {
        uint code = ev.u.ExceptionCode;
        const uint WX86_BREAKPOINT = 0x4000001F;
        const uint WX86_SINGLE_STEP = 0x4000001E;
        ulong addr = (ulong)ev.u.ExceptionAddress;
        bool firstChance = ev.u.FirstChance != 0;
        _stopTid = (int)ev.dwThreadId;

        if (code == Native.EXCEPTION_BREAKPOINT || code == WX86_BREAKPOINT)
        {
            if (_initialBreakPending)
            {
                _initialBreakPending = false;
                Log("loader breakpoint (system)");
                if (_oepPending is ulong ep)
                {
                    var first = ReadMem(ep, 1);
                    if (first is not null && first.Length == 1 && TryWriteCode(ep, 0xCC))
                    {
                        lock (_lock)
                            if (_bps.TryGetValue(ep, out var oep)) { oep.Original = first[0]; oep.Armed = true; }
                        _oepAddress = ep;
                        Log($"OEP breakpoint armed @ 0x{ep:X} (original byte 0x{first[0]:X2})");
                    }
                    else Log($"could not arm OEP breakpoint @ 0x{ep:X}");
                    _oepPending = null;
                }
                return false;
            }

            Bp? hit = null;
            lock (_lock)
            {
                if (_bps.TryGetValue(addr, out var candidate) && candidate.Armed) hit = candidate;
            }

            if (hit is not null && hit.Address == _oepAddress) _systemBreaks = 99;

            if (hit is not null)
            {
                RestoreByte(hit);
                SetPc((int)ev.dwThreadId, addr);
                if (hit.Temp)
                {
                    lock (_lock) _bps.Remove(addr);
                    _reArmAt = null;
                    _reArmBp = null;
                    return Stop("step over complete", addr);
                }
                _reArmAt = addr;
                _reArmBp = hit;
                return Stop($"{hit.Label} breakpoint", addr);
            }

            // WOW64 bootstrap raises an extra loader break before the 32-bit entry point runs.
            if (_oepAddress != 0 && _systemBreaks < 4)
            {
                _systemBreaks++;
                Log($"system breakpoint #{_systemBreaks} skipped @ 0x{addr:X} (waiting for OEP)");
                return false;
            }

            // External int3 (DebugBreakProcess / ntdll!DbgBreakPoint): IP already points past it.
            return Stop(firstChance ? "paused (external int3)" : "paused (second-chance int3)", addr);
        }

        if (code == Native.EXCEPTION_SINGLE_STEP || code == WX86_SINGLE_STEP)
        {
            if (_phase == Phase.StepPastRun)
            {
                ReArm();
                _phase = Phase.None;
                return false;
            }
            if (_phase == Phase.StepPastStep)
            {
                ReArm();
                _phase = Phase.None;
                ulong pc = ReadPc((int)ev.dwThreadId) ?? addr;
                return Stop("step", pc);
            }
            return Stop("single step", ReadPc((int)ev.dwThreadId) ?? addr);
        }

        _exceptionCode = code;
        _exceptionAddress = addr;
        _exceptionFirstChance = firstChance;
        string detail = DescribeException(code);
        if (code == Native.EXCEPTION_ACCESS_VIOLATION)
        {
            ulong kind = (ulong)ev.u.ExceptionInformation0;
            ulong target = (ulong)ev.u.ExceptionInformation1;
            detail += kind switch
            {
                0 => $" read 0x{target:X}",
                1 => $" write 0x{target:X}",
                8 => $" execute 0x{target:X}",
                _ => $" access 0x{target:X}"
            };
        }
        Log($"{(firstChance ? "first" : "second")}-chance 0x{code:X8} {detail} @ 0x{addr:X}");

        if (!firstChance)
        {
            _status = Native.DBG_EXCEPTION_NOT_HANDLED;
            _stopReason = $"second-chance exception {detail}";
            return Stop(_stopReason, addr);
        }

        _status = Native.DBG_EXCEPTION_NOT_HANDLED;
        if (!IsFatalException(code))
        {
            // compiler runtimes raise bookkeeping exceptions (MS_VC_EXCEPTION thread naming,
            // C++ EH) as first chance on nearly every modern binary; do not stop on them.
            Log($"first-chance 0x{code:X8} passed to target @ 0x{addr:X}");
            return false;
        }
        return Stop($"exception 0x{code:X8} {detail}", addr);
    }

    private bool Stop(string reason, ulong address)
    {
        Log($"STOP '{reason}' @ 0x{address:X}");
        Pc = address;
        _stopReason = reason;
        State = DynState.Paused;
        Bump();
        return true;
    }

    private void WaitForCommand(int tid)
    {
        Cmd cmd;
        lock (_lock)
        {
            _cmd = Cmd.None;
            while (_cmd == Cmd.None && !_shutdown)
                Monitor.Wait(_lock, 200);
            cmd = _cmd;
            _cmd = Cmd.None;
        }

        switch (cmd)
        {
            case Cmd.Kill:
                if (_launched) Native.TerminateProcess(_process, 1);
                _status = Native.DBG_CONTINUE;
                break;

            case Cmd.Run:
                State = DynState.Running;
                _runClock.Restart();
                Bump();
                if (_reArmAt is ulong runAddr) { SetTrapFlag(tid); _phase = Phase.StepPastRun; }
                break;

            case Cmd.Step:
                State = DynState.Running;
                Bump();
                SetTrapFlag(tid);
                _phase = _reArmAt is null ? Phase.None : Phase.StepPastStep;
                break;

            case Cmd.StepOver:
                State = DynState.Running;
                Bump();
                if (_reArmAt is not null)
                {
                    SetTrapFlag(tid);
                    _phase = Phase.StepPastStep;
                    break;
                }
                PrepareStepOver(tid);
                break;

            default: // window closed / shutdown: resume so the process is not frozen
                if (_shutdown && _launched) Native.TerminateProcess(_process, 1);
                State = DynState.Running;
                break;
        }
    }

    /// <summary>Step over a call by breaking at the next instruction; single-step anything else.</summary>
    private void PrepareStepOver(int tid)
    {
        ulong? pc = ReadPc(tid);
        if (pc is null) { SetTrapFlag(tid); _phase = Phase.None; return; }
        var lines = Disassemble(pc.Value, 1, 0);
        bool isCall = lines.Count > 0 &&
            lines[0].Text.StartsWith("call", StringComparison.OrdinalIgnoreCase);
        if (!isCall) { SetTrapFlag(tid); _phase = Phase.None; return; }

        ulong next = pc.Value + (ulong)lines[0].Length;
        var bp = new Bp { Address = next, Label = "step-over", Temp = true };
        lock (_lock) _bps[next] = bp;
        if (TryWriteCode(next, 0xCC)) { bp.Armed = true; Bump(); }
        else { lock (_lock) _bps.Remove(next); SetTrapFlag(tid); }
        _phase = Phase.None;
    }

    private void ReArm()
    {
        if (_reArmAt is not ulong addr) return;
        if (TryWriteCode(addr, 0xCC) && _reArmBp is not null) _reArmBp.Armed = true;
        _reArmAt = null;
        _reArmBp = null;
        Bump();
    }

    // ---- context ----

    private struct Regs
    {
        public ulong Rip, Rsp, Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, R8, R9, R10, R11, R12, R13, R14, R15;
        public uint EFlags;
        public uint SegCs, SegSs, SegDs, SegEs, SegFs, SegGs;
        public uint Eip, Esp, Eax, Ebx, Ecx, Edx, Esi, Edi, Ebp;
    }

    /// <summary>16-byte aligned native buffer for CONTEXT (x64 requires alignment).</summary>
    private sealed class CtxBuffer : IDisposable
    {
        private readonly IntPtr _raw;
        public readonly IntPtr Ptr;

        public CtxBuffer(int size)
        {
            _raw = Marshal.AllocHGlobal(size + 32);
            Ptr = (IntPtr)(((long)_raw + 15) & ~15L);
            for (int i = 0; i + 8 <= size; i += 8) Marshal.WriteInt64(Ptr, i, 0);
        }

        public T Read<T>() where T : struct => Marshal.PtrToStructure<T>(Ptr);

        public void Write<T>(T value) where T : struct => Marshal.StructureToPtr(value, Ptr, false);

        public void Dispose() => Marshal.FreeHGlobal(_raw);
    }

    private const int CtxSize64 = 1232;
    private const int CtxSize32 = 716;

    private Regs? ReadContext(int tid)
    {
        IntPtr handle = OpenThreadFor(tid);
        if (handle == IntPtr.Zero)
        {
            Log($"OpenThread failed for tid {tid} (stopTid {_stopTid}, win32={Marshal.GetLastWin32Error()})");
            return null;
        }
        try
        {
            if (Bitness == 64)
            {
                using var buf = new CtxBuffer(CtxSize64);
                buf.Write(new Native.Ctx64 { ContextFlags = Native.CONTEXT_FULL_64 });
                if (!Native.GetThreadContext(handle, buf.Ptr))
                {
                    Log($"GetThreadContext failed win32={Marshal.GetLastWin32Error()}");
                    return null;
                }
                var c = buf.Read<Native.Ctx64>();
                return new Regs
                {
                    Rip = c.Rip, Rsp = c.Rsp, Rax = c.Rax, Rbx = c.Rbx, Rcx = c.Rcx, Rdx = c.Rdx,
                    Rsi = c.Rsi, Rdi = c.Rdi, Rbp = c.Rbp, R8 = c.R8, R9 = c.R9, R10 = c.R10,
                    R11 = c.R11, R12 = c.R12, R13 = c.R13, R14 = c.R14, R15 = c.R15, EFlags = c.EFlags
                };
            }

            using (var buf = new CtxBuffer(CtxSize32))
            {
                buf.Write(new Native.Ctx32 { ContextFlags = Native.CONTEXT_FULL_32 });
                if (!Native.Wow64GetThreadContext(handle, buf.Ptr))
                {
                    Log($"Wow64GetThreadContext failed win32={Marshal.GetLastWin32Error()}");
                    return null;
                }
                var c = buf.Read<Native.Ctx32>();
                return new Regs
                {
                    Eip = c.Eip, Esp = c.Esp, Eax = c.Eax, Ebx = c.Ebx, Ecx = c.Ecx, Edx = c.Edx,
                    Esi = c.Esi, Edi = c.Edi, Ebp = c.Ebp, EFlags = c.EFlags,
                    SegCs = c.SegCs, SegSs = c.SegSs, SegDs = c.SegDs, SegEs = c.SegEs,
                    SegFs = c.SegFs, SegGs = c.SegGs
                };
            }
        }
        finally { Native.CloseHandle(handle); }
    }

    private ulong? ReadPc(int tid)
    {
        var r = ReadContext(tid);
        if (r is null) return null;
        return Bitness == 64 ? r.Value.Rip : r.Value.Eip;
    }

    private bool SetPc(int tid, ulong pc)
    {
        IntPtr handle = OpenThreadFor(tid);
        if (handle == IntPtr.Zero) return false;
        try
        {
            if (Bitness == 64)
            {
                using var buf = new CtxBuffer(CtxSize64);
                buf.Write(new Native.Ctx64 { ContextFlags = Native.CONTEXT_CONTROL_64 | Native.CONTEXT_INTEGER_64 });
                if (!Native.GetThreadContext(handle, buf.Ptr)) return false;
                var c = buf.Read<Native.Ctx64>();
                c.Rip = pc;
                c.ContextFlags = Native.CONTEXT_CONTROL_64 | Native.CONTEXT_INTEGER_64;
                buf.Write(c);
                if (!Native.SetThreadContext(handle, buf.Ptr))
                {
                    Log($"SetThreadContext(rip) failed win32={Marshal.GetLastWin32Error()}");
                    return false;
                }
                return true;
            }

            using (var buf = new CtxBuffer(CtxSize32))
            {
                buf.Write(new Native.Ctx32 { ContextFlags = Native.CONTEXT_CONTROL_32 | Native.CONTEXT_INTEGER_32 });
                if (!Native.Wow64GetThreadContext(handle, buf.Ptr)) return false;
                var c = buf.Read<Native.Ctx32>();
                c.Eip = (uint)pc;
                c.ContextFlags = Native.CONTEXT_CONTROL_32 | Native.CONTEXT_INTEGER_32;
                buf.Write(c);
                if (!Native.Wow64SetThreadContext(handle, buf.Ptr))
                {
                    Log($"Wow64SetThreadContext(eip) failed win32={Marshal.GetLastWin32Error()}");
                    return false;
                }
                return true;
            }
        }
        finally { Native.CloseHandle(handle); }
    }

    private void SetTrapFlag(int tid)
    {
        IntPtr handle = OpenThreadFor(tid);
        if (handle == IntPtr.Zero) return;
        try
        {
            if (Bitness == 64)
            {
                using var buf = new CtxBuffer(CtxSize64);
                buf.Write(new Native.Ctx64 { ContextFlags = Native.CONTEXT_FULL_64 });
                if (!Native.GetThreadContext(handle, buf.Ptr))
                {
                    Log($"TF: GetThreadContext failed win32={Marshal.GetLastWin32Error()}");
                    return;
                }
                var c = buf.Read<Native.Ctx64>();
                c.EFlags |= Native.EFLAGS_TF;
                c.ContextFlags = Native.CONTEXT_CONTROL_64;
                buf.Write(c);
                if (!Native.SetThreadContext(handle, buf.Ptr))
                    Log($"TF: SetThreadContext failed win32={Marshal.GetLastWin32Error()}");
            }
            else
            {
                using var buf = new CtxBuffer(CtxSize32);
                buf.Write(new Native.Ctx32 { ContextFlags = Native.CONTEXT_FULL_32 });
                if (!Native.Wow64GetThreadContext(handle, buf.Ptr))
                {
                    Log($"TF(wow64): get failed win32={Marshal.GetLastWin32Error()}");
                    return;
                }
                var c = buf.Read<Native.Ctx32>();
                c.EFlags |= Native.EFLAGS_TF;
                c.ContextFlags = Native.CONTEXT_CONTROL_32;
                buf.Write(c);
                if (!Native.Wow64SetThreadContext(handle, buf.Ptr))
                    Log($"TF(wow64): set failed win32={Marshal.GetLastWin32Error()}");
            }
        }
        finally { Native.CloseHandle(handle); }
    }

    /// <summary>Always a fresh handle: debug-event handles are not reliable targets for GetThreadContext.</summary>
    private IntPtr OpenThreadFor(int tid) =>
        Native.OpenThread(
            Native.THREAD_GET_CONTEXT | Native.THREAD_SET_CONTEXT |
            Native.THREAD_SUSPEND_RESUME | Native.THREAD_QUERY_INFORMATION |
            Native.THREAD_ALL_ACCESS, false, tid);

    // ---- memory ----

    public byte[]? ReadMem(ulong address, int size)
    {
        if (_process == IntPtr.Zero || size <= 0) return null;
        var buffer = new byte[size];
        if (!Native.ReadProcessMemory(_process, (IntPtr)(long)address, buffer, size, out IntPtr read) || (long)read <= 0)
            return null;
        if ((long)read < size) Array.Resize(ref buffer, (int)read);
        return buffer;
    }

    private bool TryWriteCode(ulong address, byte value)
    {
        if (_process == IntPtr.Zero) return false;
        if (!Native.VirtualProtectEx(_process, (IntPtr)(long)address, 1, Native.PAGE_EXECUTE_READWRITE, out uint old))
            return false;
        var one = new[] { value };
        bool ok = Native.WriteProcessMemory(_process, (IntPtr)(long)address, one, 1, out _);
        Native.VirtualProtectEx(_process, (IntPtr)(long)address, 1, old, out _);
        if (ok) Native.FlushInstructionCache(_process, (IntPtr)(long)address, 1);
        return ok;
    }

    private bool WriteCode(ulong address, byte value) => TryWriteCode(address, value);

    private void RestoreByte(Bp bp)
    {
        TryWriteCode(bp.Address, bp.Original);
        bp.Armed = false;
        Bump();
    }

    private bool QueryRegion(ulong address, out ulong regionSize, out uint protect)
    {
        regionSize = 0;
        protect = 0;
        if (Native.VirtualQueryEx(_process, (IntPtr)(long)address,
                out var mbi, (ulong)Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>()) == 0)
            return false;
        regionSize = mbi.RegionSize;
        protect = mbi.Protect;
        return mbi.State == Native.MEM_COMMIT;
    }

    private string? TryModuleName(ulong baseAddress)
    {
        foreach (var m in Modules())
            if (m.Base == baseAddress) return m.Name;
        return null;
    }

    private string? ReadAscii(ulong address, int max)
    {
        var buf = ReadMem(address, max);
        if (buf is null) return null;
        int end = Array.IndexOf(buf, (byte)0);
        return Encoding.ASCII.GetString(buf, 0, end < 0 ? buf.Length : end);
    }

    // ---- views ----

    public List<DisasmLine> Disassemble(ulong address, int count, ulong currentPc)
    {
        var result = new List<DisasmLine>();
        if (_process == IntPtr.Zero) return result;
        int bitness = Bitness == 32 ? 32 : 64;
        ulong cursor = address;
        for (int i = 0; i < count; i++)
        {
            var chunk = ReadMem(cursor, 16);
            if (chunk is null || chunk.Length == 0) break;
            var reader = new ByteArrayCodeReader(chunk);
            var decoder = IcedDecoder.Create(bitness, reader, cursor);
            var insn = decoder.Decode();
            if (insn.Code == Code.INVALID) break;
            var formatter = new NasmFormatter();
            var output = new StringOutput();
            formatter.Format(insn, output);
            var bytes = new StringBuilder();
            for (int b = 0; b < insn.Length && b < 8; b++) bytes.Append(chunk[b].ToString("X2"));
            result.Add(new DisasmLine
            {
                Address = cursor,
                Bytes = bytes.ToString(),
                Text = output.ToStringAndReset(),
                Current = currentPc != 0 && cursor == currentPc,
                Length = insn.Length
            });
            cursor += (ulong)insn.Length;
        }
        return result;
    }

    public List<MemLine> HexDump(ulong address, int size)
    {
        var lines = new List<MemLine>();
        var buf = ReadMem(address, size);
        if (buf is null) return lines;
        for (int i = 0; i < buf.Length; i += 16)
        {
            var hex = new StringBuilder(48);
            var ascii = new StringBuilder(16);
            for (int j = 0; j < 16; j++)
            {
                if (i + j < buf.Length)
                {
                    byte b = buf[i + j];
                    hex.Append(b.ToString("X2")).Append(' ');
                    ascii.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                }
                else { hex.Append("   "); ascii.Append(' '); }
            }
            lines.Add(new MemLine { Address = address + (ulong)i, Hex = hex.ToString().TrimEnd(), Ascii = ascii.ToString() });
        }
        return lines;
    }

    private static string DecodeFlags64(uint f) => DecodeFlags(f);

    private static string DecodeFlags32(uint f) => DecodeFlags(f);

    private static string DecodeFlags(uint f)
    {
        var on = new List<string>();
        if ((f & 0x1) != 0) on.Add("CF");
        if ((f & 0x4) != 0) on.Add("PF");
        if ((f & 0x10) != 0) on.Add("AF");
        if ((f & 0x40) != 0) on.Add("ZF");
        if ((f & 0x80) != 0) on.Add("SF");
        if ((f & 0x100) != 0) on.Add("TF");
        if ((f & 0x200) != 0) on.Add("IF");
        if ((f & 0x400) != 0) on.Add("DF");
        if ((f & 0x800) != 0) on.Add("OF");
        return on.Count == 0 ? "(none)" : string.Join(" ", on);
    }

    private static bool IsFatalException(uint code) => code is
        Native.EXCEPTION_ACCESS_VIOLATION or
        Native.EXCEPTION_ILLEGAL_INSTRUCTION or
        Native.EXCEPTION_INT_DIVIDE_BY_ZERO or
        Native.EXCEPTION_PRIV_INSTRUCTION or
        0xC0000409 or   // fastfail
        0xC0000139 or   // entry point not found
        0xC0000135 or   // DLL not found
        0xC0000142;     // DLL init failed

    private static string DescribeException(uint code) => code switch
    {
        Native.EXCEPTION_ACCESS_VIOLATION => "access violation",
        Native.EXCEPTION_ILLEGAL_INSTRUCTION => "illegal instruction",
        Native.EXCEPTION_INT_DIVIDE_BY_ZERO => "integer divide by zero",
        Native.EXCEPTION_PRIV_INSTRUCTION => "privileged instruction",
        0xC0000409 => "stack buffer overrun (fastfail)",
        0xC0000139 => "entry point not found",
        0xC0000135 => "DLL not found",
        0xC0000142 => "DLL init failed",
        _ => "exception"
    };

    // ---- housekeeping ----

    private void Bump()
    {
        Revision++;
    }

    private void Log(string line)
    {
        lock (_lock)
        {
            _log.Add($"{DateTime.Now:HH:mm:ss.fff}  {line}");
            if (_log.Count > MaxLog) _log.RemoveRange(0, _log.Count - MaxLog);
        }
    }

    private void Cleanup()
    {
        State = _exitSeen ? DynState.Exited : DynState.Failed;
        if (!_exitSeen) _stopReason = "debug loop ended";
        lock (_lock) _threadIds.Clear();
        if (_process != IntPtr.Zero) { Native.CloseHandle(_process); _process = IntPtr.Zero; }
        Log("session closed");
        Bump();
    }

    public void Dispose()
    {
        if (_shutdown) return;
        _shutdown = true;
        lock (_lock) Monitor.PulseAll(_lock);
        if (HasSession)
        {
            if (_launched) Native.TerminateProcess(_process, 1);
            else Native.DebugActiveProcessStop(Pid);
        }
        _loop?.Join(1500);
    }
}

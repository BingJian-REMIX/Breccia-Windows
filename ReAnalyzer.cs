using System.Text;
using System.Text.RegularExpressions;
using Iced.Intel;
using PeNet.Header.Pe;
using IcedDecoder = Iced.Intel.Decoder;

namespace Breccia.WPF;

/// <summary>Reverse-engineering pass: disassembly, function/call-graph recovery,
/// IAT cross-references, string mining, toolchain fingerprints and structural anomalies.</summary>
public sealed class ReResult
{
    public List<ReportNode> Nodes { get; } = new();
    public List<Finding> Findings { get; } = new();
    public int FunctionCount { get; set; }
    public int InstructionCount { get; set; }
    public int FunctionTotal { get; set; }
    public int StringTotal { get; set; }
    public int StringKept { get; set; }
    public int SuspiciousStrings { get; set; }
    public int ApiCallSites { get; set; }
    public int ApiCallSiteTotal { get; set; }
    public string? PackerSignature { get; set; }
}

public static class ReAnalyzer
{
    private const int MaxFunctions = 24;
    private const int MaxInstructionsPerFunction = 56;
    private const int MaxInstructionsTotal = 1100;
    private const int MaxStringNodes = 600;
    private const int MaxStringsScanned = 200_000;
    private const int MaxBytesPerFunction = 4096;

    private static readonly NasmFormatter Formatter = CreateFormatter();

    private static NasmFormatter CreateFormatter()
    {
        var f = new NasmFormatter();
        f.Options.UppercaseHex = false;
        f.Options.SpaceAfterOperandSeparator = true;
        f.Options.RipRelativeAddresses = false;
        return f;
    }

    // ---- x86 / x64 prologue patterns used for function discovery ----
    private static readonly (byte[] Pattern, byte[] Mask)[] Prologues32 =
    {
        (new byte[] { 0x55, 0x8B, 0xEC }, new byte[] { 1, 1, 1 }),
        (new byte[] { 0x55, 0x89, 0xE5 }, new byte[] { 1, 1, 1 }),
        (new byte[] { 0x8B, 0xFF, 0x55, 0x8B, 0xEC }, new byte[] { 1, 1, 1, 1, 1 }),
        (new byte[] { 0x53, 0x8B, 0xDC }, new byte[] { 1, 1, 1 }),
        (new byte[] { 0x6A, 0xFF, 0x68 }, new byte[] { 1, 0, 1 })
    };

    private static readonly (byte[] Pattern, byte[] Mask)[] Prologues64 =
    {
        (new byte[] { 0x48, 0x89, 0x5C, 0x24 }, new byte[] { 1, 1, 1, 1 }),
        (new byte[] { 0x48, 0x89, 0x4C, 0x24 }, new byte[] { 1, 1, 1, 1 }),
        (new byte[] { 0x48, 0x89, 0x54, 0x24 }, new byte[] { 1, 1, 1, 1 }),
        (new byte[] { 0x48, 0x83, 0xEC }, new byte[] { 1, 1, 1 }),
        (new byte[] { 0x55, 0x48, 0x8B, 0xEC }, new byte[] { 1, 1, 1, 1 }),
        (new byte[] { 0x40, 0x53 }, new byte[] { 1, 1 }),
        (new byte[] { 0x40, 0x55 }, new byte[] { 1, 1 }),
        (new byte[] { 0x48, 0x8B, 0xC4 }, new byte[] { 1, 1, 1 }),
        (new byte[] { 0x4C, 0x8B, 0xDC }, new byte[] { 1, 1, 1 })
    };

    // Entry-point byte signatures for common protectors (mask 0 = wildcard).
    private static readonly (string Name, byte[] Pattern, byte[] Mask)[] EntrySignatures =
    {
        ("UPX stub", new byte[] { 0x60, 0xBE, 0, 0, 0, 0, 0x8D, 0xBE }, new byte[] { 1, 1, 0, 0, 0, 0, 1, 1 }),
        ("ASPack 2.x", new byte[] { 0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3 },
            new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }),
        ("MEW / compact stub", new byte[] { 0xE9, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })
    };

    private static readonly Regex UrlRx = new(@"^(https?|ftp)://", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex IpRx = new(@"^(?:\d{1,3}\.){3}\d{1,3}$", RegexOptions.Compiled);
    private static readonly Regex CmdRx = new(
        @"\b(cmd\.exe|powershell(\.exe)?|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|wmic|net1?\.exe|sc\.exe|taskkill|vssadmin|bcdedit)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RegistryRx = new(
        @"(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|SOFTWARE\\|SYSTEM\\CurrentControlSet)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PathRx = new(@"^([A-Za-z]:\\|%[A-Za-z0-9_]+%\\|\\\\[A-Za-z0-9_.\-]+\\)", RegexOptions.Compiled);
    private static readonly Regex AntiVmRx = new(
        @"\b(VMware|VirtualBox|VBox|VBOX|QEMU|Xen|Sandboxie|SbieDll|Cuckoo|Wine|Hyper-?V|vmtoolsd)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex MalwareRx = new(
        @"(\.onion\b|ransom|keylog|botnet|backdoor|rootkit|mimikatz|meterpreter|beacon\.dll|Cobalt)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex UserAgentRx = new(@"Mozilla/\d", RegexOptions.Compiled);
    private static readonly Regex ModuleRx = new(@"^[A-Za-z0-9_.\-]+\.(dll|exe|sys|ocx|drv|cpl)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex DotNetRx = new(@"(mscorlib|System\.Runtime|System\.Private\.CoreLib|\.NETFramework|v4\.0\.30319)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private sealed class Span
    {
        public string Name = "";
        public uint Va, VSize, RawPtr, RawSize;
        public bool Exec, Write;
    }

    private sealed class FunctionResult
    {
        public uint Rva;
        public string Name = "";
        public List<(string Text, Tone Tone)> Lines = new();
        public List<uint> Callees = new();
        public List<(string Api, string Dll, ulong Site, uint Rva)> CallSites = new();
        public int InsnCount;
        public bool HasSyscall;
        public bool HasPebAccess;
        public int Int3Count;
        public int CpuidCount;
        public bool HasRdtsc;
        public uint ByteLength;
    }

    public static ReResult Analyze(
        byte[] bytes,
        IReadOnlyList<SectionInfo> sections,
        ulong imageBase,
        uint entryRva,
        uint machine,
        IReadOnlyList<ImportFunction> imports,
        IReadOnlyList<ImageImportDescriptor> descriptors)
    {
        var result = new ReResult();
        var spans = sections
            .Select(s => new Span
            {
                Name = s.Name,
                Va = s.VirtualAddress,
                VSize = s.VirtualSize,
                RawPtr = s.RawPointer,
                RawSize = s.RawSize,
                Exec = s.Executable,
                Write = s.Writable
            })
            .ToArray();

        int bitness = machine switch { 0x014C => 32, 0x8664 => 64, _ => 0 };
        var iat = BuildIatMap(bytes, spans, imageBase, descriptors, bitness == 64 ? 8 : 4);

        var funcs = new List<FunctionResult>();
        var apiCalls = new List<(string Api, string Dll, ulong Site, uint Rva)>();
        var syscallSites = new List<ulong>();
        var discovered = new List<uint>();

        // Scan IAT call sites up-front so functions that actually call sensitive APIs get disassembled.
        var preScan = bitness == 0
            ? new List<(string Api, string Dll, ulong Site, uint Rva)>()
            : ScanIatCallSites(bytes, spans, imageBase, iat, bitness);
        var preSensitive = preScan.Where(c => PeAnalyzer.SensitiveApis.ContainsKey(c.Api)).ToList();

        if (bitness != 0)
        {
            discovered = DiscoverFunctions(bytes, spans, bitness, out var prologueHits);
            result.FunctionTotal = discovered.Count;
            var planned = PlanFunctions(entryRva, discovered, SeedFunctions(preSensitive, prologueHits));

            int budget = MaxInstructionsTotal;
            var seen = new HashSet<uint>();
            var queue = new Queue<uint>(planned);
            int rounds = 0;
            while (queue.Count > 0 && funcs.Count < MaxFunctions && budget > 0 && rounds < MaxFunctions * 2)
            {
                rounds++;
                uint rva = queue.Dequeue();
                if (!seen.Add(rva)) continue;
                if (funcs.Any(f => rva >= f.Rva && rva < f.Rva + f.ByteLength)) continue;
                var fr = Disassemble(bytes, spans, imageBase, rva, bitness, iat, Math.Min(MaxInstructionsPerFunction, budget));
                if (fr is null || fr.InsnCount == 0) continue;
                funcs.Add(fr);
                budget -= fr.InsnCount;
                result.InstructionCount += fr.InsnCount;
                if (fr.HasSyscall) syscallSites.Add(imageBase + fr.Rva);
                foreach (var call in fr.CallSites) apiCalls.Add(call);
                foreach (var callee in fr.Callees)
                    if (funcs.Count + queue.Count < MaxFunctions && !seen.Contains(callee))
                        queue.Enqueue(callee);
            }
        }

        if (bitness != 0)
            foreach (var site in preScan)
                if (!apiCalls.Any(x => x.Api == site.Api && x.Site == site.Site))
                    apiCalls.Add(site);

        result.FunctionCount = funcs.Count;
        result.ApiCallSiteTotal = apiCalls.Count;
        var sensitiveCalls = apiCalls.Where(c => PeAnalyzer.SensitiveApis.ContainsKey(c.Api)).ToList();
        result.ApiCallSites = sensitiveCalls.Count;
        result.PackerSignature = MatchEntrySignature(bytes, spans, entryRva);

        var strings = ExtractStrings(bytes, spans);
        result.StringTotal = strings.Total;
        result.SuspiciousStrings = strings.Suspicious;

        var root = new ReportNode
        {
            Text = bitness == 0
                ? "REVERSE ENGINEERING / 深度逆向  (unsupported architecture)"
                : "REVERSE ENGINEERING / 深度逆向",
            Tone = Tone.Accent,
            Bold = true
        };
        root.Add(
            $"Functions   : {funcs.Count} disassembled / {result.FunctionTotal} discovered   " +
            $"Insns: {result.InstructionCount}", Tone.Muted);
        root.Add(
            $"Strings     : {strings.Kept} shown / {strings.Total} found   " +
            $"suspicious: {strings.Suspicious}", strings.Suspicious > 0 ? Tone.Warn : Tone.Muted);
        root.Add($"IAT xrefs   : {sensitiveCalls.Count} sensitive / {apiCalls.Count} total call site(s)",
            sensitiveCalls.Count > 0 ? Tone.Danger : Tone.Muted);
        if (bitness == 0)
            root.Add("Iced 仅覆盖 x86 / x64；当前架构跳过反汇编，仅做字符串与结构分析。", Tone.Warn);

        if (bitness != 0)
        {
            root.Children.Add(BuildDisassemblyNode(funcs, entryRva));
            root.Children.Add(BuildFunctionsNode(funcs, discovered));
            root.Children.Add(BuildCallGraphNode(funcs, apiCalls));
            root.Children.Add(BuildXrefNode(apiCalls, sensitiveCalls));
        }

        root.Children.Add(BuildStringsNode(strings));
        root.Children.Add(BuildToolchainNode(result.PackerSignature, imports, sections, strings));
        root.Children.Add(BuildRichHeaderNode(bytes));
        root.Children.Add(BuildOverlayNode(bytes, spans));
        root.Children.Add(BuildEntropyMapNode(bytes, spans));

        var anomalies = new ReportNode { Text = "ANOMALIES / 结构异常", Tone = Tone.Normal, Bold = true };
        AddAnomalies(anomalies, bytes, spans, imports, sensitiveCalls, syscallSites, funcs, strings, result);
        root.Children.Add(anomalies);

        result.Nodes.Add(root);
        return result;
    }

    // ---- module / address helpers ----

    // IAT slots are resolved from the import descriptors: walk OriginalFirstThunk for names and
    // FirstThunk for the slot address. PeNet's ImportFunction.IATOffset is relative to the IAT base,
    // not an RVA, so it cannot be used directly for call-site matching.
    private static Dictionary<ulong, (string Dll, string Api)> BuildIatMap(
        byte[] bytes, Span[] spans, ulong imageBase, IReadOnlyList<ImageImportDescriptor> descriptors, int ptrSize)
    {
        var map = new Dictionary<ulong, (string, string)>();
        foreach (var d in descriptors)
        {
            if (d.FirstThunk == 0 || d.OriginalFirstThunk == 0) continue;
            string dll = ReadCString(bytes, spans, d.Name) ?? "<unknown>";
            for (int i = 0; i < 2048; i++)
            {
                long lookup = OffsetOf(spans, d.OriginalFirstThunk + (uint)(i * ptrSize));
                if (lookup < 0) break;
                ulong thunk = ReadPtr(bytes, lookup, ptrSize);
                if (thunk == 0) break;

                bool byOrdinal = ptrSize == 8
                    ? (thunk & 0x8000000000000000UL) != 0
                    : (thunk & 0x80000000UL) != 0;
                if (byOrdinal) continue;

                string? name = ReadCString(bytes, spans, (uint)(thunk & 0x7FFFFFFF) + 2);
                if (string.IsNullOrWhiteSpace(name)) continue;
                map[imageBase + d.FirstThunk + (uint)(i * ptrSize)] = (dll, name!);
            }
        }
        return map;
    }

    private static long OffsetOf(Span[] spans, uint rva)
    {
        var span = SpanFor(spans, rva);
        return span is null ? -1 : RvaToOffset(span, rva);
    }

    private static ulong ReadPtr(byte[] bytes, long offset, int ptrSize)
    {
        if (offset < 0) return 0;
        if (ptrSize == 8) return offset + 8 <= bytes.Length ? BitConverter.ToUInt64(bytes, (int)offset) : 0;
        return offset + 4 <= bytes.Length ? BitConverter.ToUInt32(bytes, (int)offset) : 0;
    }

    private static string? ReadCString(byte[] bytes, Span[] spans, uint rva)
    {
        long off = OffsetOf(spans, rva);
        if (off < 0 || off >= bytes.Length) return null;
        var sb = new StringBuilder(64);
        for (long i = off; i < bytes.Length && sb.Length < 256; i++)
        {
            byte b = bytes[i];
            if (b == 0) return sb.Length == 0 ? null : sb.ToString();
            if (b is < 0x20 or > 0x7E) return null;
            sb.Append((char)b);
        }
        return null;
    }

    // Linear scan for `FF 15` (call qword [IAT]) across executable sections, so call sites are found
    // even in functions that were never selected for disassembly.
    private static List<(string Api, string Dll, ulong Site, uint Rva)> ScanIatCallSites(
        byte[] bytes, Span[] spans, ulong imageBase, Dictionary<ulong, (string Dll, string Api)> iat, int bitness)
    {
        var hits = new List<(string, string, ulong, uint)>();
        if (iat.Count == 0) return hits;
        var seen = new HashSet<(string Api, ulong Site)>();

        foreach (var s in spans)
        {
            if (!s.Exec || s.RawSize == 0) continue;
            long start = s.RawPtr;
            long end = Math.Min(bytes.Length, (long)s.RawPtr + s.RawSize) - 6;
            for (long i = start; i < end; i++)
            {
                if (bytes[i] != 0xFF || bytes[i + 1] != 0x15) continue;

                // A REX prefix (48/4C/49/41/40) belongs to the same call instruction: report the
                // prefix address and use a 7-byte instruction length instead of 6.
                long insnStart = i;
                bool rex = bitness == 64 && i > start &&
                           bytes[i - 1] is 0x48 or 0x4C or 0x49 or 0x41 or 0x40;
                if (rex) insnStart = i - 1;

                uint rva = s.Va + (uint)(insnStart - s.RawPtr);
                ulong target;
                if (bitness == 64)
                {
                    int disp = BitConverter.ToInt32(bytes, (int)i + 2);
                    long next = (long)(imageBase + rva) + (rex ? 7 : 6);
                    long abs = next + disp;
                    if (abs < 0) continue;
                    target = (ulong)abs;
                }
                else
                {
                    target = BitConverter.ToUInt32(bytes, (int)i + 2);
                }

                if (!iat.TryGetValue(target, out var api)) continue;
                ulong site = imageBase + rva;
                if (!seen.Add((api.Api, site))) continue;
                hits.Add((api.Api, api.Dll, site, rva));
                i += 5; // skip the displacement so the same call is not re-matched one byte later
            }
        }
        return hits;
    }

    private static Span? SpanFor(Span[] spans, uint rva)
    {
        foreach (var s in spans)
            if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.RawSize)) return s;
        return null;
    }

    private static long RvaToOffset(Span s, uint rva)
    {
        uint delta = rva - s.Va;
        if (delta >= s.RawSize) return -1;
        return (long)s.RawPtr + delta;
    }

    // ---- function discovery ----

    private static List<uint> DiscoverFunctions(byte[] bytes, Span[] spans, int bitness, out List<uint> prologueHits)
    {
        prologueHits = new List<uint>();
        var patterns = bitness == 64 ? Prologues64 : Prologues32;
        var found = new HashSet<uint>();

        foreach (var s in spans)
        {
            if (!s.Exec || s.RawSize == 0) continue;
            long start = s.RawPtr;
            long end = Math.Min(bytes.Length, (long)s.RawPtr + s.RawSize);
            for (long i = start; i < end - 12; i++)
            {
                bool hit = false;
                foreach (var (pattern, mask) in patterns)
                {
                    if (i + pattern.Length > end) continue;
                    bool ok = true;
                    for (int k = 0; k < pattern.Length; k++)
                    {
                        if (mask[k] == 1 && bytes[i + k] != pattern[k]) { ok = false; break; }
                    }
                    if (ok) { hit = true; break; }
                }
                if (!hit) continue;

                uint rva = s.Va + (uint)(i - s.RawPtr);
                if (!found.Add(rva)) continue;
                prologueHits.Add(rva);
                if (prologueHits.Count >= 4000) break;
            }
            if (prologueHits.Count >= 4000) break;
        }

        return prologueHits.ToList();
    }

    private static List<uint> PlanFunctions(uint entryRva, List<uint> discovered, List<uint> seeds)
    {
        var plan = new List<uint>();
        if (entryRva != 0) plan.Add(entryRva);
        foreach (var rva in seeds)
        {
            if (plan.Count >= 12) break;
            if (!plan.Contains(rva)) plan.Add(rva);
        }
        foreach (var rva in discovered)
        {
            if (plan.Count >= MaxFunctions * 2) break;
            if (!plan.Contains(rva)) plan.Add(rva);
        }
        return plan;
    }

    // Map each sensitive call site to the nearest preceding prologue so its containing function
    // is disassembled and the call line is annotated.
    private static List<uint> SeedFunctions(
        List<(string Api, string Dll, ulong Site, uint Rva)> sensitive, List<uint> prologues)
    {
        var seeds = new List<uint>();
        foreach (var site in sensitive)
        {
            uint best = 0;
            foreach (var rva in prologues)
                if (rva <= site.Rva && rva > best) best = rva;
            if (best != 0 && !seeds.Contains(best)) seeds.Add(best);
        }
        return seeds;
    }

    // ---- disassembly ----

    private static FunctionResult? Disassemble(
        byte[] bytes, Span[] spans, ulong imageBase, uint rva, int bitness,
        Dictionary<ulong, (string Dll, string Api)> iat, int maxInsn)
    {
        var span = SpanFor(spans, rva);
        if (span is null || !span.Exec) return null;
        long off = RvaToOffset(span, rva);
        if (off < 0 || off >= bytes.Length) return null;

        int avail = (int)Math.Min(
            Math.Min((long)span.RawSize - (rva - span.Va), (long)bytes.Length - off),
            MaxBytesPerFunction);
        if (avail < 2) return null;

        var reader = new ByteArrayCodeReader(bytes, (int)off, avail);
        var decoder = IcedDecoder.Create(bitness, reader, imageBase + rva, DecoderOptions.None);
        var fr = new FunctionResult { Rva = rva, Name = rva == 0 ? "image_base" : $"sub_{imageBase + rva:X8}" };
        int consumed = 0;
        var sb = new StringBuilder(96);

        for (int i = 0; i < maxInsn; i++)
        {
            var insn = decoder.Decode();
            if (insn.Code == Code.INVALID) break;

            sb.Clear();
            var output = new StringOutput(sb);
            Formatter.Format(insn, output);
            string text = sb.ToString();

            var tone = Tone.Normal;
            if (insn.Mnemonic == Mnemonic.Syscall)
            {
                fr.HasSyscall = true;
                tone = Tone.Danger;
                text += "   <- direct syscall (bypasses ntdll)";
            }
            else if (insn.Mnemonic == Mnemonic.Int3)
            {
                fr.Int3Count++;
                tone = Tone.Muted;
            }
            else if (insn.Mnemonic == Mnemonic.Cpuid)
            {
                fr.CpuidCount++;
                tone = Tone.Warn;
            }
            else if (insn.Mnemonic == Mnemonic.Rdtsc)
            {
                fr.HasRdtsc = true;
                tone = Tone.Warn;
            }

            if (insn.MemorySegment is Register.FS or Register.GS &&
                (insn.MemoryDisplacement32 == 0x30 || insn.MemoryDisplacement32 == 0x60))
                fr.HasPebAccess = true;

            if (insn.IsCallNear)
            {
                ulong target = insn.NearBranchTarget;
                uint trva = (uint)(target - imageBase);
                var tspan = SpanFor(spans, trva);
                if (tspan is not null && tspan.Exec && target >= imageBase)
                {
                    fr.Callees.Add(trva);
                    text += $"   ; -> {target:X8}";
                    if (tone == Tone.Normal) tone = Tone.Accent;
                }
            }
            else if (insn.IsCallNearIndirect && insn.InstructionMemoryTarget(out ulong memTarget) &&
                     iat.TryGetValue(memTarget, out var hit))
            {
                fr.CallSites.Add((hit.Api, hit.Dll, insn.IP, rva));
                bool sensitive = PeAnalyzer.SensitiveApis.ContainsKey(hit.Api);
                text += $"   ; -> {hit.Dll}!{hit.Api}" + (sensitive ? "   [!] SENSITIVE" : "");
                tone = sensitive ? Tone.Danger : Tone.Accent;
            }

            string hex = HexBytes(bytes, (int)(off + consumed), insn.Length);
            fr.Lines.Add(($"0x{insn.IP:X8}  {hex,-26}  {text}", tone));
            fr.InsnCount++;
            consumed += insn.Length;

            if (insn.Mnemonic == Mnemonic.Ret)
            {
                int next = (int)(off + consumed);
                if (next + 1 >= bytes.Length) break;
                if (bytes[next] is 0xCC or 0x90 or 0x00) break;
                if (i > 24) break;
            }
            if (consumed >= avail - 1) break;
        }

        fr.ByteLength = (uint)consumed;
        return fr.InsnCount == 0 ? null : fr;
    }

    private static bool InstructionMemoryTarget(this Instruction insn, out ulong target)
    {
        target = 0;
        if (insn.IsIPRelativeMemoryOperand)
        {
            target = insn.IPRelativeMemoryAddress;
            return true;
        }
        if (insn.MemoryBase == Register.None && insn.MemoryIndex == Register.None)
        {
            target = insn.MemoryDisplacement64;
            return true;
        }
        return false;
    }

    private static string HexBytes(byte[] bytes, int offset, int count)
    {
        var sb = new StringBuilder(count * 3);
        for (int i = 0; i < count && offset + i < bytes.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(bytes[offset + i].ToString("x2"));
        }
        return sb.ToString();
    }

    // ---- report nodes: disassembly / functions / call graph / xref ----

    private static ReportNode BuildDisassemblyNode(List<FunctionResult> funcs, uint entryRva)
    {
        var node = new ReportNode { Text = "DISASSEMBLY / 反汇编", Tone = Tone.Accent, Bold = true };
        if (funcs.Count == 0)
        {
            node.Add("(nothing disassembled)", Tone.Muted);
            return node;
        }
        foreach (var f in funcs)
        {
            string label = f.Rva == entryRva ? "ENTRY" : f.Name;
            var fn = node.Group(
                $"0x{f.Rva:X8}  {label,-16}  insn {f.InsnCount,-3} calls {f.Callees.Count}", Tone.Normal, false);
            foreach (var (text, tone) in f.Lines) fn.Add(text, tone);
        }
        if (funcs.Count >= MaxFunctions)
            node.Add($"... 反汇编上限 {MaxFunctions} 个函数 / {MaxInstructionsTotal} 条指令，其余未展开", Tone.Muted);
        return node;
    }

    private static ReportNode BuildFunctionsNode(List<FunctionResult> funcs, List<uint> discovered)
    {
        var node = new ReportNode { Text = "FUNCTIONS / 函数识别", Tone = Tone.Accent, Bold = true };
        node.Add($"Prologue hits: {discovered.Count}   disassembled: {funcs.Count}", Tone.Muted);
        foreach (var f in funcs)
        {
            string flags = "";
            if (f.HasSyscall) flags += " SYSCALL";
            if (f.HasPebAccess) flags += " PEB";
            if (f.HasRdtsc) flags += " RDTSC";
            if (f.CpuidCount > 0) flags += $" CPUID×{f.CpuidCount}";
            if (f.Int3Count > 0) flags += $" INT3×{f.Int3Count}";
            node.Add(
                $"0x{f.Rva:X8}  {f.Name,-18} insn {f.InsnCount,-3} callees {f.Callees.Count,-3}{flags}",
                flags.Length > 0 ? Tone.Warn : Tone.Normal);
        }
        var tail = funcs.OrderByDescending(f => f.InsnCount).FirstOrDefault();
        if (tail is not null)
            node.Add($"largest analysed block: {tail.Name} ({tail.InsnCount} insn)", Tone.Muted);
        return node;
    }

    private static ReportNode BuildCallGraphNode(List<FunctionResult> funcs, List<(string Api, string Dll, ulong Site, uint Rva)> apiCalls)
    {
        var node = new ReportNode { Text = "CALL GRAPH / 调用图", Tone = Tone.Accent, Bold = true };
        int edges = funcs.Sum(f => f.Callees.Count);
        node.Add($"Internal edges: {edges}   external (IAT) sites: {apiCalls.Count}", Tone.Muted);

        var hubs = funcs
            .Select(f => (f.Name, Rva: f.Rva, Degree: f.Callees.Count + funcs.Count(o => o.Callees.Contains(f.Rva))))
            .OrderByDescending(x => x.Degree)
            .Take(8)
            .ToList();
        node.Add("Hubs (callees + callers):", Tone.Muted);
        foreach (var (name, rva, degree) in hubs)
            node.Add($"  0x{rva:X8}  {name,-18} degree {degree}");

        if (edges > 0)
        {
            node.Add("Edges (sample):", Tone.Muted);
            foreach (var f in funcs)
                foreach (var callee in f.Callees.Distinct().Take(4))
                    node.Add($"  0x{f.Rva:X8} -> 0x{callee:X8}", Tone.Muted);
        }
        return node;
    }

    private static ReportNode BuildXrefNode(
        List<(string Api, string Dll, ulong Site, uint Rva)> all,
        List<(string Api, string Dll, ulong Site, uint Rva)> sensitive)
    {
        var node = new ReportNode
        {
            Text = "IAT XREFS / 导入调用点",
            Tone = sensitive.Count > 0 ? Tone.Danger : Tone.Accent,
            Bold = true
        };
        node.Add($"sensitive {sensitive.Count}   all IAT call sites {all.Count}", Tone.Muted);
        if (sensitive.Count == 0)
            node.Add("未定位到敏感 API 的直接调用点", Tone.Muted);

        foreach (var g in sensitive.GroupBy(c => c.Api).OrderByDescending(g => g.Count()))
        {
            var info = PeAnalyzer.SensitiveApis[g.Key];
            var sites = g.Select(c => $"0x{c.Site:X8}").Distinct().Take(6).ToList();
            node.Add($"{g.Key}  [{info.Level}]  {g.First().Dll}  xrefs {g.Count()}", Tone.Danger, true);
            node.Add($"   sites: {string.Join(", ", sites)}", Tone.Danger);
        }

        var others = all
            .Where(c => !PeAnalyzer.SensitiveApis.ContainsKey(c.Api))
            .GroupBy(c => c.Api)
            .OrderByDescending(g => g.Count())
            .Take(40)
            .ToList();
        if (others.Count > 0)
        {
            var otherNode = node.Group($"OTHER IAT CALLS / 其他导入调用 [{others.Count} APIs]", Tone.Normal, false);
            foreach (var g in others)
                otherNode.Add($"{g.Key,-28} {g.First().Dll,-22} xrefs {g.Count()}", Tone.Muted);
        }
        node.Add("注: 统计 call [IAT] 直接调用；GetProcAddress 动态解析与 jmp thunk 不计入。", Tone.Muted);
        return node;
    }

    // ---- strings ----

    private sealed class StringResult
    {
        public int Total;
        public int Suspicious;
        public int Kept;
        public List<(string Cat, string Value, uint Rva, string Section, Tone Tone, bool Suspicious)> Items = new();
    }

    private static StringResult ExtractStrings(byte[] bytes, Span[] spans)
    {
        var res = new StringResult();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var raw = new List<(string Value, uint Rva, string Section, bool Wide)>();
        int scanned = 0;

        for (int i = 0; i < bytes.Length && scanned < MaxStringsScanned; i++)
        {
            // ASCII
            if (bytes[i] is >= 0x20 and <= 0x7E)
            {
                int start = i;
                while (i < bytes.Length && bytes[i] is >= 0x20 and <= 0x7E) i++;
                int len = i - start;
                if (len >= 5 && len <= 512) Capture(bytes, spans, start, len, false, raw, res);
                i--;
                continue;
            }

            // UTF-16LE (ASCII range only)
            if (bytes[i] is >= 0x20 and <= 0x7E && i + 1 < bytes.Length && bytes[i + 1] == 0)
            {
                int start = i;
                int chars = 0;
                while (i + 1 < bytes.Length && bytes[i] is >= 0x20 and <= 0x7E && bytes[i + 1] == 0)
                {
                    i += 2;
                    chars++;
                }
                if (chars >= 4 && chars <= 256) Capture(bytes, spans, start, chars * 2, true, raw, res);
                i--;
                continue;
            }
            scanned++;
        }

        foreach (var item in raw)
        {
            var (cat, tone, suspicious) = Classify(item.Value);
            res.Items.Add((cat, item.Value, item.Rva, item.Section, tone, suspicious));
            res.Total++;
            if (suspicious) res.Suspicious++;
        }

        // Keep the highest-signal strings first: suspicious, then long values.
        var kept = res.Items
            .OrderByDescending(x => x.Suspicious)
            .ThenByDescending(x => x.Value.Length)
            .Take(MaxStringNodes)
            .ToList();
        res.Kept = kept.Count;
        res.Items = kept;
        return res;
    }

    private static void Capture(
        byte[] bytes, Span[] spans, int offset, int len, bool wide,
        List<(string, uint, string, bool)> raw, StringResult res)
    {
        string value = wide
            ? Encoding.Unicode.GetString(bytes, offset, len)
            : Encoding.ASCII.GetString(bytes, offset, len);
        if (value.Length < 4) return;

        var span = spans.FirstOrDefault(s => offset >= s.RawPtr && offset < s.RawPtr + s.RawSize);
        if (span is null) return;
        uint rva = span.Va + (uint)(offset - span.RawPtr);
        raw.Add((value, rva, span.Name, wide));
    }

    private static (string Cat, Tone Tone, bool Suspicious) Classify(string s)
    {
        if (UrlRx.IsMatch(s)) return ("URL / 网络", Tone.Danger, true);
        if (IpRx.IsMatch(s) && s.Split('.').All(p => int.TryParse(p, out int v) && v <= 255))
            return ("IP 地址", Tone.Danger, true);
        if (CmdRx.IsMatch(s)) return ("命令行 / LOLBin", Tone.Danger, true);
        if (MalwareRx.IsMatch(s)) return ("可疑指示", Tone.Danger, true);
        if (AntiVmRx.IsMatch(s)) return ("反分析 / 虚拟环境", Tone.Warn, true);
        if (RegistryRx.IsMatch(s)) return ("注册表", Tone.Warn, false);
        if (PathRx.IsMatch(s)) return ("文件路径", Tone.Warn, false);
        if (UserAgentRx.IsMatch(s)) return ("User-Agent", Tone.Accent, false);
        if (DotNetRx.IsMatch(s)) return ("运行时 / 框架", Tone.Warn, false);
        if (ModuleRx.IsMatch(s)) return ("模块名", Tone.Normal, false);
        return ("其他", Tone.Normal, false);
    }

    private static ReportNode BuildStringsNode(StringResult strings)
    {
        var node = new ReportNode
        {
            Text = "STRINGS / 字符串",
            Tone = strings.Suspicious > 0 ? Tone.Warn : Tone.Accent,
            Bold = true
        };
        node.Add($"found {strings.Total}   shown {strings.Kept}   suspicious {strings.Suspicious}", Tone.Muted);
        if (strings.Total == 0)
        {
            node.Add("(no printable strings)", Tone.Muted);
            return node;
        }
        foreach (var g in strings.Items.GroupBy(x => x.Cat).OrderByDescending(g => g.Count()))
        {
            bool hot = g.Any(x => x.Suspicious);
            var cat = node.Group($"{g.Key}  [{g.Count()}]", hot ? Tone.Danger : Tone.Normal, false);
            foreach (var item in g.Take(120))
            {
                string sec = string.IsNullOrWhiteSpace(item.Section) ? "?" : item.Section;
                string text = item.Value.Length > 96 ? item.Value[..96] + "..." : item.Value;
                cat.Add($"{sec,-8} 0x{item.Rva:X8}  {text}", item.Tone);
            }
            if (g.Count() > 120) cat.Add($"... 另有 {g.Count() - 120} 条未展开", Tone.Muted);
        }
        return node;
    }

    // ---- toolchain / packer fingerprints ----

    private static string? MatchEntrySignature(byte[] bytes, Span[] spans, uint entryRva)
    {
        if (entryRva == 0) return null;
        var span = SpanFor(spans, entryRva);
        if (span is null) return null;
        long off = RvaToOffset(span!, entryRva);
        if (off < 0) return null;
        foreach (var (name, pattern, mask) in EntrySignatures)
        {
            if (off + pattern.Length > bytes.Length) continue;
            bool ok = true;
            for (int i = 0; i < pattern.Length; i++)
                if (mask[i] == 1 && bytes[off + i] != pattern[i]) { ok = false; break; }
            if (ok) return name;
        }
        return null;
    }

    private static ReportNode BuildToolchainNode(
        string? packerSig, IReadOnlyList<ImportFunction> imports, IReadOnlyList<SectionInfo> sections, StringResult strings)
    {
        var node = new ReportNode { Text = "TOOLCHAIN / 编译器与保护壳指纹", Tone = Tone.Accent, Bold = true };
        if (packerSig is not null)
            node.Add($"EP signature match: {packerSig}", Tone.Danger, true);
        else
            node.Add("EP signature match: none", Tone.Muted);

        var modules = imports.Select(i => i.DLL ?? "").Where(d => d.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var names = sections.Select(s => s.Name.ToLowerInvariant()).ToHashSet();

        string tool =
            modules.Any(m => m.StartsWith("msvbvm", StringComparison.OrdinalIgnoreCase)) ? "Visual Basic 6 (MSVBVM)"
            : modules.Any(m => m.Contains("vcruntime", StringComparison.OrdinalIgnoreCase) ||
                               m.Contains("msvcp", StringComparison.OrdinalIgnoreCase) ||
                               m.Contains("ucrtbase", StringComparison.OrdinalIgnoreCase) ||
                               m.Contains("api-ms-win-crt", StringComparison.OrdinalIgnoreCase)) ? "MSVC / Universal CRT"
            : strings.Items.Any(s => s.Value.Contains("Go build ID", StringComparison.Ordinal)) ? "Go (build ID string)"
            : strings.Items.Any(s => s.Value.Contains("rustc", StringComparison.OrdinalIgnoreCase)) ? "Rust (rustc marker)"
            : names.Contains("code") && names.Contains("data") && modules.Any(m => m.Contains("msvcrt")) ? "Delphi / Borland"
            : modules.Any(m => m.Equals("msvcrt.dll", StringComparison.OrdinalIgnoreCase)) ? "MinGW / GCC (msvcrt)"
            : "unknown / statically linked or packed";
        node.Add($"Toolchain hint: {tool}");

        node.Add($"Sections: {string.Join(" ", sections.Select(s => s.Name))}", Tone.Muted);
        node.Add($"Import modules: {modules.Count}", Tone.Muted);

        bool dynamicResolve = imports.Any(i => i.Name is "GetProcAddress" or "LdrGetProcedureAddress") &&
                              imports.Any(i => i.Name is "LoadLibraryA" or "LoadLibraryW" or "LoadLibraryExA" or "LoadLibraryExW");
        node.Add($"Dynamic API resolution (LoadLibrary + GetProcAddress): {(dynamicResolve ? "yes" : "no")}",
            dynamicResolve ? Tone.Warn : Tone.Muted);
        return node;
    }

    private static ReportNode BuildRichHeaderNode(byte[] bytes)
    {
        var node = new ReportNode { Text = "RICH HEADER / 构建信息", Tone = Tone.Normal, Bold = true };
        var entries = ParseRich(bytes, out uint? key);
        if (entries.Count == 0)
        {
            node.Add("(no Rich header — stripped, non-MSVC or packed)", Tone.Muted);
            return node;
        }
        node.Add($"XOR key 0x{key:X8}   entries {entries.Count}", Tone.Muted);
        foreach (var (prod, build, count) in entries.OrderByDescending(e => e.Count).Take(16))
            node.Add($"prod 0x{prod:X4}  build {build,-6}  objects {count}");
        if (entries.Count > 16) node.Add($"... 另有 {entries.Count - 16} 项未展开", Tone.Muted);
        return node;
    }

    private static List<(int Prod, int Build, int Count)> ParseRich(byte[] bytes, out uint? keyOut)
    {
        keyOut = null;
        var list = new List<(int, int, int)>();
        int limit = Math.Min(bytes.Length - 8, 0x1000);
        for (int p = 0x40; p < limit; p++)
        {
            if (bytes[p] != (byte)'R' || bytes[p + 1] != (byte)'i' || bytes[p + 2] != (byte)'c' || bytes[p + 3] != (byte)'h')
                continue;
            uint key = BitConverter.ToUInt32(bytes, p + 4);
            for (int s = p - 8; s >= 0x40; s -= 4)
            {
                if ((BitConverter.ToUInt32(bytes, s) ^ key) != 0x536E6144) continue; // "DanS"
                for (int e = s + 16; e + 8 <= p; e += 8)
                {
                    uint compid = BitConverter.ToUInt32(bytes, e) ^ key;
                    uint count = BitConverter.ToUInt32(bytes, e + 4) ^ key;
                    list.Add(((int)(compid >> 16), (int)(compid & 0xFFFF), (int)count));
                }
                keyOut = key;
                return list;
            }
        }
        return list;
    }

    // ---- overlay / entropy map ----

    private static ReportNode BuildOverlayNode(byte[] bytes, Span[] spans)
    {
        var node = new ReportNode { Text = "OVERLAY / 附加数据", Tone = Tone.Normal, Bold = true };
        long end = 0;
        foreach (var s in spans)
            if (s.RawSize > 0) end = Math.Max(end, (long)s.RawPtr + s.RawSize);
        long size = bytes.Length - end;
        if (size <= 0)
        {
            node.Add("(none — file ends with the last section)", Tone.Muted);
            return node;
        }
        double entropy = Entropy(bytes, end, size);
        node.Add($"Offset 0x{end:X8}   size {size:N0} bytes   entropy {entropy:F3}",
            entropy >= 7.0 && size >= 4096 ? Tone.Warn : Tone.Muted);
        node.Add("Preview: " + HexBytes(bytes, (int)Math.Min(end, bytes.Length - 1), (int)Math.Min(24, size)), Tone.Muted);
        return node;
    }

    private static ReportNode BuildEntropyMapNode(byte[] bytes, Span[] spans)
    {
        var node = new ReportNode { Text = "ENTROPY MAP / 熵分布", Tone = Tone.Normal, Bold = true };
        const string ramp = "▁▂▃▄▅▆▇█";
        foreach (var s in spans)
        {
            if (s.RawSize == 0) continue;
            long start = s.RawPtr;
            long total = Math.Min(s.RawSize, (long)bytes.Length - start);
            if (total <= 0) continue;
            const int blocks = 48;
            long step = Math.Max(1, total / blocks);
            var bar = new StringBuilder(blocks);
            double max = 0, sum = 0;
            int n = 0;
            for (long b = 0; b < total; b += step)
            {
                int len = (int)Math.Min(step, total - b);
                double e = Entropy(bytes, start + b, len);
                max = Math.Max(max, e);
                sum += e;
                n++;
                int idx = (int)Math.Clamp(e / 8.0 * (ramp.Length - 1), 0, ramp.Length - 1);
                bar.Append(ramp[idx]);
                if (n >= blocks) break;
            }
            double avg = n > 0 ? sum / n : 0;
            var tone = max >= 7.5 ? Tone.Danger : max >= 7.0 ? Tone.Warn : Tone.Normal;
            node.Add($"{s.Name,-10} H={avg:F2}/{max:F2}  {bar}", tone);
        }
        node.Add("图例: ▁ 低熵(代码/字符串)  █ 高熵(压缩/加密)", Tone.Muted);
        return node;
    }

    private static double Entropy(byte[] data, long offset, long count)
    {
        if (count <= 0 || offset < 0 || offset >= data.Length) return 0;
        long end = Math.Min(offset + count, data.Length);
        long total = end - offset;
        if (total <= 0) return 0;
        var freq = new int[256];
        for (long i = offset; i < end; i++) freq[data[i]]++;
        double e = 0;
        foreach (int f in freq)
            if (f > 0)
            {
                double p = f / (double)total;
                e -= p * Math.Log2(p);
            }
        return e;
    }

    // ---- anomalies ----

    private static void AddAnomalies(
        ReportNode node, byte[] bytes, Span[] spans, IReadOnlyList<ImportFunction> imports,
        List<(string Api, string Dll, ulong Site, uint Rva)> sensitiveCalls, List<ulong> syscallSites,
        List<FunctionResult> funcs, StringResult strings, ReResult result)
    {
        int issues = 0;

        void Flag(string severity, string title, string? detail, int weight)
        {
            var tone = severity is "CRITICAL" or "HIGH" ? Tone.Danger
                : severity == "MEDIUM" ? Tone.Warn : Tone.Muted;
            node.Add($"[{severity}] {title}", tone, tone == Tone.Danger);
            if (detail is not null) node.Add("           " + detail, Tone.Muted);
            result.Findings.Add(new Finding
            {
                Severity = severity, Title = title, Detail = detail ?? "", Weight = weight
            });
            issues++;
        }

        foreach (var s in spans)
        {
            long end = (long)s.RawPtr + s.RawSize;
            if (s.RawSize > 0 && end > bytes.Length)
                Flag("HIGH", $"节区 {s.Name} 原始数据越出文件末尾",
                    $"raw 0x{s.RawPtr:X8}+0x{s.RawSize:X8} > file 0x{bytes.Length:X8}", 14);
        }

        for (int i = 0; i < spans.Length; i++)
            for (int j = i + 1; j < spans.Length; j++)
            {
                var a = spans[i];
                var b = spans[j];
                if (a.VSize == 0 || b.VSize == 0) continue;
                long aEnd = (long)a.Va + a.VSize;
                long bEnd = (long)b.Va + b.VSize;
                if (a.Va < bEnd && b.Va < aEnd)
                    Flag("MEDIUM", $"节区 VA 区间重叠: {a.Name} / {b.Name}",
                        $"{a.Name} 0x{a.Va:X8}+0x{a.VSize:X}   {b.Name} 0x{b.Va:X8}+0x{b.VSize:X}", 10);
            }

        int ordinalOnly = imports.Count(i => string.IsNullOrWhiteSpace(i.Name));
        if (ordinalOnly > 0)
            Flag("MEDIUM", $"IAT 含 {ordinalOnly} 个序号导入（无名称）",
                "常见于隐藏 API 名或手工构造导入表", 6);

        if (result.PackerSignature is not null)
            Flag("CRITICAL", $"入口点特征匹配保护壳: {result.PackerSignature}",
                "字节签名命中，代码可能被压缩/加密，静态反汇编不可信", 30);

        if (syscallSites.Count > 0)
            Flag("HIGH", $"发现 {syscallSites.Count} 处直接 syscall 指令",
                "绕过 ntdll 挂钩，常见于 EDR 规避与 shellcode", 16);

        if (sensitiveCalls.Count > 0)
        {
            var distinct = sensitiveCalls.Select(c => c.Api).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            Flag("HIGH", $"敏感 API 调用点已定位: {distinct.Count} 个 API / {sensitiveCalls.Count} 处",
                string.Join(", ", distinct.Take(6)) + $"  @ 0x{sensitiveCalls[0].Site:X8}",
                Math.Min(12, 3 + distinct.Count));
        }

        if (funcs.Any(f => f.HasPebAccess))
            Flag("MEDIUM", "代码直接读取 PEB (fs:[30h] / gs:[60h])",
                "常见于反调试、API 哈希解析与隐藏导入", 8);

        if (funcs.Any(f => f.HasRdtsc) && funcs.Any(f => f.CpuidCount > 0))
            Flag("LOW", "RDTSC + CPUID 组合", "可能用于时间反调试 / 虚拟机检测", 3);

        int antiVm = strings.Items.Count(s => s.Cat == "反分析 / 虚拟环境");
        if (antiVm > 0)
            Flag("MEDIUM", $"字符串含反虚拟化关键字 ×{antiVm}", null, 8);

        int cmds = strings.Items.Count(s => s.Cat == "命令行 / LOLBin");
        if (cmds > 0)
            Flag("MEDIUM", $"字符串引用系统工具 / LOLBin ×{cmds}", null, 8);

        long overlaySize = bytes.Length - spans.Where(s => s.RawSize > 0)
            .Select(s => (long)s.RawPtr + s.RawSize).DefaultIfEmpty(0).Max();
        if (overlaySize > 0)
        {
            double e = Entropy(bytes, bytes.Length - overlaySize, overlaySize);
            if (overlaySize >= 4096 && e >= 7.0)
                Flag("MEDIUM", $"overlay {overlaySize:N0} 字节且高熵 ({e:F2})",
                    "附加数据可能携带加密载荷 / 安装包", 10);
        }

        if (issues == 0) node.Add("未发现异常结构", Tone.Safe);
    }
}

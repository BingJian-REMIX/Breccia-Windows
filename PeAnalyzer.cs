using System.IO;
using System.Security.Cryptography;
using PeNet;
using PeNet.Header.Pe;

namespace Breccia.WPF;

public enum Tone { Normal, Accent, Danger, Warn, Safe, Muted }

public sealed class ReportNode
{
    public string Text { get; set; } = "";
    public Tone Tone { get; set; } = Tone.Normal;
    public bool Bold { get; set; }
    public List<ReportNode> Children { get; set; } = new();

    public ReportNode Add(string text, Tone tone = Tone.Normal, bool bold = false)
    {
        Children.Add(new ReportNode { Text = text, Tone = tone, Bold = bold });
        return this;
    }

    public ReportNode Group(string text, Tone tone = Tone.Accent, bool bold = true)
    {
        var node = new ReportNode { Text = text, Tone = tone, Bold = bold };
        Children.Add(node);
        return node;
    }
}

public sealed class SectionInfo
{
    public string Name { get; set; } = "";
    public uint VirtualAddress { get; set; }
    public uint VirtualSize { get; set; }
    public uint RawSize { get; set; }
    public uint RawPointer { get; set; }
    public double Entropy { get; set; }
    public bool Executable { get; set; }
    public bool Writable { get; set; }
    public bool Readable { get; set; }
    public bool PackerMarker { get; set; }
    public string Characteristics { get; set; } = "";
}

public sealed class Finding
{
    public string Severity { get; set; } = "INFO";
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Weight { get; set; }
}

public sealed class AnalysisReport
{
    public string FileName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public long FileSize { get; set; }
    public string Sha256 { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string Md5 { get; set; } = "";
    public string? ImpHash { get; set; }
    public string? TypeRefHash { get; set; }
    public string Architecture { get; set; } = "";
    public string ImageType { get; set; } = "";
    public string CompileTime { get; set; } = "";
    public string EntryPoint { get; set; } = "";
    public string Subsystem { get; set; } = "";
    public bool IsDotNet { get; set; }
    public int ImportCount { get; set; }
    public int ExportCount { get; set; }
    public int RiskScore { get; set; }
    public string RiskLevel { get; set; } = "";
    public List<SectionInfo> Sections { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
    public List<ReportNode> Nodes { get; set; } = new();
}

public static class PeAnalyzer
{
    private static readonly string[] PackerMarkers =
        { "UPX0", "UPX1", ".VMP", ".ASPACK", ".THEMIDA", ".NSP", ".ENIGMA", ".RLPACK" };

    private static readonly Dictionary<string, (string Level, int Weight)> SensitiveApis =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["CreateRemoteThread"] = ("CRITICAL", 12),
            ["CreateRemoteThreadEx"] = ("CRITICAL", 12),
            ["NtCreateThreadEx"] = ("CRITICAL", 12),
            ["RtlCreateUserThread"] = ("CRITICAL", 12),
            ["QueueUserAPC"] = ("CRITICAL", 10),
            ["NtQueueApcThread"] = ("CRITICAL", 10),
            ["SetThreadContext"] = ("CRITICAL", 10),
            ["NtSetContextThread"] = ("CRITICAL", 10),
            ["VirtualAllocEx"] = ("HIGH", 8),
            ["VirtualAllocExNuma"] = ("HIGH", 8),
            ["WriteProcessMemory"] = ("HIGH", 8),
            ["NtWriteVirtualMemory"] = ("HIGH", 8),
            ["ZwWriteVirtualMemory"] = ("HIGH", 8),
            ["NtUnmapViewOfSection"] = ("HIGH", 8),
            ["ZwUnmapViewOfSection"] = ("HIGH", 8),
            ["NtMapViewOfSection"] = ("HIGH", 6),
            ["SetWindowsHookExA"] = ("MEDIUM", 5),
            ["SetWindowsHookExW"] = ("MEDIUM", 5),
            ["GetAsyncKeyState"] = ("MEDIUM", 5),
            ["AdjustTokenPrivileges"] = ("MEDIUM", 5),
            ["OpenProcessToken"] = ("MEDIUM", 5),
            ["CreateProcessAsUserA"] = ("MEDIUM", 5),
            ["CreateProcessAsUserW"] = ("MEDIUM", 5),
            ["URLDownloadToFileA"] = ("MEDIUM", 5),
            ["URLDownloadToFileW"] = ("MEDIUM", 5),
            ["WinHttpOpen"] = ("MEDIUM", 4),
            ["IsDebuggerPresent"] = ("LOW", 2),
            ["CheckRemoteDebuggerPresent"] = ("LOW", 2),
            ["NtQueryInformationProcess"] = ("LOW", 2)
        };

    private static readonly string[] DirectoryNames =
    {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
        "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
        "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"
    };

    private static readonly string[] InjectionChain =
        { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" };

    public static AnalysisReport Analyze(string path) => Analyze(File.ReadAllBytes(path), path);

    public static AnalysisReport Analyze(byte[] bytes, string path)
    {
        PeFile pe;
        try { pe = new PeFile(bytes); }
        catch (Exception ex) { throw new InvalidDataException("不是有效的 PE 映像（文件过小或 DOS/PE 头损坏）", ex); }

        var nt = pe.ImageNtHeaders;
        if (nt is null || nt.Signature != 0x00004550)
            throw new InvalidDataException("不是有效的 PE 映像（MZ / PE 头缺失）");

        var fh = nt.FileHeader;
        var oh = nt.OptionalHeader;

        // All optional structures are read defensively: malformed / packed PEs can throw on lazy parsing.
        var sections = Arr(() => pe.ImageSectionHeaders);
        var imports = Arr(() => pe.ImportedFunctions);
        var delayImports = Arr(() => pe.DelayImportedFunctions);
        var exports = Arr(() => pe.ExportedFunctions);
        var descriptors = Arr(() => pe.ImageImportDescriptors);
        var delayDescriptors = Arr(() => pe.ImageDelayImportDescriptors);
        var relocs = Arr(() => pe.ImageRelocationDirectory);
        var debug = Arr(() => pe.ImageDebugDirectory);
        var runtimeFuncs = Arr(() => pe.ExceptionDirectory);
        var directories = Arr(() => oh.DataDirectory);
        var tls = SafeOrNull<ImageTlsDirectory>(() => pe.ImageTlsDirectory);
        var loadConfig = SafeOrNull<ImageLoadConfigDirectory>(() => pe.ImageLoadConfigDirectory);
        var clr = SafeOrNull<ImageCor20Header>(() => pe.ImageComDescriptor);
        var exportDir = SafeOrNull<ImageExportDirectory>(() => pe.ImageExportDirectory);
        var resourceDir = SafeOrNull<ImageResourceDirectory>(() => pe.ImageResourceDirectory);
        var winCert = SafeOrNull<WinCertificate>(() => pe.WinCertificate);
        var auth = SafeOrNull<PeNet.Header.Authenticode.AuthenticodeInfo>(() => pe.AuthenticodeInfo);
        var meta = SafeOrNull<PeNet.Header.Net.MetaDataHdr>(() => pe.MetaDataHdr);
        var resources = SafeOrNull<PeNet.Header.Resource.Resources>(() => pe.Resources);
        var dos = SafeOrNull<ImageDosHeader>(() => pe.ImageDosHeader);

        uint machine = Convert.ToUInt32(fh.Machine);
        string arch = machine switch
        {
            0x014C => "x86 (I386 / 32-bit)",
            0x8664 => "x64 (AMD64 / 64-bit)",
            0xAA64 => "ARM64 (AArch64)",
            0x01C0 or 0x01C4 => "ARM (32-bit)",
            0x0200 => "IA64",
            _ => $"UNKNOWN (0x{machine:X4})"
        };
        long stamp = fh.TimeDateStamp;
        string compiled = stamp is > 0 and < 253402300799
            ? DateTimeOffset.FromUnixTimeSeconds(stamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz")
            : "N/A (timestamp 0 / invalid)";
        bool isDotNet = Safe(() => pe.IsDotNet, false);
        bool isDll = Safe(() => pe.IsDll, false);
        bool isDriver = Safe(() => pe.IsDriver, false);
        bool signed = Safe(() => pe.IsAuthenticodeSigned, false);
        bool validSig = Safe(() => pe.HasValidAuthenticodeSignature, false);
        bool trustedSig = Safe(() => pe.IsTrustedAuthenticodeSignature, false);

        uint dllChars = Convert.ToUInt32(oh.DllCharacteristics);
        bool aslr = (dllChars & 0x0040) != 0;
        bool dep = (dllChars & 0x0100) != 0;
        bool highEntropyVa = (dllChars & 0x0020) != 0;
        bool guardCf = (dllChars & 0x4000) != 0;

        var report = new AnalysisReport
        {
            FileName = Path.GetFileName(path),
            FilePath = path,
            FileSize = bytes.LongLength,
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
            Sha1 = Convert.ToHexString(SHA1.HashData(bytes)),
            Md5 = Convert.ToHexString(MD5.HashData(bytes)),
            ImpHash = Safe(() => pe.ImpHash, null),
            TypeRefHash = Safe(() => pe.TypeRefHash, null),
            Architecture = arch,
            ImageType = isDriver ? "SYS (driver)" : isDll ? "DLL" : "EXE",
            CompileTime = compiled,
            EntryPoint = $"0x{oh.AddressOfEntryPoint:X8}",
            Subsystem = Safe(() => oh.SubsystemResolved, "?"),
            IsDotNet = isDotNet,
            ImportCount = imports.Length,
            ExportCount = exports.Length
        };

        var findings = new List<Finding>();
        var root = new ReportNode();

        // ---- IDENTITY ----
        var id = root.Group("IDENTITY / 标识");
        Kv(id, "File", report.FileName);
        Kv(id, "Size", $"{bytes.LongLength:N0} bytes");
        Kv(id, "Type", $"{report.ImageType}  |  {(isDotNet ? ".NET assembly" : "native")}");
        Kv(id, "Architecture", arch);
        Kv(id, "Machine", $"0x{machine:X4} ({fh.MachineResolved})");
        Kv(id, "Compile Time", compiled);
        Kv(id, "EntryPoint", $"{report.EntryPoint} (RVA)");
        Kv(id, "ImageBase", $"0x{oh.ImageBase:X}");
        Kv(id, "Subsystem", report.Subsystem);
        Kv(id, "SizeOfImage", $"0x{oh.SizeOfImage:X8}");
        Kv(id, "CheckSum", $"0x{oh.CheckSum:X8}");
        Kv(id, "Linker", $"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}");
        Kv(id, "ASLR / DEP", $"{(aslr ? "ON" : "OFF")} / {(dep ? "ON" : "OFF")}",
            aslr && dep ? Tone.Safe : Tone.Warn);
        Kv(id, "Authenticode", signed
            ? $"signed | valid={validSig} | trusted={trustedSig}"
            : "not signed", signed && !validSig ? Tone.Danger : Tone.Normal);

        // ---- HEADERS ----
        var hdr = root.Group("HEADERS / 头部明细");
        var dosNode = hdr.Group("DOS Header", Tone.Normal, false);
        Kv(dosNode, "e_magic", dos is null ? "?" : $"0x{dos.E_magic:X4}");
        Kv(dosNode, "e_lfanew", dos is null ? "?" : $"0x{dos.E_lfanew:X8}");
        var ntNode = hdr.Group("NT Headers", Tone.Normal, false);
        Kv(ntNode, "Signature", $"0x{nt.Signature:X8}");
        Kv(ntNode, "Machine", $"0x{machine:X4}");
        Kv(ntNode, "NumberOfSections", fh.NumberOfSections.ToString());
        Kv(ntNode, "TimeDateStamp", fh.TimeDateStamp.ToString());
        Kv(ntNode, "SizeOfOptionalHeader", $"0x{fh.SizeOfOptionalHeader:X4}");
        Kv(ntNode, "Characteristics", string.Join(", ", fh.CharacteristicsResolved ?? new List<string>()));
        var optNode = hdr.Group("Optional Header", Tone.Normal, false);
        Kv(optNode, "Magic", oh.Magic.ToString());
        Kv(optNode, "AddressOfEntryPoint", $"0x{oh.AddressOfEntryPoint:X8}");
        Kv(optNode, "BaseOfCode / Data", $"0x{oh.BaseOfCode:X8} / 0x{oh.BaseOfData:X8}");
        Kv(optNode, "ImageBase", $"0x{oh.ImageBase:X}");
        Kv(optNode, "Section/FileAlign", $"0x{oh.SectionAlignment:X} / 0x{oh.FileAlignment:X}");
        Kv(optNode, "SizeOfImage", $"0x{oh.SizeOfImage:X8}");
        Kv(optNode, "SizeOfHeaders", $"0x{oh.SizeOfHeaders:X8}");
        Kv(optNode, "Subsystem", report.Subsystem);
        Kv(optNode, "DllCharacteristics", $"0x{dllChars:X4}  [ASLR={aslr}, DEP={dep}, HIGH_ENTROPY_VA={highEntropyVa}, GUARD_CF={guardCf}]");
        Kv(optNode, "NumberOfRvaAndSizes", oh.NumberOfRvaAndSizes.ToString());

        // ---- DATA DIRECTORIES ----
        var dirNode = root.Group("DATA DIRECTORIES / 数据目录");
        for (int i = 0; i < directories.Length; i++)
        {
            string name = i < DirectoryNames.Length ? DirectoryNames[i] : $"INDEX_{i}";
            var d = directories[i];
            bool present = d.VirtualAddress != 0 && d.Size != 0;
            dirNode.Add($"{i,2}  {name,-16} RVA 0x{d.VirtualAddress:X8}  SIZE 0x{d.Size:X8}",
                present ? Tone.Normal : Tone.Muted);
        }
        if (directories.Length == 0) dirNode.Add("(none)", Tone.Muted);

        // ---- SECTIONS ----
        var secNode = root.Group("SECTIONS / 节区");
        var sectionInfos = new List<SectionInfo>();
        foreach (var s in sections)
        {
            string name = (s.Name ?? "?").TrimEnd('\0', ' ');
            uint flags = Convert.ToUInt32(s.Characteristics);
            bool exec = (flags & 0x20000000) != 0;
            bool write = (flags & 0x80000000) != 0;
            bool read = (flags & 0x40000000) != 0;
            double entropy = Entropy(bytes, s.PointerToRawData, s.SizeOfRawData);
            bool marker = PackerMarkers.Any(m => name.StartsWith(m, StringComparison.OrdinalIgnoreCase));
            string chars = string.Join(", ", s.CharacteristicsResolved ?? new List<string>());

            sectionInfos.Add(new SectionInfo
            {
                Name = name,
                VirtualAddress = s.VirtualAddress,
                VirtualSize = s.VirtualSize,
                RawSize = s.SizeOfRawData,
                RawPointer = s.PointerToRawData,
                Entropy = Math.Round(entropy, 3),
                Executable = exec,
                Writable = write,
                Readable = read,
                PackerMarker = marker,
                Characteristics = chars
            });

            Tone tone = marker || (exec && write) ? Tone.Danger
                : entropy >= 7.0 ? Tone.Warn : Tone.Normal;
            var sn = secNode.Group(
                $"{name,-10} VA 0x{s.VirtualAddress:X8}  VS 0x{s.VirtualSize:X8}  RAW 0x{s.SizeOfRawData:X8}  H={entropy:F3}",
                tone, false);
            sn.Add($"Flags        : 0x{flags:X8}  [R:{(read ? "Y" : "N")} W:{(write ? "Y" : "N")} X:{(exec ? "Y" : "N")}]");
            sn.Add($"Raw Pointer  : 0x{s.PointerToRawData:X8}");
            sn.Add($"Entropy      : {entropy:F3} / 8.000", entropy >= 7.0 ? Tone.Warn : Tone.Normal);
            sn.Add($"Attributes   : {chars}", Tone.Muted);
            if (marker) sn.Add($"PACKER MARKER: {name}", Tone.Danger, true);
        }
        if (sectionInfos.Count == 0) secNode.Add("(no sections)", Tone.Muted);
        report.Sections = sectionInfos;

        // ---- IMPORTS ----
        var impNode = root.Group("IMPORTS / 导入表");
        var apiNames = new HashSet<string>(imports.Select(f => f.Name ?? ""), StringComparer.OrdinalIgnoreCase);
        FillImports(impNode, imports, descriptors.Length);
        var sensitive = imports.Where(f => SensitiveApis.ContainsKey(f.Name ?? "")).ToList();
        if (sensitive.Count > 0)
        {
            int maxWeight = sensitive.Max(f => SensitiveApis[f.Name!].Weight);
            findings.Add(new Finding
            {
                Severity = maxWeight >= 10 ? "CRITICAL" : "HIGH",
                Title = $"检出 {sensitive.Count} 个敏感 API",
                Detail = string.Join(", ", sensitive.Select(f => f.Name).Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
                Weight = Math.Min(30, 6 + sensitive.Count * 2 + maxWeight / 2)
            });
        }
        if (InjectionChain.All(apiNames.Contains))
            findings.Add(new Finding
            {
                Severity = "CRITICAL",
                Title = "经典远程线程注入链",
                Detail = "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread 同时出现",
                Weight = 25
            });

        // ---- DELAY IMPORTS ----
        var delayNode = root.Group("DELAY IMPORTS / 延迟导入");
        FillImports(delayNode, delayImports, delayDescriptors.Length);

        // ---- EXPORTS ----
        var expNode = root.Group("EXPORTS / 导出表");
        if (exportDir is not null)
        {
            Kv(expNode, "TimeDateStamp", exportDir.TimeDateStamp.ToString());
            Kv(expNode, "Base", exportDir.Base.ToString());
            Kv(expNode, "NumberOfFunctions", exportDir.NumberOfFunctions.ToString());
            Kv(expNode, "NumberOfNames", exportDir.NumberOfNames.ToString());
        }
        foreach (var e in exports.Take(500))
            expNode.Add($"{e.Ordinal,5}  0x{e.Address:X8}  {(e.HasName ? e.Name : "<ordinal>")}" +
                        (e.HasForward ? $"  -> {e.ForwardName}" : ""),
                e.HasForward ? Tone.Accent : Tone.Normal);
        if (exports.Length == 0) expNode.Add("(no exports)", Tone.Muted);
        else if (exports.Length > 500) expNode.Add($"... 另有 {exports.Length - 500} 项未展开", Tone.Muted);

        // ---- RESOURCES ----
        var resNode = root.Group("RESOURCES / 资源");
        if (resourceDir?.DirectoryEntries is { } entries)
        {
            Kv(resNode, "Top-level entries", entries.Count.ToString());
            foreach (var e in entries.Take(30))
            {
                if (e is null) continue;
                resNode.Add($"{e.NameResolved ?? e.ID.ToString(),-24} ID 0x{e.ID:X4}  {(e.DataIsDirectory ? "DIR" : "DATA")}");
            }
        }
        if (resources is not null)
        {
            Kv(resNode, "Icons", Safe(() => resources.Icons?.Length ?? 0, 0).ToString());
            Kv(resNode, "Icon groups", Safe(() => resources.GroupIconDirectories?.Length ?? 0, 0).ToString());
            var vsi = SafeOrNull<PeNet.Header.Resource.VsVersionInfo>(() => resources.VsVersionInfo);
            var tables = Arr(() => vsi?.StringFileInfo?.StringTable);
            foreach (var t in tables)
            {
                var v = resNode.Group($"VersionInfo [{t.SzKey}]", Tone.Normal, false);
                foreach (var (k, val) in new[]
                         {
                             ("CompanyName", t.CompanyName), ("ProductName", t.ProductName),
                             ("FileDescription", t.FileDescription), ("FileVersion", t.FileVersion),
                             ("ProductVersion", t.ProductVersion), ("OriginalFilename", t.OriginalFilename),
                             ("LegalCopyright", t.LegalCopyright), ("InternalName", t.InternalName)
                         })
                    if (!string.IsNullOrWhiteSpace(val)) Kv(v, k, val!);
            }
        }
        if (resNode.Children.Count == 0) resNode.Add("(no resources)", Tone.Muted);

        // ---- RELOCATIONS ----
        var relNode = root.Group("RELOCATIONS / 重定位");
        Kv(relNode, "Blocks", relocs.Length.ToString());
        Kv(relNode, "Entries", relocs.Sum(b => b.TypeOffsets?.Length ?? 0).ToString());
        foreach (var b in relocs.Take(25))
            relNode.Add($"0x{b.VirtualAddress:X8}  size {b.SizeOfBlock,-6}  entries {b.TypeOffsets?.Length ?? 0}");
        if (relocs.Length > 25) relNode.Add($"... 另有 {relocs.Length - 25} 个块未展开", Tone.Muted);

        // ---- DEBUG ----
        var dbgNode = root.Group("DEBUG / 调试目录");
        string? pdbPath = null;
        foreach (var d in debug)
        {
            var dn = dbgNode.Group($"{d.DebugType}  size {d.SizeOfData}", Tone.Normal, false);
            dn.Add($"TimeDateStamp : {d.TimeDateStamp}");
            dn.Add($"RawData       : ptr 0x{d.PointerToRawData:X8}  addr 0x{d.AddressOfRawData:X8}");
            var cv = SafeOrNull<PeNet.Header.Resource.CvInfoPdb70>(() => d.CvInfoPdb70);
            if (cv is not null && !string.IsNullOrWhiteSpace(cv.PdbFileName))
            {
                dn.Add($"PDB           : {cv.PdbFileName}", Tone.Accent);
                pdbPath ??= cv.PdbFileName;
            }
        }
        if (debug.Length == 0) dbgNode.Add("(no debug directory)", Tone.Muted);
        if (!string.IsNullOrEmpty(pdbPath))
            findings.Add(new Finding { Severity = "INFO", Title = "调试符号路径", Detail = pdbPath!, Weight = 0 });

        // ---- TLS ----
        var tlsNode = root.Group("TLS / 线程局部存储");
        int tlsCallbacks = 0;
        if (tls is not null)
        {
            Kv(tlsNode, "RawData Start", $"0x{tls.StartAddressOfRawData:X}");
            Kv(tlsNode, "RawData End", $"0x{tls.EndAddressOfRawData:X}");
            Kv(tlsNode, "AddressOfIndex", $"0x{tls.AddressOfIndex:X}");
            Kv(tlsNode, "AddressOfCallBacks", $"0x{tls.AddressOfCallBacks:X}");
            Kv(tlsNode, "SizeOfZeroFill", $"0x{tls.SizeOfZeroFill:X8}");
            tlsCallbacks = Safe(() => tls.TlsCallbacks?.Length ?? 0, 0);
            Kv(tlsNode, "Callbacks", tlsCallbacks.ToString(), tlsCallbacks > 0 ? Tone.Warn : Tone.Normal);
        }
        else tlsNode.Add("(no TLS directory)", Tone.Muted);
        if (tlsCallbacks > 0)
            findings.Add(new Finding
            {
                Severity = "LOW", Title = "存在 TLS 回调",
                Detail = $"{tlsCallbacks} 个回调，常见于反调试 / 早于入口点执行", Weight = 5
            });

        // ---- LOAD CONFIG ----
        var lcNode = root.Group("LOAD CONFIG / 加载配置");
        if (loadConfig is not null)
        {
            Kv(lcNode, "Size", $"0x{loadConfig.Size:X8}");
            Kv(lcNode, "TimeDateStamp", loadConfig.TimeDateStamp.ToString());
            Kv(lcNode, "SecurityCookie", $"0x{loadConfig.SecurityCookie:X}");
            Kv(lcNode, "SEHandlerCount", loadConfig.SEHandlerCount.ToString());
            Kv(lcNode, "GuardCFFunctionCount", loadConfig.GuardCFFunctionCount.ToString());
            Kv(lcNode, "GuardFlags", $"0x{loadConfig.GuardFlags:X8}");
        }
        else lcNode.Add("(no load config)", Tone.Muted);

        // ---- CLR ----
        var clrNode = root.Group("CLR / .NET 元数据");
        if (clr is not null)
        {
            Kv(clrNode, "Runtime", $"{clr.MajorRuntimeVersion}.{clr.MinorRuntimeVersion}");
            Kv(clrNode, "Flags", string.Join(", ", clr.FlagsResolved ?? new List<string>()));
            Kv(clrNode, "EntryPointToken", $"0x{clr.EntryPointToken:X8}");
            uint mdRva = Safe(() => clr.MetaData?.VirtualAddress ?? 0u, 0u);
            uint mdSize = Safe(() => clr.MetaData?.Size ?? 0u, 0u);
            Kv(clrNode, "MetaData RVA/Size", $"0x{mdRva:X8} / 0x{mdSize:X8}");
        }
        if (meta is not null)
        {
            Kv(clrNode, "MetaData Version", meta.Version ?? "?");
            Kv(clrNode, "Streams", meta.Streams.ToString());
            foreach (var s in meta.MetaDataStreamsHdrs ?? Array.Empty<PeNet.Header.Net.MetaDataStreamHdr>())
                clrNode.Add($"{s.StreamName,-12} offset 0x{s.RelOffset:X8}  size 0x{s.Size:X8}");
        }
        Kv(clrNode, "Module Version IDs", Safe(() => pe.ClrModuleVersionIds?.Count ?? 0, 0).ToString());
        if (clr is null && meta is null) clrNode.Add("(native image, no CLR header)", Tone.Muted);

        // ---- EXCEPTION / UNWIND ----
        var excNode = root.Group("EXCEPTION / 异常表 (x64)");
        Kv(excNode, "Runtime functions", runtimeFuncs.Length.ToString());
        foreach (var f in runtimeFuncs.Take(20))
            excNode.Add($"0x{f.FunctionStart:X8} - 0x{f.FunctionEnd:X8}  unwind 0x{f.UnwindInfo:X8}");
        if (runtimeFuncs.Length == 0) excNode.Add("(none)", Tone.Muted);

        // ---- AUTHENTICODE ----
        var sigNode = root.Group("AUTHENTICODE / 数字签名");
        Kv(sigNode, "Signed", signed.ToString());
        Kv(sigNode, "Valid", validSig.ToString(), signed && !validSig ? Tone.Danger : Tone.Normal);
        Kv(sigNode, "Trusted", trustedSig.ToString());
        if (winCert is not null)
        {
            Kv(sigNode, "Certificate length", winCert.DwLength.ToString());
            Kv(sigNode, "Revision", $"0x{winCert.WRevision:X4}");
            Kv(sigNode, "Type", winCert.WCertificateType.ToString());
        }
        if (auth is not null)
        {
            Kv(sigNode, "Signer serial", auth.SignerSerialNumber ?? "?");
            Kv(sigNode, "Timestamp", auth.SigningTimestamp?.ToString("u") ?? "?");
            var cert2 = SafeOrNull<System.Security.Cryptography.X509Certificates.X509Certificate2>(
                () => auth.SigningCertificate);
            if (cert2 is not null)
            {
                Kv(sigNode, "Subject", cert2.Subject);
                Kv(sigNode, "Issuer", cert2.Issuer);
                Kv(sigNode, "NotAfter", cert2.NotAfter.ToString("u"));
                Kv(sigNode, "Thumbprint", cert2.Thumbprint ?? "?");
            }
        }
        if (signed && !validSig)
            findings.Add(new Finding
            {
                Severity = "HIGH", Title = "Authenticode 签名无效",
                Detail = "文件已签名但校验失败，可能被篡改", Weight = 15
            });

        // ---- HASHES ----
        var hashNode = root.Group("HASHES / 哈希");
        Kv(hashNode, "SHA256", report.Sha256);
        Kv(hashNode, "SHA1", report.Sha1);
        Kv(hashNode, "MD5", report.Md5);
        Kv(hashNode, "ImpHash", report.ImpHash ?? "n/a");
        Kv(hashNode, "TypeRefHash", report.TypeRefHash ?? "n/a");

        // ---- RISK RULES ----
        string[] packHits = sectionInfos.Where(s => s.PackerMarker).Select(s => s.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (packHits.Length > 0)
            findings.Add(new Finding
            {
                Severity = "CRITICAL", Title = "检测到加壳",
                Detail = string.Join(", ", packHits), Weight = 30
            });

        var highEntropy = sectionInfos.Where(s => s.RawSize > 0 && s.Entropy >= 7.0).ToArray();
        if (highEntropy.Length > 0)
            findings.Add(new Finding
            {
                Severity = "HIGH", Title = "高熵节区（疑似加密 / 压缩）",
                Detail = string.Join(", ", highEntropy.Select(s => $"{s.Name}={s.Entropy:F2}")), Weight = 15
            });

        var wx = sectionInfos.Where(s => s.Executable && s.Writable).ToArray();
        if (wx.Length > 0)
            findings.Add(new Finding
            {
                Severity = "HIGH", Title = "可写且可执行节区 (W+X)",
                Detail = string.Join(", ", wx.Select(s => s.Name)), Weight = 15
            });

        if (sectionInfos.Count > 0)
        {
            var epSection = sectionInfos.FirstOrDefault(s =>
                oh.AddressOfEntryPoint >= s.VirtualAddress &&
                oh.AddressOfEntryPoint < s.VirtualAddress + Math.Max(s.VirtualSize, 1));
            if (epSection is null)
                findings.Add(new Finding
                {
                    Severity = "HIGH", Title = "入口点不在任何节区",
                    Detail = $"EntryPoint 0x{oh.AddressOfEntryPoint:X8}", Weight = 15
                });
            else if (!epSection.Executable)
                findings.Add(new Finding
                {
                    Severity = "HIGH", Title = "入口点位于非可执行节区",
                    Detail = $"EntryPoint 0x{oh.AddressOfEntryPoint:X8} -> {epSection.Name}", Weight = 15
                });
        }

        if (!isDotNet && imports.Length < 5 && sectionInfos.Count > 0)
            findings.Add(new Finding
            {
                Severity = "MEDIUM", Title = "导入表异常稀疏",
                Detail = $"仅 {imports.Length} 个导入函数，常见于加壳 / 手动解析 IAT", Weight = 10
            });
        if (!aslr)
            findings.Add(new Finding
            {
                Severity = "MEDIUM", Title = "未启用 ASLR (DynamicBase)",
                Detail = "映像基址固定，利于利用开发", Weight = 8
            });
        if (!dep)
            findings.Add(new Finding
            {
                Severity = "MEDIUM", Title = "未启用 DEP (NX_COMPAT)",
                Detail = "数据页可执行保护缺失", Weight = 8
            });

        report.RiskScore = Math.Min(100, findings.Sum(f => f.Weight));
        report.RiskLevel = report.RiskScore >= 70 ? "CRITICAL"
            : report.RiskScore >= 45 ? "HIGH"
            : report.RiskScore >= 20 ? "MEDIUM"
            : report.RiskScore > 0 ? "LOW" : "CLEAN";
        report.Findings = findings.OrderByDescending(f => f.Weight).ToList();

        var riskNode = new ReportNode
        {
            Text = "RISK ASSESSMENT / 风险评估",
            Tone = report.RiskScore >= 45 ? Tone.Danger : report.RiskScore >= 20 ? Tone.Warn : Tone.Safe,
            Bold = true
        };
        riskNode.Add($"Risk Score : {report.RiskScore}/100   [{report.RiskLevel}]",
            riskNode.Tone, true);
        foreach (var f in report.Findings)
        {
            var tone = f.Severity switch
            {
                "CRITICAL" or "HIGH" => Tone.Danger,
                "MEDIUM" => Tone.Warn,
                "LOW" => Tone.Muted,
                _ => Tone.Accent
            };
            riskNode.Add($"[{f.Severity,-8}] {f.Title}", tone, true);
            riskNode.Add($"           {f.Detail}", Tone.Muted);
        }
        if (report.Findings.Count == 0) riskNode.Add("未发现明显风险特征", Tone.Safe);

        report.Nodes = new List<ReportNode> { riskNode };
        report.Nodes.AddRange(root.Children);
        return report;
    }

    private static void FillImports(ReportNode node, ImportFunction[] funcs, int descriptorCount)
    {
        node.Add($"Descriptors : {descriptorCount}    Functions : {funcs.Length}", Tone.Muted);
        if (funcs.Length == 0)
        {
            node.Add("(none)", Tone.Muted);
            return;
        }
        foreach (var g in funcs
                     .GroupBy(f => string.IsNullOrWhiteSpace(f.DLL) ? "<unknown>" : f.DLL!,
                         StringComparer.OrdinalIgnoreCase)
                     .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            var apis = g.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();
            bool hasSensitive = apis.Any(f => SensitiveApis.ContainsKey(f.Name ?? ""));
            var dllNode = node.Group(
                hasSensitive ? $"{g.Key}   [{apis.Count}]   [!]" : $"{g.Key}   [{apis.Count}]",
                hasSensitive ? Tone.Danger : Tone.Normal, false);
            foreach (var f in apis)
            {
                string api = string.IsNullOrWhiteSpace(f.Name) ? "<ordinal>" : f.Name!;
                bool sensitive = SensitiveApis.TryGetValue(api, out var info);
                dllNode.Add(sensitive
                        ? $"{api}   <- SENSITIVE [{info.Level}]"
                        : api,
                    sensitive ? Tone.Danger : Tone.Normal);
            }
        }
    }

    private static void Kv(ReportNode node, string key, object? value, Tone tone = Tone.Normal) =>
        node.Add($"{key,-22}: {value}", tone);

    private static double Entropy(byte[] data, uint offset, uint count)
    {
        if (count == 0 || offset >= data.Length) return 0;
        long end = Math.Min((long)offset + count, data.Length);
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

    private static T[] Arr<T>(Func<T[]?> read)
    {
        try { return read() ?? Array.Empty<T>(); } catch { return Array.Empty<T>(); }
    }

    private static T Safe<T>(Func<T> read, T fallback)
    {
        try { return read(); } catch { return fallback; }
    }

    private static T? SafeOrNull<T>(Func<T?> read) where T : class
    {
        try { return read(); } catch { return null; }
    }
}

using System.Runtime.InteropServices;
using System.Text;

namespace Breccia.WPF.Dyn;

/// <summary>Minimal Win32 debug-API surface. Layouts mirror winnt.h for x64 hosts.</summary>
internal static class Native
{
    // ---- debug events ----
    public const uint EXCEPTION_DEBUG_EVENT = 1;
    public const uint CREATE_THREAD_DEBUG_EVENT = 2;
    public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    public const uint EXIT_THREAD_DEBUG_EVENT = 4;
    public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    public const uint LOAD_DLL_DEBUG_EVENT = 6;
    public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    public const uint RIP_EVENT = 9;

    public const uint DBG_CONTINUE = 0x00010002;
    public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    public const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
    public const uint EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D;
    public const uint EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
    public const uint EXCEPTION_PRIV_INSTRUCTION = 0xC0000096;

    // ---- process / thread ----
    public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    public const uint DEBUG_PROCESS = 0x00000001;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint CREATE_SUSPENDED = 0x00000004;

    public const uint THREAD_GET_CONTEXT = 0x0008;
    public const uint THREAD_SET_CONTEXT = 0x0010;
    public const uint THREAD_SUSPEND_RESUME = 0x0002;
    public const uint THREAD_QUERY_INFORMATION = 0x0040;
    public const uint THREAD_ALL_ACCESS = 0x1FFFFF;
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;

    // ---- context flags ----
    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT_i386 = 0x00010000;
    public const uint CONTEXT_CONTROL_64 = CONTEXT_AMD64 | 0x1;
    public const uint CONTEXT_INTEGER_64 = CONTEXT_AMD64 | 0x2;
    public const uint CONTEXT_FULL_64 = CONTEXT_CONTROL_64 | CONTEXT_INTEGER_64 | (CONTEXT_AMD64 | 0x8);
    public const uint CONTEXT_CONTROL_32 = CONTEXT_i386 | 0x1;
    public const uint CONTEXT_INTEGER_32 = CONTEXT_i386 | 0x2;
    public const uint CONTEXT_SEGMENTS_32 = CONTEXT_i386 | 0x4;
    public const uint CONTEXT_FULL_32 = CONTEXT_CONTROL_32 | CONTEXT_INTEGER_32 | CONTEXT_SEGMENTS_32;

    public const uint EFLAGS_TF = 0x100;
    public const uint EFLAGS_IF = 0x200;

    // ---- memory ----
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;

    public const uint LIST_MODULES_ALL = 0x03;

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    /// <summary>Union payload of DEBUG_EVENT; 160 bytes, fields are offset views.</summary>
    [StructLayout(LayoutKind.Explicit, Size = 160)]
    public struct DebugEventUnion
    {
        // EXCEPTION_DEBUG_INFO
        [FieldOffset(0)] public uint ExceptionCode;
        [FieldOffset(4)] public uint ExceptionFlags;
        [FieldOffset(8)] public IntPtr ExceptionRecord;
        [FieldOffset(16)] public IntPtr ExceptionAddress;
        [FieldOffset(24)] public uint NumberParameters;
        [FieldOffset(32)] public IntPtr ExceptionInformation0;
        [FieldOffset(40)] public IntPtr ExceptionInformation1;
        [FieldOffset(152)] public uint FirstChance;

        // CREATE_PROCESS_DEBUG_INFO
        [FieldOffset(0)] public IntPtr CpFile;
        [FieldOffset(8)] public IntPtr CpProcess;
        [FieldOffset(16)] public IntPtr CpThread;
        [FieldOffset(24)] public IntPtr CpBaseOfImage;

        // CREATE_THREAD_DEBUG_INFO
        [FieldOffset(0)] public IntPtr CtThread;
        [FieldOffset(16)] public IntPtr CtStartAddress;

        // EXIT_THREAD / EXIT_PROCESS
        [FieldOffset(0)] public uint ExitCode;

        // LOAD_DLL_DEBUG_INFO
        [FieldOffset(0)] public IntPtr LdFile;
        [FieldOffset(8)] public IntPtr LdBaseOfDll;

        // OUTPUT_DEBUG_STRING_INFO
        [FieldOffset(0)] public ushort DbgStringUnicode;
        [FieldOffset(8)] public ushort DbgStringLength;
        [FieldOffset(16)] public IntPtr DbgStringAddress;

        // RIP_INFO
        [FieldOffset(0)] public uint RipReason;
        [FieldOffset(4)] public uint RipError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEBUG_EVENT
    {
        public uint dwDebugEventCode;
        public uint dwProcessId;
        public uint dwThreadId;
        public DebugEventUnion u;
    }

    [StructLayout(LayoutKind.Explicit, Size = 1232)]
    public struct Ctx64
    {
        [FieldOffset(0x30)] public uint ContextFlags;
        [FieldOffset(0x44)] public uint EFlags;
        [FieldOffset(0x78)] public ulong Rax;
        [FieldOffset(0x80)] public ulong Rcx;
        [FieldOffset(0x88)] public ulong Rdx;
        [FieldOffset(0x90)] public ulong Rbx;
        [FieldOffset(0x98)] public ulong Rsp;
        [FieldOffset(0xA0)] public ulong Rbp;
        [FieldOffset(0xA8)] public ulong Rsi;
        [FieldOffset(0xB0)] public ulong Rdi;
        [FieldOffset(0xB8)] public ulong R8;
        [FieldOffset(0xC0)] public ulong R9;
        [FieldOffset(0xC8)] public ulong R10;
        [FieldOffset(0xD0)] public ulong R11;
        [FieldOffset(0xD8)] public ulong R12;
        [FieldOffset(0xE0)] public ulong R13;
        [FieldOffset(0xE8)] public ulong R14;
        [FieldOffset(0xF0)] public ulong R15;
        [FieldOffset(0xF8)] public ulong Rip;
    }

    [StructLayout(LayoutKind.Explicit, Size = 716)]
    public struct Ctx32
    {
        [FieldOffset(0x00)] public uint ContextFlags;
        [FieldOffset(0x8C)] public uint SegGs;
        [FieldOffset(0x90)] public uint SegFs;
        [FieldOffset(0x94)] public uint SegEs;
        [FieldOffset(0x98)] public uint SegDs;
        [FieldOffset(0x9C)] public uint Edi;
        [FieldOffset(0xA0)] public uint Esi;
        [FieldOffset(0xA4)] public uint Ebx;
        [FieldOffset(0xA8)] public uint Edx;
        [FieldOffset(0xAC)] public uint Ecx;
        [FieldOffset(0xB0)] public uint Eax;
        [FieldOffset(0xB4)] public uint Ebp;
        [FieldOffset(0xB8)] public uint Eip;
        [FieldOffset(0xBC)] public uint SegCs;
        [FieldOffset(0xC0)] public uint EFlags;
        [FieldOffset(0xC4)] public uint Esp;
        [FieldOffset(0xC8)] public uint SegSs;
    }

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    public struct MEMORY_BASIC_INFORMATION
    {
        [FieldOffset(0)] public ulong BaseAddress;
        [FieldOffset(8)] public ulong AllocationBase;
        [FieldOffset(16)] public uint AllocationProtect;
        [FieldOffset(24)] public ulong RegionSize;
        [FieldOffset(32)] public uint State;
        [FieldOffset(36)] public uint Protect;
        [FieldOffset(40)] public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr lpEntryPoint;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessW(
        string? lpApplicationName, string? lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcess(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcessStop(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugSetProcessKillOnExit(bool killOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugBreakProcess(IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WaitForDebugEventEx(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, int dwThreadId);

    // CONTEXT buffers are passed as pointers: the x64 CONTEXT requires 16-byte alignment,
    // which a marshalled `ref struct` local does not guarantee.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern ulong VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, ulong dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(
        IntPtr hProcess, IntPtr lpAddress, ulong dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, ulong dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process2(IntPtr hProcess, out ushort processMachine, out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags,
        StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[] lphModule,
        int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule,
        StringBuilder lpFilename, int nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, int cbSize);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemTimeAsFileTime(out long ft);

    public static string LastError(string what) =>
        $"{what} failed (win32 {Marshal.GetLastWin32Error()})";
}

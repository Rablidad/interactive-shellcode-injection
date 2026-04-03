using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ShellcodeInjectionConhost
{
    internal class Win32
    {
        [Flags]
        internal enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        internal enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct CONTEXT
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,      // null = let OS choose
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(
          uint dwDesiredAccess,
          bool bInheritHandle,
          uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("ntdll.dll")]
        internal static extern int NtQueryInformationThread(
         IntPtr hThread,
         int threadInformationClass,
         out uint threadInformation,
         uint threadInformationLength,
         IntPtr returnLength);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool StackWalk64(
            uint machineType, 
            IntPtr hProcess, 
            IntPtr hThread, 
            ref STACKFRAME64 stackFrame, 
            ref CONTEXT context,
            IntPtr readMemory, 
            IntPtr functionTableAccess, 
            IntPtr getModuleBase, 
            IntPtr translate);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymInitialize(IntPtr hProcess, string userSearchPath, bool invadeProcess);

        [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool SymFromAddr(IntPtr hProcess, ulong address, out ulong displacement, ref SYMBOL_INFO symbol);

        [DllImport("dbghelp.dll")]
        internal static extern IntPtr SymFunctionTableAccess64(IntPtr hProcess, ulong addrBase);

        [DllImport("dbghelp.dll")]
        internal static extern ulong SymGetModuleBase64(IntPtr hProcess, ulong address);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();
        
        [DllImport("kernel32.dll")]
        internal static extern uint SuspendThread(IntPtr hThread);
        
        [DllImport("kernel32.dll")] 
        internal static extern uint ResumeThread(IntPtr hThread);

        internal const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        internal const uint SYMOPT_UNDNAME = 0x2;
        internal const uint SYMOPT_DEFERRED_LOADS = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        internal struct ADDRESS64 { public ulong Offset; public ushort Segment; public uint Mode; }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STACKFRAME64
        {
            public ADDRESS64 AddrPC, AddrReturn, AddrFrame, AddrStack, AddrBStore;
            public IntPtr FuncTableEntry;
            public ulong Params0, Params1, Params2, Params3;
            public bool Far, Virtual;
            public ulong Reserved0, Reserved1, Reserved2;
            public ADDRESS64 AddrTeb;
            public uint KdHelp0, KdHelp1, KdHelp2, KdHelp3;
            public ulong KdHelp4, KdHelp5, KdHelp6, KdHelp7;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SYMBOL_INFO
        {
            public uint SizeOfStruct;
            public uint TypeIndex;
            public ulong Reserved0, Reserved1;
            public uint Index, Size;
            public ulong ModBase, Flags, Value, Address;
            public uint Register, Scope, Tag, NameLen, MaxNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Name;
        }

        // Allocation types
        internal const uint MEM_COMMIT = 0x00001000;
        internal const uint MEM_RESERVE = 0x00002000;
        internal const uint MEM_RELEASE = 0x00008000;

        // Page protection
        internal const uint PAGE_NOACCESS = 0x01;
        internal const uint PAGE_READONLY = 0x02;
        internal const uint PAGE_READWRITE = 0x04;
        internal const uint PAGE_EXECUTE = 0x10;
        internal const uint PAGE_EXECUTE_READ = 0x20;
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;

        //public const uint THREAD_GET_CONTEXT = 0x0008;
        //public const uint THREAD_SET_CONTEXT = 0x0010;
        //public const uint THREAD_SUSPEND_RESUME = 0x0002;
        //public const uint THREAD_ALL_ACCESS = 0x001F03FF;

        // Access rights
        internal const uint THREAD_TERMINATE = 0x0001;
        internal const uint THREAD_SUSPEND_RESUME = 0x0002;
        internal const uint THREAD_GET_CONTEXT = 0x0008;
        internal const uint THREAD_SET_CONTEXT = 0x0010;
        internal const uint THREAD_SET_INFORMATION = 0x0020;
        internal const uint THREAD_QUERY_INFORMATION = 0x0040;
        internal const uint THREAD_SET_THREAD_TOKEN = 0x0080;
        internal const uint THREAD_IMPERSONATE = 0x0100;
        internal const uint THREAD_DIRECT_IMPERSONATION = 0x0200;
        internal const uint THREAD_SET_LIMITED_INFORMATION = 0x0400;
        internal const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        internal const uint THREAD_ALL_ACCESS = 0x001F03FF;
        //const uint THREAD_QUERY_INFORMATION = 0x0040;
    }
}

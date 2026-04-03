using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ShellcodeInjectionConhost.Program;
using static ShellcodeInjectionConhost.Win32;

namespace ShellcodeInjectionConhost
{
    internal class Threading
    {
        delegate IntPtr FunctionTableAccessProc(IntPtr hProcess, ulong addrBase);
        delegate ulong GetModuleBaseProc(IntPtr hProcess, ulong address);

        internal static bool IsThreadInReadFile(IntPtr hProcess, IntPtr hThread)
        {
            SymInitialize(hProcess, null, true);

            SuspendThread(hThread);
            try
            {
                var ctx = new CONTEXT { ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL };
                GetThreadContext(hThread, ref ctx);

                var frame = new STACKFRAME64();
                frame.AddrPC.Offset = ctx.Rip; frame.AddrPC.Mode = 3;
                frame.AddrFrame.Offset = ctx.Rbp; frame.AddrFrame.Mode = 3;
                frame.AddrStack.Offset = ctx.Rsp; frame.AddrStack.Mode = 3;

                // Named delegates — Marshal.GetFunctionPointerForDelegate requires concrete types
                FunctionTableAccessProc ftAccess = (hp, addr) => SymFunctionTableAccess64(hp, addr);
                GetModuleBaseProc getModBase = (hp, addr) => SymGetModuleBase64(hp, addr);

                IntPtr pFtAccess = Marshal.GetFunctionPointerForDelegate(ftAccess);
                IntPtr pGetModBase = Marshal.GetFunctionPointerForDelegate(getModBase);

                for (int i = 0; i < 20; i++)
                {
                    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
                            ref frame, ref ctx,
                            IntPtr.Zero, pFtAccess, pGetModBase, IntPtr.Zero))
                        break;

                    var sym = new SYMBOL_INFO
                    {
                        SizeOfStruct = (uint)Marshal.SizeOf<SYMBOL_INFO>(),
                        MaxNameLen = 256
                    };

                    SymFromAddr(hProcess, frame.AddrPC.Offset, out _, ref sym);

                    if (sym.Name != null &&
                       (sym.Name.Contains("NtReadFile") ||
                        sym.Name.Contains("ReadFile") ||
                        sym.Name.Contains("ReadConsole")))
                        return true;
                }

                return false;
            }
            finally
            {
                ResumeThread(hThread);
            }
        }
    }
}

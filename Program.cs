// See https://aka.ms/new-console-template for more information

using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

[MemoryDiagnoser]
public unsafe class Program
{
    const ulong MB_DIVISOR = 1024 * 1024;

    const long LONG_MB_DIVISOR = (long)MB_DIVISOR;

    const uint buffersize = 1024 * 1024;

    void* bufferPtr;


    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SYSTEM_PROCESS_INFORMATION
    {
        internal uint NextEntryOffset;
        internal uint NumberOfThreads;
        private fixed byte Reserved1[48];
        internal UNICODE_STRING ImageName;
        internal int BasePriority;
        internal IntPtr UniqueProcessId;
        private readonly UIntPtr Reserved2;
        internal uint HandleCount;
        internal uint SessionId;
        private readonly UIntPtr Reserved3;
        internal UIntPtr PeakVirtualSize;  // SIZE_T
        internal UIntPtr VirtualSize;
        private readonly uint Reserved4;
        internal UIntPtr PeakWorkingSetSize;  // SIZE_T
        internal UIntPtr WorkingSetSize;  // SIZE_T
        private readonly UIntPtr Reserved5;
        internal UIntPtr QuotaPagedPoolUsage;  // SIZE_T
        private readonly UIntPtr Reserved6;
        internal UIntPtr QuotaNonPagedPoolUsage;  // SIZE_T
        internal UIntPtr PagefileUsage;  // SIZE_T
        internal UIntPtr PeakPagefileUsage;  // SIZE_T
        internal UIntPtr PrivatePageCount;  // SIZE_T
        private fixed long Reserved7[6];

    }

    [DllImport("psapi.dll", SetLastError = true)] public static extern int GetProcessMemoryInfo(IntPtr handle, ref PROCESS_MEMORY_COUNTERS pmc, int cb);
    [StructLayout(LayoutKind.Sequential)] 
    public struct PROCESS_MEMORY_COUNTERS 
    {
        public uint cb;
        public uint PageFaultCount;
        public ulong PeakWorkingSetSize;
        public ulong WorkingSetSize;
        public ulong QuotaPeakPagedPoolUsage;
        public ulong QuotaPagedPoolUsage;
        public ulong QuotaPeakNonPagedPoolUsage;
        public ulong QuotaNonPagedPoolUsage;
        public ulong PagefileUsage;
        public ulong PeakPagefileUsage;
        public ulong PrivateUsage; 
    }

    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa380518.aspx
    // https://msdn.microsoft.com/en-us/library/windows/hardware/ff564879.aspx
    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        /// <summary>
        /// Length in bytes, not including the null terminator, if any.
        /// </summary>
        internal ushort Length;

        /// <summary>
        /// Max size of the buffer in bytes
        /// </summary>
        internal ushort MaximumLength;
        internal IntPtr Buffer;
    }

    [DllImportAttribute("ntdll.dll", EntryPoint = "NtQuerySystemInformation", ExactSpelling = true)]
    internal static unsafe extern uint NtQuerySystemInformation(int SystemInformationClass, void* SystemInformation, uint SystemInformationLength, uint* ReturnLength);

    public const int SystemProcessInformation = 5;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint FormatMessage(
        uint dwFlags,
        IntPtr lpSource,
        uint dwMessageId,
        uint dwLanguageId,
        [Out] System.Text.StringBuilder lpBuffer,
        uint nSize,
        IntPtr Arguments);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();


    private const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    private const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

    private static string GetErrorMessage(int errorCode)
    {
        System.Text.StringBuilder messageBuffer = new System.Text.StringBuilder(512);
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, IntPtr.Zero, (uint)errorCode, 0, messageBuffer, (uint)messageBuffer.Capacity, IntPtr.Zero);
        return messageBuffer.ToString();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private class MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;

        public MEMORYSTATUSEX()
        {
            this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

    static unsafe void Main()
    {
        //var p = new Program();
        //p.GetProcessNtQuerySystemInformation();
        var summary = BenchmarkRunner.Run<Program>();
    }

    public Program()
    {
        bufferPtr = NativeMemory.Alloc(buffersize);
    }

    [Benchmark]
    public void GetProcessVirtualMemorySize64() 
    {
        using (Process p = Process.GetCurrentProcess())
        {
            Console.WriteLine($"VirtualSize {p.VirtualMemorySize64}");
        }
    }

    [Benchmark]
    public unsafe void GetProcessNtQuerySystemInformation() 
    {
        uint actualSize = 0;
        try
        {
            // First call to NtQuerySystemInformation to get the size of the buffer needed
            uint status = NtQuerySystemInformation(SystemProcessInformation, bufferPtr, buffersize, &actualSize);
            if (status != 0xc0000004 && status != 0) // STATUS_INFO_LENGTH_MISMATCH
            {
                uint lastError = GetLastError();
                throw new Exception("NtQuerySystemInformation failed with status: " + status + ", error code: " + lastError);
            }

            var buffer = Marshal.AllocHGlobal((int)actualSize);

            if (status == 0)
            {

                int processInformationOffset = 0;

                while (true)
                {
                    var data = new ReadOnlySpan<byte>(bufferPtr, (int)actualSize);
                    ref readonly SYSTEM_PROCESS_INFORMATION pi = ref MemoryMarshal.AsRef<SYSTEM_PROCESS_INFORMATION>(data.Slice(processInformationOffset));

                    //// Process ID shouldn't overflow. OS API GetCurrentProcessID returns DWORD.
                    var processId = pi.UniqueProcessId.ToInt64();
                    if (Environment.ProcessId == processId)
                    {
                        var longSize = (long)pi.VirtualSize;
                        Console.WriteLine($"VirtualSize {longSize}");
                    }

                    if (pi.NextEntryOffset == 0)
                    {
                        break;
                    }
                    processInformationOffset += (int)pi.NextEntryOffset;
                }

                //Console.WriteLine("Number of threads: " + spi.NumberOfThreads); 
            }
        }
        finally
        {
            //NativeMemory.Free(bufferPtr);
        }
    }

    [Benchmark]
    public void GetProcessVirtualSizeWMI() 
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Create a new management scope
            ManagementScope scope = new ManagementScope(@"\\.\root\cimv2");

            // Create a new object query
            ObjectQuery query = new ObjectQuery($"SELECT * FROM Win32_Process WHERE ProcessId = {Environment.ProcessId}");

            // Create a new management object searcher
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

            // Get the collection of management objects
            ManagementObjectCollection processes = searcher.Get();

            // Iterate through the collection and display process information
            foreach (ManagementObject process in processes)
            {
                Console.WriteLine($"Virtual Size: {process["VirtualSize"]}");
            }
        }
    }

}
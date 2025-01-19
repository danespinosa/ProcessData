// See https://aka.ms/new-console-template for more information

using System;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;
using static Program;

class Program
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_BASIC_INFORMATION
    {
        public uint Reserved;
        public uint TimerResolution;
        public uint PageSize;
        public uint NumberOfPhysicalPages;
        public uint LowestPhysicalPageNumber;
        public uint HighestPhysicalPageNumber;
        public uint AllocationGranularity;
        public uint MinimumUserModeAddress;
        public uint MaximumUserModeAddress;
        public uint ActiveProcessorsAffinityMask;
        public byte NumberOfProcessors;
    }

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

    [DllImport("KERNEL32.DLL")]
    private static extern int OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

    [DllImport("psapi.dll", SetLastError = true)] public static extern int GetProcessMemoryInfo(IntPtr handle, ref PROCESS_MEMORY_COUNTERS_EX pmc, int cb);
    [StructLayout(LayoutKind.Sequential)] 
    public struct PROCESS_MEMORY_COUNTERS_EX 
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
        const ulong MB_DIVISOR = 1024 * 1024;
        const long LONG_MB_DIVISOR = (long)MB_DIVISOR;

        for (int i = 0; i < 1000; i++)
        {
            using (var p = Process.GetCurrentProcess())
            {
                var gcTotalAvailableMemoryBytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
                Console.WriteLine($"process.VirtualMemorySize64: {p.VirtualMemorySize64 / LONG_MB_DIVISOR} MB");
                Console.WriteLine($"GC.GetGCMemoryInfo().TotalAvailableMemoryBytes: {gcTotalAvailableMemoryBytes / LONG_MB_DIVISOR} MB");

                MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
                if (GlobalMemoryStatusEx(memStatus))
                {
                    Console.WriteLine($"Memory Load: {memStatus.dwMemoryLoad}%");
                    Console.WriteLine($"Avail Virtual Memory: {memStatus.ullAvailVirtual / MB_DIVISOR} MB");
                    Console.WriteLine($"Total Virtual Memory: {memStatus.ullTotalVirtual / MB_DIVISOR} MB");
                    Console.WriteLine($"Total Page File: {memStatus.ullTotalPageFile / MB_DIVISOR} MB");
                    Console.WriteLine($"Available Page File: {memStatus.ullAvailPageFile / MB_DIVISOR} MB");
                    Console.WriteLine($"Total Phys: {memStatus.ullTotalPhys / MB_DIVISOR} MB");
                    Console.WriteLine($"Avail Phys: {memStatus.ullAvailPhys / MB_DIVISOR} MB");
                }
                else
                {
                    Console.WriteLine("Unable to get memory status.");
                }

                uint actualSize = 0;
                uint buffersize = 1024 * 1024;
                void* bufferPtr = NativeMemory.Alloc(buffersize);
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
                    //// Second call to NtQuerySystemInformation to get the actual data
                    if (status == 0)
                    {
                        // Use a dictionary to avoid duplicate entries if any
                        // 60 is a reasonable number for processes on a normal machine.
                        Dictionary<int, ProcessInfo> processInfos = new Dictionary<int, ProcessInfo>(60);

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
                                Console.WriteLine("Virtual size: " + longSize / LONG_MB_DIVISOR);
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
                    NativeMemory.Free(bufferPtr);
                }

                // Get the handle to the process IntPtr processHandle = currentProcess.Handle; 
                // Create an instance of PROCESS_MEMORY_COUNTERS_EX
                PROCESS_MEMORY_COUNTERS_EX pmc = new PROCESS_MEMORY_COUNTERS_EX();
                // Call GetProcessMemoryInfo to get memory information
                // var size = Marshal.SizeOf(typeof(_PROCESS_MEMORY_COUNTERS_EX2)) + 30;
                //pmc.cb = (uint)Marshal.SizeOf(typeof(_PROCESS_MEMORY_COUNTERS_EX2));
                int pHandle = (int)p.Handle;
                // Get the handle to the process
                IntPtr processHandle = p.Handle;
                int memExStatus = GetProcessMemoryInfo(pHandle, ref pmc, 80);
                if (memExStatus != 0)
                {
                    Console.WriteLine($"Private usage: {pmc.PrivateUsage / LONG_MB_DIVISOR} MB");
                }
                else
                {
                    uint error = GetLastError();
                    var msg = GetErrorMessage((int)error);
                    Console.WriteLine("Failed to get process memory information.");
                }

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
                    Console.WriteLine($"Process Name: {process["Name"]}");
                    Console.WriteLine($"Process ID: {process["ProcessId"]}");
                    Console.WriteLine($"Executable Path: {process["ExecutablePath"]}");
                    Console.WriteLine($"Virtual Size: {(UInt64)process["VirtualSize"] / LONG_MB_DIVISOR}");
                    Console.WriteLine($"Working Set: {(UInt64)process["WorkingSetSize"] / LONG_MB_DIVISOR}");
                    Console.WriteLine();
                }

                Task.Delay(5000).Wait();
            }
        }
    }
}

/// <summary>
/// This data structure contains information about a process that is collected
/// in bulk by querying the operating system.  The reason to make this a separate
/// structure from the process component is so that we can throw it away all at once
/// when Refresh is called on the component.
/// </summary>
internal sealed class ProcessInfo
{
    internal int BasePriority { get; set; }
    internal string ProcessName { get; set; } = string.Empty;
    internal int ProcessId { get; set; }
    internal long PoolPagedBytes { get; set; }
    internal long PoolNonPagedBytes { get; set; }
    internal long VirtualBytes { get; set; }
    internal long VirtualBytesPeak { get; set; }
    internal long WorkingSetPeak { get; set; }
    internal long WorkingSet { get; set; }
    internal long PageFileBytesPeak { get; set; }
    internal long PageFileBytes { get; set; }
    internal long PrivateBytes { get; set; }
    internal int SessionId { get; set; }
    internal int HandleCount { get; set; }
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
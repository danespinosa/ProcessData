// See https://aka.ms/new-console-template for more information

using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
        //public uint NextEntryOffset;
        //public uint NumberOfThreads;
        //// Other fields omitted for brevity
        //public IntPtr WorkingSetPrivateSize;
        //public ulong VirtualSize;
        //internal IntPtr UniqueProcessId;
        //internal uint NextEntryOffset;
        //internal uint NumberOfThreads;
        //internal int BasePriority;
        //internal IntPtr UniqueProcessId;
        //private readonly UIntPtr Reserved2;
        //internal uint HandleCount;
        //internal uint SessionId;
        //private readonly UIntPtr Reserved3;
        //internal UIntPtr PeakVirtualSize;  // SIZE_T
        //internal UIntPtr VirtualSize;
        //private readonly uint Reserved4;
        //internal UIntPtr PeakWorkingSetSize;  // SIZE_T
        //internal UIntPtr WorkingSetSize;  // SIZE_T
        //private readonly UIntPtr Reserved5;
        //internal UIntPtr QuotaPagedPoolUsage;  // SIZE_T
        //private readonly UIntPtr Reserved6;
        //internal UIntPtr QuotaNonPagedPoolUsage;  // SIZE_T
        //internal UIntPtr PagefileUsage;  // SIZE_T
        //internal UIntPtr PeakPagefileUsage;  // SIZE_T
        //internal UIntPtr PrivatePageCount;  // SIZE_T

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
            using var p = Process.GetCurrentProcess();
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
                    throw new Exception("NtQuerySystemInformation failed with status: " + status + ", error code: "+ lastError);
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
                            Console.WriteLine("Virtual size: " + (long)pi.VirtualSize / LONG_MB_DIVISOR);
                            //    string? processName = null;
                            //    ReadOnlySpan<char> processNameSpan =
                            //        pi.ImageName.Buffer != IntPtr.Zero ? GetProcessShortName(new ReadOnlySpan<char>(pi.ImageName.Buffer.ToPointer(), pi.ImageName.Length / sizeof(char))) :
                            //        (processName =
                            //            processId == NtProcessManager.SystemProcessID ? "System" :
                            //            processId == NtProcessManager.IdleProcessID ? "Idle" :
                            //            processId.ToString(CultureInfo.InvariantCulture)); // use the process ID for a normal process without a name

                            //    if (string.IsNullOrEmpty(processNameFilter) || processNameSpan.Equals(processNameFilter, StringComparison.OrdinalIgnoreCase))
                            //    {
                            //        processName ??= processNameSpan.ToString();

                            //        // get information for a process
                            //        ProcessInfo processInfo = new ProcessInfo()
                            //        {
                            //            ProcessName = processName,
                            //            ProcessId = processId,
                            //            VirtualBytes = (long)pi.VirtualSize,
                            //        };

                            //        processInfos[processInfo.ProcessId] = processInfo;
                            //    }
                        }

                        if (pi.NextEntryOffset == 0)
                        {
                            break;
                        }
                        processInformationOffset += (int)pi.NextEntryOffset;
                    }

                    //Console.WriteLine("Number of threads: " + spi.NumberOfThreads); 
                }
                //else 
                //{
                //    throw new Exception("NtQuerySystemInformation failed with status: " + status); 
                //} 
            } 
            finally 
            {
                NativeMemory.Free(bufferPtr);
                //if (buffer != IntPtr.Zero) 
                //{
                //    Marshal.FreeHGlobal(buffer); 
                //}
            }

            Task.Delay(5000).Wait();
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
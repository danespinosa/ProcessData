// See https://aka.ms/new-console-template for more information

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
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

    static async Task Main()
    {
        const ulong MB_DIVISOR = 1024 * 1024;
        const long LONG_MB_DIVISOR = (long)MB_DIVISOR;

        for (int i = 0; i < 1000; i++)
        {
            using var p = Process.GetCurrentProcess();
            var gcTotalAvailableMemoryBytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            Console.WriteLine($"process.VirtualMemorySize64: {p.VirtualMemorySize64/LONG_MB_DIVISOR} MB");
            Console.WriteLine($"GC.GetGCMemoryInfo().TotalAvailabmeMemoryBytes {gcTotalAvailableMemoryBytes / LONG_MB_DIVISOR} MB");

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

            await Task.Delay(5000);
        }
    }
}

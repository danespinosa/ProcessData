using System;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

class Program
{
    static void Main()
    {
        using Process p = Process.GetCurrentProcess();

        // if windows use the management apis 
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
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
                Console.WriteLine($"Virtual Size: {process["VirtualSize"]}");
                Console.WriteLine($"The committed VM is {p.VirtualMemorySize64}");

            }
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Console.WriteLine($"The committed VM is {p.VirtualMemorySize64}");
        }

        Console.ReadLine();

        // Create a new management scope

    }
}

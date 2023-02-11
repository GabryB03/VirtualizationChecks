﻿/// Source: https://stackoverflow.com/questions/36431220/getting-a-list-of-dlls-currently-loaded-in-a-process-c-sharp

using System.Runtime.InteropServices;
using System.Text;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

public class NativeModules
{
    public static List<Module> CollectModules(Process process)
    {
        List<Module> collectedModules = new List<Module>();

        IntPtr[] modulePointers = new IntPtr[0];
        int bytesNeeded = 0;

        if (!Native.EnumProcessModulesEx(process.Handle, modulePointers, 0, out bytesNeeded, (uint)Native.ModuleFilter.ListModulesAll))
        {
            return collectedModules;
        }

        int totalNumberofModules = bytesNeeded / IntPtr.Size;
        modulePointers = new IntPtr[totalNumberofModules];

        if (Native.EnumProcessModulesEx(process.Handle, modulePointers, bytesNeeded, out bytesNeeded, (uint)Native.ModuleFilter.ListModulesAll))
        {
            for (int index = 0; index < totalNumberofModules; index++)
            {
                StringBuilder moduleFilePath = new StringBuilder(1024);
                Native.GetModuleFileNameEx(process.Handle, modulePointers[index], moduleFilePath, (uint)(moduleFilePath.Capacity));

                string moduleName = Path.GetFileName(moduleFilePath.ToString());
                Native.ModuleInformation moduleInformation = new Native.ModuleInformation();
                Native.GetModuleInformation(process.Handle, modulePointers[index], out moduleInformation, (uint)(IntPtr.Size * (modulePointers.Length)));

                Module module = new Module(moduleName, moduleInformation.lpBaseOfDll, moduleInformation.SizeOfImage);
                collectedModules.Add(module);
            }
        }

        return collectedModules;
    }
}

public class Native
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ModuleInformation
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    internal enum ModuleFilter
    {
        ListModulesDefault = 0x0,
        ListModules32Bit = 0x01,
        ListModules64Bit = 0x02,
        ListModulesAll = 0x03,
    }

    [DllImport("psapi.dll")]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll")]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out ModuleInformation lpmodinfo, uint cb);
}

public class Module
{
    public Module(string moduleName, IntPtr baseAddress, uint size)
    {
        ModuleName = moduleName;
        BaseAddress = baseAddress;
        Size = size;
    }

    public string ModuleName { get; set; }
    public IntPtr BaseAddress { get; set; }
    public uint Size { get; set; }
}
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using System.Reflection;
using System.Linq;

public class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lib);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

    private static readonly string[] VmIndicators = {
        "vmware", "virtualbox", "vbox", "qemu", "kvm", "microsoft virtual", "hyper-v", "parallels", "xen"
    };

    private static readonly List<string> VmMacPrefixes = new List<string> {
        "00:05:69",
        "00:0C:29",
        "00:1C:14",
        "00:50:56",
        "08:00:27",
        "00:16:3E",
        "00:03:FF"
    };

    public static void Main()
    {
        Console.Title = "Virtualization Checks | Made by https://github.com/ZygoteCode/";
        Console.ForegroundColor = ConsoleColor.White;

        if (Assembly.GetCallingAssembly() != Assembly.GetExecutingAssembly())
        {
            NotPassed("Entry Point Check", "The assembly that is calling the entry point method is not the currently executing assembly");
        }
        else
        {
            Passed("Entry Point Check", "The assembly that is calling the entry point method is the currently executing assembly");
        }

        BiosCheck();
        ProcessorCheck();
        DiskDrivesCheck();
        MacAddressCheck();
        RecentFilesCheck();
        UptimeCheck();
        DriversCheck();
        UsernameCheck();
        ComputerNameCheck();
        DirectoriesCheck();
        PortConnectionsCheck();
        ProcessesCheck();
        ServicesCheck();
        WineCheck();
        TimingsCheck();
        ModulesCheck();
        SystemNamesCheck();
        RegistryKeysCheck();
        OwnershipCheck();
        ProgramTitleCheck();
        Console.ReadLine();
    }

    public static void Passed(string type, string details)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("[");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("PASSED");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] [");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(type);
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] " + details);
        Console.WriteLine();
    }

    public static void NotPassed(string type, string details)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("[");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("NOT PASSED");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] [");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(type);
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] " + details);
        Console.WriteLine();
    }

    public static void UptimeCheck()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
            {
                foreach (var obj in searcher.Get())
                {
                    string lastBootTimeString = obj["LastBootUpTime"]?.ToString();
                    if (!string.IsNullOrEmpty(lastBootTimeString))
                    {
                        DateTime lastBootTime = ManagementDateTimeConverter.ToDateTime(lastBootTimeString);
                        TimeSpan uptime = DateTime.Now - lastBootTime;

                        TimeSpan minUptime = TimeSpan.FromMinutes(10);
                        TimeSpan maxUptime = TimeSpan.FromDays(365 * 2);

                        if (uptime < minUptime)
                        {
                            Program.NotPassed("Uptime Check", $"System uptime ({uptime}) is suspiciously short (< {minUptime}).");
                        }
                        else if (uptime > maxUptime)
                        {
                            Program.NotPassed("Uptime Check", $"System uptime ({uptime}) is suspiciously long (> {maxUptime}).");
                        }
                        else
                        {
                            Program.Passed("Uptime Check", $"System uptime ({uptime}) seems reasonable.");
                        }
                    }
                    else
                    {
                        Program.Passed("Uptime Check", "Could not retrieve LastBootUpTime.");
                    }
                    obj.Dispose();
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Uptime Check failed: {ex.Message}");
        }
    }


    public static void RecentFilesCheck()
    {
        try
        {
            string recentFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            if (Directory.Exists(recentFolderPath))
            {
                int fileCount = Directory.GetFiles(recentFolderPath).Length;
                const int minRecentFiles = 5;

                if (fileCount < minRecentFiles)
                {
                    Program.NotPassed("Recent Files Check", $"Low number of recent files detected ({fileCount} < {minRecentFiles}).");
                }
                else
                {
                    Program.Passed("Recent Files Check", $"Number of recent files ({fileCount}) seems reasonable (>= {minRecentFiles}).");
                }
            }
            else
            {
                Program.Passed("Recent Files Check", "Recent files folder not found or inaccessible.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Recent Files Check failed: {ex.Message}");
        }
    }

    public static void MacAddressCheck()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"))
            {
                bool vmMacFound = false;
                foreach (var obj in searcher.Get())
                {
                    string mac = obj["MACAddress"]?.ToString();
                    if (!string.IsNullOrEmpty(mac))
                    {
                        string prefix = mac.Substring(0, 8).ToUpperInvariant();
                        if (VmMacPrefixes.Contains(prefix))
                        {
                            Program.NotPassed("MAC Address Check", $"Detected VM MAC Address: {mac} (Prefix: {prefix})");
                            vmMacFound = true;
                        }
                    }
                    obj.Dispose();
                }

                if (!vmMacFound)
                {
                    Program.Passed("MAC Address Check", "No known VM MAC address prefixes detected.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] MAC Address Check failed: {ex.Message}");
        }
    }

    private static void BiosCheck()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
            {
                foreach (var obj in searcher.Get())
                {
                    string manufacturer = obj["Manufacturer"]?.ToString().ToLowerInvariant() ?? "";
                    string version = obj["Version"]?.ToString().ToLowerInvariant() ?? "";
                    string serialNumber = obj["SerialNumber"]?.ToString().ToLowerInvariant() ?? "";

                    if (VmIndicators.Any(ind => manufacturer.Contains(ind)))
                        Program.NotPassed("WMI BIOS Check", $"Manufacturer contains VM indicator: {manufacturer}");
                    else
                        Program.Passed("WMI BIOS Check", $"Manufacturer: {manufacturer}");

                    if (VmIndicators.Any(ind => version.Contains(ind)))
                        Program.NotPassed("WMI BIOS Check", $"Version contains VM indicator: {version}");
                    else
                        Program.Passed("WMI BIOS Check", $"Version: {version}");

                    if (VmIndicators.Any(ind => serialNumber.Contains(ind)))
                        Program.NotPassed("WMI BIOS Check", $"SerialNumber contains VM indicator: {serialNumber}");
                    else
                        Program.Passed("WMI BIOS Check", $"SerialNumber: {serialNumber}");

                    obj.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] WMI BIOS Check failed: {ex.Message}");
        }
    }

    private static void DiskDrivesCheck()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
            {
                bool foundVmDisk = false;
                long totalSizeGB = 0;
                foreach (var obj in searcher.Get())
                {
                    string model = obj["Model"]?.ToString().ToLowerInvariant() ?? "";
                    string pnpDeviceId = obj["PNPDeviceID"]?.ToString().ToLowerInvariant() ?? "";
                    ulong sizeBytes = (ulong)(obj["Size"] ?? 0UL);
                    totalSizeGB += (long)(sizeBytes / (1024 * 1024 * 1024));

                    if (VmIndicators.Any(ind => model.Contains(ind)) || VmIndicators.Any(ind => pnpDeviceId.Contains(ind)))
                    {
                        Program.NotPassed("WMI Disk Check", $"Disk Model/PNP ID contains VM indicator: {model} / {pnpDeviceId}");
                        foundVmDisk = true;
                    }
                    obj.Dispose();
                }

                if (!foundVmDisk)
                {
                    Program.Passed("WMI Disk Check", "No disk Model/PNP ID contains VM indicators.");
                }

                const long minDiskSizeGB = 100;
                if (totalSizeGB > 0 && totalSizeGB < minDiskSizeGB)
                {
                    Program.NotPassed("WMI Disk Size Check", $"Total disk size ({totalSizeGB} GB) is suspiciously small (< {minDiskSizeGB} GB).");
                }
                else
                {
                    Program.Passed("WMI Disk Size Check", $"Total disk size ({totalSizeGB} GB) seems reasonable (>= {minDiskSizeGB} GB).");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] WMI Disk Check failed: {ex.Message}");
        }
    }

    private static void ProcessorCheck()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
            {
                uint coreCount = 0;
                foreach (var obj in searcher.Get())
                {
                    string name = obj["Name"]?.ToString().ToLowerInvariant() ?? "";
                    coreCount += (uint)(obj["NumberOfCores"] ?? 0U);

                    if (VmIndicators.Any(ind => name.Contains(ind)))
                        Program.NotPassed("WMI Processor Check", $"Processor Name contains VM indicator: {name}");
                    else
                        Program.Passed("WMI Processor Check", $"Processor Name: {name}");

                    obj.Dispose();
                }

                const uint minCores = 2;
                if (coreCount > 0 && coreCount < minCores)
                {
                    Program.NotPassed("WMI Processor Core Count Check", $"Total core count ({coreCount}) is suspiciously low (< {minCores}).");
                }
                else
                {
                    Program.Passed("WMI Processor Core Count Check", $"Total core count ({coreCount}) seems reasonable (>= {minCores}).");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] WMI Processor Check failed: {ex.Message}");
        }
    }

    public static void DriversCheck()
    {
        string[] drives = Directory.GetLogicalDrives();
        string[] drivers = new string[] { "Vmmouse.sys", "vm3dgl.dll", "vmdum.dll", "vm3dver.dll", "vmtray.dll", "vmusbmouse.sys",
            "vmx_svga.sys", "vmxnet.sys", "VMToolsHook.dll", "vmhgfs.dll", "vmmousever.dll", "vmGuestLib.dll", "VmGuestLibJava.dll", "vmscsi.sys",
            "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vboxdisp.dll", "vboxhook.dll", "vboxmrxnp.dll", "vboxogl.dll",
            "vboxoglarrayspu.dll", "vboxoglcrutil.dll", "vboxoglerrorspu.dll", "vboxoglfeedbackspu.dll", "vboxoglpackspu.dll",
            "vboxoglpassthroughspu.dll", "vboxservice.exe", "vboxtray.exe", "VBoxControl.exe", "balloon.sys", "netkvm.sys",
            "vioinput", "viofs.sys", "vioser.sys",
    "vmmouse.sys", "vm3dgl.dll", "vmdum.dll", "vm3dver.dll", "vmtray.dll",
    "vmusbmouse.sys", "vmx_svga.sys", "vmxnet.sys", "vmtoolsd.exe",
    "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe", "vmhgfs.sys",
    "vmmemctl.sys", "vmci.sys", "vmhgfsclient.dll", "vmwareguestproxy.dll",
    "vmwarevirtualdevicedevobj.dll",
    "vboxmouse.sys", "vboxguest.sys", "vboxsf.sys", "vboxvideo.sys",
    "vboxdisp.dll", "vboxhook.dll", "vboxmrxnp.dll", "vboxogl.dll",
    "vboxoglarrayspu.dll", "vboxoglcrutil.dll", "vboxoglerrorspu.dll",
    "vboxoglfeedbackspu.dll", "vboxoglpackspu.dll",
    "vboxoglpassthroughspu.dll", "vboxservice.exe", "vboxtray.exe",
    "vboxcontrol.exe", "vboxguestcontrolsvc.exe", "vboxguestnotificationsvc.exe",
    "vboxdrv.sys", "vboxnetflt.sys", "vboxusbmon.sys", "vboxnetadp.sys",
    "vboxvideogl.dll", "vboxsvga.dll",
    "vmbus.sys", "vmbushid.sys", "vmic.dll", "storvsp.sys", "storflt.sys",
    "vmprox.dll", "vmsrvc.dll", "icssvc.exe", "netvsc.sys", "winhv.sys", "hvix64.exe",
    "balloon.sys", "netkvm.sys", "vioinput.sys", "viofs.sys", "vioser.sys",
    "virtio_net.sys", "virtio_blk.sys", "virtio_scsi.sys", "virtio_serial.sys",
    "virtio_balloon.sys", "virtio_rng.sys", "qemu-ga.exe", "qemuwmi.dll",
    "prl_boot.sys", "prl_dd.sys", "prl_fs.sys", "prl_fs_freeze.sys", "prl_mouse.sys",
    "prl_net_adapter.sys", "prl_sf.sys", "prl_tg.sys", "prl_time_sync.sys",
    "prl_tools.dll", "prl_tools_service.exe", "prl_cc.exe", "prl_hook.dll",
    "xen.sys", "xenvbd.sys", "xennet.sys", "xenvif.sys", "xenhid.sys", "xenbus.sys",
    "xenservice.exe",
    "sbiedll.dll", "sbiedrv.sys", "sandboxierpcss.exe", "sandboxiedcomlaunch.exe",
    "cuckoomon.dll", "avprec.dll",
    "cmdvrt32.dll", "cmdvrt64.dll",
    "sxindll.dll", "snxhk.dll",
    "dbghelp.dll",
    "ftdibus.sys",
    "agp440.sys" };

        foreach (string drive in drives)
        {
            if (Directory.Exists(drive + "Windows"))
            {
                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\System32\\drivers\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\System32\\drivers\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\System32\\drivers\\" + driver);
                    }
                }

                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\System32\\drivers\\UMDF\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\System32\\drivers\\UMDF\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\System32\\drivers\\UMDF\\" + driver);
                    }
                }

                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\Sysnative\\drivers\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\Sysnative\\drivers\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\Sysnative\\drivers\\" + driver);
                    }
                }

                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\System32\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\System32\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\System32\\" + driver);
                    }
                }
            }
        }
    }

    public static void UsernameCheck()
    {
        string[] badNames = {     "johnson", "miller",
    "malware", "maltest", "test", "virus", "sandbox", "sand box",
    "sample", "vm", "virtual", "vbox", "vmware", "user", "admin",
    "test user", "testuser", "vagrant", "administrator", "tester",
    "analysis", "analyzer", "honeypot", "nepenthes", "cuckoo",
    "johndoe", "john doe",
    "wdagutilityaccount" };
        string username = Environment.UserName.ToLower();

        foreach (string badName in badNames)
        {
            if (username.ToLower().Equals(badName.ToLower()))
            {
                NotPassed("Username Check", badName);
            }
            else
            {
                Passed("Username Check", badName);
            }
        }
    }

    public static void ComputerNameCheck()
    {
        string[] badNames = { "Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount" };
        string computerName = Environment.MachineName.ToLower();

        foreach (string badName in badNames)
        {
            if (computerName.ToLower().Equals(badName.ToLower()))
            {
                NotPassed("Computer Name Check", badName);
            }
            else
            {
                Passed("Computer Name Check", badName);
            }
        }
    }

    public static void DirectoriesCheck()
    {
        string[] drives = Directory.GetLogicalDrives();
        string[] directories = new string[] { "Program Files\\VMWare",
            "Program Files\\Oracle\\VirtualBox Guest Additions", "Program Files (x86)\\Oracle\\VirtualBox Guest Additions",    "Program Files\\VMware\\VMware Tools",
    "Program Files (x86)\\VMware\\VMware Tools",
    "Program Files\\Oracle\\VirtualBox Guest Additions",
    "Program Files (x86)\\Oracle\\VirtualBox Guest Additions",
    "Program Files (x86)\\Parallels\\Parallels Tools",
    "Program Files\\Parallels\\Parallels Tools",
    "C:\\Sandbox",
     "Program Files\\Qemu-ga",
     "C:\\Program Files\\qemu-ga", };

        foreach (string drive in drives)
        {
            foreach (string directory in directories)
            {
                if (Directory.Exists(drive + directory))
                {
                    NotPassed("Directories Checking", drive + directory);
                }
                else
                {
                    Passed("Directories Checking", drive + directory);
                }
            }
        }
    }

    public static void PortConnectionsCheck()
    {
        int portConnections = new ManagementObjectSearcher("SELECT * FROM Win32_PortConnector").Get().Count;

        if (portConnections == 0)
        {
            NotPassed("Port Connections Check", "Port connections count (SELECT * FROM Win32_PortConnector): " + portConnections);
        }
        else
        {
            Passed("Port Connections Check", "Port connections count (SELECT * FROM Win32_PortConnector): " + portConnections);
        }
    }

    public static void ProcessesCheck()
    {
        string[] badProcessNames = {    
    "vmtoolsd", "vmwaretray", "vmwareuser", "vmacthlp",
    "vboxservice", "vboxtray", "vboxguestcontrolsvc", "vboxguestnotificationsvc",
    "icssvc",
    "qemu-ga",
    "prl_tools_service", "prl_cc",
    "xenservice",
    "sandboxierpcss", "sandboxiedcomlaunch",
    "joeboxserver",
    "ollydbg", "ida", "idaq", "idaq64", "idag", "idag64", "idaw", "idaw64",
    "windbg", "x64dbg", "x32dbg",
    "procmon", "procexp", "regmon", "filemon", "wireshark", "dumpcap",
    "tcpview", "autoruns", "autorunsc", "processhacker",
    "sysanalyzer",
    "hookexplorer", "importrec", "petools" };
        List<string> checkedProcesses = new List<string>();

        try
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    foreach (string badProcessName in badProcessNames)
                    {
                        if (process.ProcessName.ToLower().Equals(badProcessName.ToLower()))
                        {
                            if (!checkedProcesses.Contains(badProcessName.ToLower()))
                            {
                                checkedProcesses.Add(badProcessName.ToLower());
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        catch
        {

        }

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Process");

            foreach (ManagementObject queryObj in searcher.Get())
            {
                try
                {
                    foreach (string badProcessName in badProcessNames)
                    {
                        if (Path.GetFileNameWithoutExtension(queryObj["Name"].ToString()).ToLower().Equals(badProcessName.ToLower()))
                        {
                            if (!checkedProcesses.Contains(badProcessName.ToLower()))
                            {
                                checkedProcesses.Add(badProcessName.ToLower());
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        catch
        {

        }

        foreach (string badProcessName in badProcessNames)
        {
            if (checkedProcesses.Contains(badProcessName.ToLower()))
            {
                NotPassed("Processes Check", badProcessName);
            }
            else
            {
                Passed("Processes Check", badProcessName);
            }
        }
    }

    public static void ServicesCheck()
    {
        string[] badServices = {
    "vmtools", "vmhgfs", "vmmemctl", "vmware physical disk helper service", "vmci", "vmusbmouse",
    "vboxservice", "vboxguest",
    "vmbus", "vmbushid", "vmicshutdown", "vmicheartbeat", "vmickvp", "vmicrdv",
    "vmictimesync", "vmicvss", "storflt", "vmproxc", "nvspwmi", "vhdsvc",
    "xensvc", "xenevtchn", "xeniface", "xennet", "xenvbd",
    "prl_tools", "prl_svchost", "prl_disp_service",
    "qemuguestagent", "virtio-fs-service",
    "sbiedrv" };
        List<string> checkedServices = new List<string>();
        ServiceController[] GetServicesOnSystem = ServiceController.GetServices();

        foreach (ServiceController service in GetServicesOnSystem)
        {
            foreach (string badService in badServices)
            {
                if (service.ServiceName.ToLower().Contains(badService.ToLower()) || badService.ToLower().Contains(service.ServiceName.ToLower()))
                {
                    if (!checkedServices.Contains(badService.ToLower()))
                    {
                        checkedServices.Add(badService.ToLower());
                    }
                }
            }
        }

        foreach (string badService in badServices)
        {
            if (checkedServices.Contains(badService.ToLower()))
            {
                NotPassed("Services Check", badService);
            }
            else
            {
                Passed("Services Check", badService);
            }
        }
    }

    public static void WineCheck()
    {
        IntPtr ModuleHandle = GetModuleHandle("kernel32.dll");

        if (GetProcAddress(ModuleHandle, "wine_get_unix_file_name").ToInt32() != 0)
        {
            NotPassed("Wine Check", "'wine_get_unix_file_name' function is available in 'kernel32.dll'.");
        }
        else
        {
            Passed("Wine Check", "'wine_get_unix_file_name' function is not available in 'kernel32.dll'.");
        }
    }

    public static void TimingsCheck()
    {
        long tickCount1 = Environment.TickCount;
        Thread.Sleep(500);
        long tickCount2 = Environment.TickCount;

        if (((tickCount2 - tickCount1) < 500L))
        {
            NotPassed("Timings Check", "Emulation is present. Could not validate a timing check.");
        }
        else
        {
            Passed("Timings Check", "Emulation is not present. Timing check validated.");
        }
    }

    public static void ModulesCheck()
    {
        string[] badModules = new string[] {    "sbiedll.dll",
    "cmdvrt32.dll", "cmdvrt64.dll",
    "sxindll.dll", "snxhk.dll",
    "cuckoomon.dll", "avprec.dll",
    "apimonitor-x86.dll", "apimonitor-x64.dll",
    "pinvm.dll",
    "log_analyzer_dll.dll",
    "rtkhook.dll",
    "prl_hook.dll" };
        List<string> checkedModules = new List<string>();

        foreach (string badModule in badModules)
        {
            try
            {
                if (GetModuleHandle(badModule).ToInt32() != 0)
                {
                    if (!checkedModules.Contains(badModule.ToLower()))
                    {
                        checkedModules.Add(badModule.ToLower());
                    }
                }
            }
            catch
            {

            }
        }

        try
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                try
                {
                    foreach (string badModule in badModules)
                    {
                        if (module.ModuleName.ToLower().Equals(badModule.ToLower()))
                        {
                            if (!checkedModules.Contains(badModule.ToLower()))
                            {
                                checkedModules.Add(badModule.ToLower());
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        catch
        {

        }

        foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            foreach (string badModule in badModules)
            {
                if (assembly.FullName.ToLower().Contains(badModule.ToLower()) || badModule.ToLower().Contains(assembly.FullName.ToLower()))
                {
                    if (!checkedModules.Contains(badModule.ToLower()))
                    {
                        checkedModules.Add(badModule.ToLower());
                    }
                }
            }
        }

        foreach (Module module in NativeModules.CollectModules(Process.GetCurrentProcess()))
        {
            foreach (string badModule in badModules)
            {
                if (module.ModuleName.ToLower().Equals(badModule.ToLower()))
                {
                    if (!checkedModules.Contains(badModule.ToLower()))
                    {
                        checkedModules.Add(badModule.ToLower());
                    }
                }
            }
        }

        foreach (string badModule in badModules)
        {
            if (checkedModules.Contains(badModule.ToLower()))
            {
                NotPassed("Modules Check", badModule);
            }
            else
            {
                Passed("Modules Check", badModule);
            }
        }
    }

    public static void SystemNamesCheck()
    {
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
        {
            using (ManagementObjectCollection items = searcher.Get())
            {
                foreach (ManagementBaseObject item in items)
                {
                    string manufacturer = item["Manufacturer"].ToString().ToLower();
                    string model = item["Model"].ToString();

                    if (manufacturer == "microsoft corporation")
                    {
                        NotPassed("System Names Check", "What is checked: {Manufacturer == 'microsoft corporation'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Manufacturer == 'microsoft corporation'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }

                    if (manufacturer.ToUpperInvariant().Contains("VIRTUAL"))
                    {
                        NotPassed("System Names Check", "What is checked: {Manufacturer, in upper case invariant, contains 'VIRTUAL'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Manufacturer, in upper case invariant, contains 'VIRTUAL'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }

                    if (manufacturer.Contains("vmware"))
                    {
                        NotPassed("System Names Check", "What is checked: {Manufacturer contains 'vmware'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Manufacturer contains 'vmware'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }

                    if (model.ToLower().Contains("virtualbox"))
                    {
                        NotPassed("System Names Check", "What is checked: {Model lower case contains 'virtualbox'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Model lower case contains 'virtualbox'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                }
            }
        }
    }

    public static void RegistryKeysCheck()
    {
        List<string> sandboxStrings = new List<string>() {     "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v", "parallels", "virtual", "bochs", "microsoft hv" };
        string[] hklmKeys1 = new string[] { @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier", @"SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S", @"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\root#vmwvmcihostdev", @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers", @"SOFTWARE\VMWare, Inc.\VMWare Tools", @"SOFTWARE\Oracle\VirtualBox Guest Additions", @"HARDWARE\ACPI\DSDT\VBOX_",     @"SOFTWARE\VMware, Inc.\VMware Tools",
    @"SOFTWARE\Oracle\VirtualBox Guest Additions",
    @"SOFTWARE\Parallels\Parallels Tools",
    @"SOFTWARE\Classes\Folder\shell\sandbox",
    @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    @"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    @"SYSTEM\CurrentControlSet\Services\VBoxMouse",
    @"SYSTEM\CurrentControlSet\Services\VBoxSF",
    @"SYSTEM\CurrentControlSet\Services\VBoxVideo",
    @"SYSTEM\CurrentControlSet\Services\vmci",
    @"SYSTEM\CurrentControlSet\Services\vmhgfs",
    @"SYSTEM\CurrentControlSet\Services\vmmouse",
    @"SYSTEM\CurrentControlSet\Services\vmtools",
    @"SYSTEM\CurrentControlSet\Services\VMMEMCTL",
    @"SYSTEM\CurrentControlSet\Services\xenevtchn",
    @"SYSTEM\CurrentControlSet\Services\xennet",
    @"SYSTEM\CurrentControlSet\Services\xenbus",
    @"SYSTEM\CurrentControlSet\Services\xenvdb",
    @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers",
    @"HARDWARE\ACPI\DSDT\VBOX__",
    @"HARDWARE\ACPI\FADT\VBOX__",
    @"HARDWARE\ACPI\RSDT\VBOX__",
    @"HARDWARE\ACPI\DSDT\VMWARE",
    @"HARDWARE\ACPI\FADT\VMWARE",
    @"HARDWARE\ACPI\RSDT\VMWARE" };
        string[] hklmKeys2 = new string[] { @"SYSTEM\ControlSet001\Services\Disk\Enum\0", @"HARDWARE\Description\System\SystemBiosInformation", @"HARDWARE\Description\System\VideoBiosVersion", @"HARDWARE\Description\System\SystemManufacturer", @"HARDWARE\Description\System\SystemProductName", @"HARDWARE\Description\System\Logical Unit Id 0",     @"SOFTWARE\VMware, Inc.\VMware Tools",
    @"SOFTWARE\Oracle\VirtualBox Guest Additions",
    @"SOFTWARE\Parallels\Parallels Tools",
    @"SOFTWARE\Classes\Folder\shell\sandbox",
    @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    @"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    @"SYSTEM\CurrentControlSet\Services\VBoxMouse",
    @"SYSTEM\CurrentControlSet\Services\VBoxSF",
    @"SYSTEM\CurrentControlSet\Services\VBoxVideo",
    @"SYSTEM\CurrentControlSet\Services\vmci",
    @"SYSTEM\CurrentControlSet\Services\vmhgfs",
    @"SYSTEM\CurrentControlSet\Services\vmmouse",
    @"SYSTEM\CurrentControlSet\Services\vmtools",
    @"SYSTEM\CurrentControlSet\Services\VMMEMCTL",
    @"SYSTEM\CurrentControlSet\Services\xenevtchn",
    @"SYSTEM\CurrentControlSet\Services\xennet",
    @"SYSTEM\CurrentControlSet\Services\xenbus",
    @"SYSTEM\CurrentControlSet\Services\xenvdb",
    @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers",
    @"HARDWARE\ACPI\DSDT\VBOX__",
    @"HARDWARE\ACPI\FADT\VBOX__",
    @"HARDWARE\ACPI\RSDT\VBOX__",
    @"HARDWARE\ACPI\DSDT\VMWARE",
    @"HARDWARE\ACPI\FADT\VMWARE",
    @"HARDWARE\ACPI\RSDT\VMWARE" };

        foreach (string hklmKey in hklmKeys1)
        {
            try
            {
                RegistryKey openedKey = Registry.LocalMachine.OpenSubKey(hklmKey, false);

                if (openedKey is object)
                {
                    NotPassed("Registry Keys Check", "HKEY_LOCAL_MACHINE\\" + hklmKey);
                }
                else
                {
                    Passed("Registry Keys Check", "HKEY_LOCAL_MACHINE\\" + hklmKey);
                }
            }
            catch
            {

            }
        }

        foreach (string hklmKey in hklmKeys2)
        {
            try
            {
                string valueName = new DirectoryInfo(hklmKey).Name;
                string value = Convert.ToString(Registry.LocalMachine.OpenSubKey(Path.GetDirectoryName(hklmKey), false).GetValue(valueName));

                foreach (string sandboxString in sandboxStrings)
                {
                    if (!string.IsNullOrEmpty(value) && value.ToLower().Contains(sandboxString.ToLower()))
                    {
                        NotPassed("Registry Keys Check (" + sandboxString + ")", hklmKey);
                    }
                    else
                    {
                        Passed("Registry Keys Check (" + sandboxString + ")", hklmKey);
                    }
                }
            }
            catch
            {

            }
        }

        string[] registryKeysValueChecks = new string[] {
    @"HARDWARE\Description\System|SystemBiosVersion",
    @"HARDWARE\Description\System|VideoBiosVersion",
    @"HARDWARE\Description\System\BIOS|SystemManufacturer",
    @"HARDWARE\Description\System\BIOS|SystemProductName",
    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0|Identifier",
    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0|Identifier",
    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0|Identifier",
    @"SYSTEM\ControlSet001\Services\Disk\Enum|DeviceDesc",
    @"SYSTEM\ControlSet001\Services\Disk\Enum|FriendlyName",
    @"SYSTEM\ControlSet002\Services\Disk\Enum|DeviceDesc",
    @"SYSTEM\ControlSet002\Services\Disk\Enum|FriendlyName",
    @"SYSTEM\ControlSet003\Services\Disk\Enum|DeviceDesc",
    @"SYSTEM\ControlSet003\Services\Disk\Enum|FriendlyName",
    @"SYSTEM\CurrentControlSet\Control\SystemInformation|SystemManufacturer",
    @"SYSTEM\CurrentControlSet\Control\SystemInformation|SystemProductName",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion|ProductId",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion|ProductId",
    @"SYSTEM\CurrentControlSet\Enum\IDE|DeviceDesc",
    @"SYSTEM\CurrentControlSet\Enum\SCSI|DeviceDesc",
    @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion|InstallDate",
    @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders|Recent",
};

        foreach (string regValueCheck in registryKeysValueChecks)
        {
            string[] parts = regValueCheck.Split('|');
            if (parts.Length == 2)
            {
                string keyPath = parts[0];
                string valueName = parts[1];
                try
                {
                    object valueData = Registry.LocalMachine.OpenSubKey(keyPath, false)?.GetValue(valueName);
                    string valueString = Convert.ToString(valueData).ToLowerInvariant();

                    if (!string.IsNullOrEmpty(valueString))
                    {
                        bool found = false;
                        foreach (string sandboxString in sandboxStrings) 
                        {
                            if (valueString.Contains(sandboxString))
                            {
                                NotPassed("Registry Value Check", $"Value '{valueName}' in HKLM\\{keyPath} contains '{sandboxString}'. Value: '{valueData}'");
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            Passed("Registry Value Check", $"Value '{valueName}' in HKLM\\{keyPath} checked. Value: '{valueData}'");
                        }
                    }
                    else
                    {
                        Passed("Registry Value Check", $"Value '{valueName}' not found or empty in HKLM\\{keyPath}.");
                    }
                }
                catch (Exception ex)
                {
                    Passed("Registry Value Check", $"Error checking HKLM\\{keyPath}\\{valueName}: {ex.Message}");
                }
            }
        }
    }

    public static void OwnershipCheck()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Process");

        foreach (ManagementObject queryObject in searcher.Get())
        {
            if (Path.GetFileNameWithoutExtension(queryObject["Name"].ToString()).ToLower().Equals(Process.GetCurrentProcess().ProcessName.ToLower()))
            {
                ManagementBaseObject outParameters = queryObject.InvokeMethod("GetOwner", null, null);
                string domain = outParameters["Domain"].ToString();
                string user = outParameters["User"].ToString();
                
                if (domain != Environment.MachineName || user != Environment.UserName)
                {
                    NotPassed("Ownership Check", "Domain: '" + domain + "', user: '" + user + "'.");
                }
                else
                {
                    Passed("Ownership Check", "Domain: '" + domain + "', user: '" + user + "'.");
                }
            }
        }
    }

    public static void ProgramTitleCheck()
    {
        try
        {
            string title = Process.GetCurrentProcess().MainWindowTitle;

            if (title.StartsWith("[#]") && title.EndsWith("[#]"))
            {
                NotPassed("Program Title Check", title);
            }
            else
            {
                Passed("Program Title Check", title);
            }
        }
        catch
        {
            Passed("Program Title Check", "No program title available.");
        }
    }
}

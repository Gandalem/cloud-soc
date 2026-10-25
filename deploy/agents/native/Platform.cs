using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

namespace CloudSoc.Native {
internal static class Platform {
    internal const string Service = "cloud-soc-filebeat", TaskName = "Cloud-SOC-Discovery";
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateService(IntPtr manager, string name, string display, uint access, uint type, uint start, uint error, string command, string group, IntPtr tag, string dependencies, string account, string password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DeleteService(IntPtr service);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
    internal static string Quote(string value) { Contract.Require(value.IndexOf('"') < 0 && value.IndexOf('\r') < 0 && value.IndexOf('\n') < 0 && !value.EndsWith("\\"), "unsafe_argument"); return "\"" + value + "\""; }
    internal static string ServiceCommand(string root) { return Quote(Installer.Beat(root)) + " --environment=windows_service " + BeatArgs(root) + " -E logging.files.redirect_stderr=true"; }
    internal static string BeatArgs(string root) { return "--path.home " + Quote(Path.GetDirectoryName(Installer.Beat(root))) + " --path.config " + Quote(root) + " --path.data " + Quote(Path.Combine(root, "data")) + " --path.logs " + Quote(Path.Combine(root, "logs")) + " -c " + Quote(Path.Combine(root, "filebeat.yml")); }
    internal static int Run(string exe, string arguments, string input, int timeout) {
        Safe.Path(exe);
        var start = new ProcessStartInfo(exe, arguments) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var process = new Process { StartInfo = start }) {
            // Drain both streams without logging configuration, errors or credentials.
            process.OutputDataReceived += delegate {}; process.ErrorDataReceived += delegate {};
            Contract.Require(process.Start(), "process_start"); process.BeginOutputReadLine(); process.BeginErrorReadLine();
            if (input != null) process.StandardInput.Write(input); process.StandardInput.Close();
            if (!process.WaitForExit(timeout)) { process.Kill(); process.WaitForExit(); throw new IOException("collector_timeout"); }
            process.WaitForExit(); return process.ExitCode;
        }
    }
    internal static bool Exists() { using (var controller = new ServiceController(Service)) { try { var status = controller.Status; return true; } catch (InvalidOperationException) { return false; } } }
    internal static void OwnService(string root) {
        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + Service)) {
            Contract.Require(key != null && String.Equals(key.GetValue("ImagePath") as string, ServiceCommand(root), StringComparison.Ordinal), "service_ownership");
        }
    }
    internal static void Create(string root) {
        IntPtr manager = OpenSCManager(null, null, 2); Contract.Require(manager != IntPtr.Zero, "service_manager");
        try {
            IntPtr service = CreateService(manager, Service, "Cloud SOC log collector", 0xF01FF, 0x10, 2, 1, ServiceCommand(root), null, IntPtr.Zero, null, "LocalSystem", null);
            Contract.Require(service != IntPtr.Zero, "service_create"); CloseServiceHandle(service);
        } finally { CloseServiceHandle(manager); }
    }
    internal static void SetRunning(string root, bool running) {
        OwnService(root);
        using (var service = new ServiceController(Service)) {
            service.Refresh();
            if (running && service.Status != ServiceControllerStatus.Running) { if (service.Status != ServiceControllerStatus.StartPending) service.Start(); service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(40)); }
            if (!running && service.Status != ServiceControllerStatus.Stopped) { if (service.Status != ServiceControllerStatus.StopPending) service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(40)); }
        }
    }
    internal static void Remove(string root) {
        OwnService(root); SetRunning(root, false);
        IntPtr manager = OpenSCManager(null, null, 1); Contract.Require(manager != IntPtr.Zero, "service_manager");
        try { IntPtr service = OpenService(manager, Service, 0x10000); Contract.Require(service != IntPtr.Zero, "service_open"); try { Contract.Require(DeleteService(service), "service_delete"); } finally { CloseServiceHandle(service); } }
        finally { CloseServiceHandle(manager); }
        for (int n = 0; n < 50 && Exists(); n++) Thread.Sleep(100);
        Contract.Require(!Exists(), "service_delete_pending");
    }
    private static dynamic Scheduler() { dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true)); service.Connect(); return service; }
    internal static bool TaskExists() {
        dynamic service = Scheduler(); dynamic folder = service.GetFolder("\\");
        try { dynamic task = folder.GetTask(TaskName); return task != null; }
        // COM interop maps ERROR_FILE_NOT_FOUND to FileNotFoundException on some
        // Windows/.NET builds. Only the exact absence HRESULT is an empty result.
        catch (Exception ex) { if ((uint)ex.HResult == 0x80070002) return false; throw; }
    }
    internal static void OwnTask(string manager) {
        dynamic service = Scheduler(); dynamic task = service.GetFolder("\\").GetTask(TaskName); dynamic definition = task.Definition;
        string principal = (string)definition.Principal.UserId;
        Contract.Require(definition.Actions.Count == 1 && (string)definition.Actions.Item(1).Path == manager && (string)definition.Actions.Item(1).Arguments == "--refresh" && (principal == "SYSTEM" || principal == "S-1-5-18"), "task_ownership");
    }
    internal static void Schedule(string manager) {
        Contract.Require(!TaskExists(), "task_exists"); dynamic service = Scheduler(); dynamic task = service.NewTask(0);
        task.RegistrationInfo.Description = "Cloud SOC native security-log discovery";
        task.Principal.UserId = "SYSTEM"; task.Principal.LogonType = 5; task.Principal.RunLevel = 1;
        task.Settings.Enabled = true; task.Settings.StartWhenAvailable = true; task.Settings.MultipleInstances = 2; task.Settings.ExecutionTimeLimit = "PT2M";
        task.Settings.DisallowStartIfOnBatteries = false; task.Settings.StopIfGoingOnBatteries = false;
        dynamic trigger = task.Triggers.Create(1); trigger.StartBoundary = DateTime.Now.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss"); trigger.Repetition.Interval = "PT5M";
        task.Triggers.Create(8); dynamic action = task.Actions.Create(0); action.Path = manager; action.Arguments = "--refresh";
        // TASK_CREATE only; no update of unrelated existing tasks. Protected task ACL.
        service.GetFolder("\\").RegisterTaskDefinition(TaskName, task, 2, "SYSTEM", null, 5, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    }
    internal static void DeleteTask(string manager) {
        OwnTask(manager); dynamic service = Scheduler(); dynamic folder = service.GetFolder("\\"); dynamic task = folder.GetTask(TaskName);
        task.Enabled = false; task.Stop(0); folder.DeleteTask(TaskName, 0); Contract.Require(!TaskExists(), "task_delete_pending");
    }
}
}

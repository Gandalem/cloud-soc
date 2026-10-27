// Explicit test entry point. Never calls Installer/SCM/Task Scheduler/registry writes.
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Principal;
using System.Windows.Forms;
using CloudSoc.Native;

internal static class NativeInstallerTests {
    private static int count;
    private static void Assert(bool value) { count++; if (!value) throw new Exception("assertion_" + count); }
    private static void Reject(Action action) { bool rejected = false; try { action(); } catch (InvalidDataException) { rejected = true; } Assert(rejected); }
    [STAThread] public static int Main(string[] args) {
        string root = Path.Combine(Path.GetTempPath(), "cloud-soc-contract-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try {
            if (args.Length == 1 && args[0] == "--reinstall-files-only") { ReinstallFiles(root); return 0; }
            string id = new string('a', 32), device = new string('b', 32), attempt = Contract.Random();
            Assert(attempt.Length == 43 && attempt != Contract.Random());
            var spec = Contract.Map("os", "windows", "system", true, "network", false, "package_id", id, "managed_device_id", device, "organization", "school", "portal_url", "https://soc.test", "endpoint", "https://soc.test:9200", "enrollment_protocol", 1);
            var registration = Contract.Map("device_id", device, "enrollment_id", id, "token", id + "." + attempt, "package_sha256", new string('c',64), "expires", 4102444800L);
            Assert(Contract.ValidatePackage(spec, registration) == spec);
            spec["network"] = true; Reject(() => Contract.ValidatePackage(spec, registration)); spec["network"] = false;
            registration["device_id"] = id; Reject(() => Contract.ValidatePackage(spec, registration)); registration["device_id"] = device;
            registration["expires"] = 1; Reject(() => Contract.ValidatePackage(spec, registration)); registration["expires"] = 4102444800L;
            foreach (string origin in new[] {"http://soc.test", "https://user:secret@soc.test", "https://soc.test/path", "https://soc.test?x=y"}) Reject(() => Contract.Origin(origin));
            Installer.LabOrigin("https://192.168.235.1:9443"); Reject(() => Installer.LabOrigin("https://8.8.8.8")); Reject(() => Installer.LabOrigin("https://public.test"));
            var reply = Contract.Map("id", id, "probe", new string('d',64), "endpoint", spec["endpoint"], "organization", "school", "receipt_verified", false, "keys", new object[] {Contract.Map("scope", "host", "key", "synthetic:key")});
            Assert(Contract.Session(reply, spec, id)["key"].Equals("synthetic:key"));
            reply["organization"] = "other"; Reject(() => Contract.Session(reply,spec,id)); reply["organization"] = "school";
            reply["keys"] = new object[] {Contract.Map("scope", "network", "key", "synthetic:key")}; Reject(() => Contract.Session(reply,spec,id));
            foreach (string name in new[] {"../escape", "C:/escape", "nested/script.ps1", "a:stream"}) {
                string path = Path.Combine(root, Guid.NewGuid().ToString("N") + ".zip"); using (var zip = ZipFile.Open(path, ZipArchiveMode.Create)) using (var writer = new StreamWriter(zip.CreateEntry(name).Open())) writer.Write("synthetic");
                Reject(() => Contract.Archive(path, 1024));
            }
            string duplicate = Path.Combine(root,"duplicate.zip"); using (var zip = ZipFile.Open(duplicate,ZipArchiveMode.Create)) { zip.CreateEntry("test.json"); zip.CreateEntry("TEST.JSON"); } Reject(() => Contract.Archive(duplicate,1024));
            string good = Path.Combine(root,"good.zip"); using (var zip = ZipFile.Open(good,ZipArchiveMode.Create)) using (var writer = new StreamWriter(zip.CreateEntry("package.json").Open())) writer.Write("{}"); Assert(Contract.Archive(good,1024).Count == 1); Reject(() => Contract.Archive(good,1));
            Reject(() => Platform.Quote("unsafe\"argument")); Reject(() => Safe.Path(@"\\server\share\file"));
            Reject(() => Safe.Signed(typeof(NativeInstallerTests).Assembly.Location));
            Assert(Contract.Hash(new byte[0]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            ReinstallPolicy();
            using (var choice = new RemovalChoice()) {
                Assert(!choice.Purge);
                var options = choice.Controls[0].Controls.OfType<RadioButton>().ToArray();
                options.Single(item => item.Text == "수집기 자료까지 삭제").Checked = true;
                Assert(choice.Purge);
                Assert(((Button)choice.CancelButton).DialogResult == DialogResult.Cancel && choice.AcceptButton == choice.CancelButton);
            }
            ReinstallFiles(root);
            Console.WriteLine("native_contracts_passed=" + count); return 0;
        } finally {
            // Only files created above in this fresh, named test directory.
            Safe.Path(root); foreach (var file in Directory.GetFiles(root)) { Safe.Path(file); File.Delete(file); } Directory.Delete(root, false);
        }
    }
    private static void ReinstallPolicy() {
        var previous = Contract.Map("phase", "purged", "purge", true, "device_id", new string('a', 32), "enrollment_id", new string('b', 32), "lab", true, "manager_sha256", new string('c', 64));
        var next = Contract.Map("device_id", new string('d', 32), "enrollment_id", new string('e', 32));
        Assert(Contract.ReinstallHistoryName(previous, next, true) == new string('a', 32) + "-" + new string('b', 32));
        foreach (string phase in new[] {"complete", "removed", "removing", "purging", "aborted", "preparing", "revocation_unconfirmed"}) {
            previous["phase"] = phase; Reject(() => Contract.ReinstallHistoryName(previous, next, true));
        }
        previous["phase"] = "purged"; previous["purge"] = false; Reject(() => Contract.ReinstallHistoryName(previous, next, true)); previous["purge"] = true;
        Reject(() => Contract.ReinstallHistoryName(previous, next, false));
        next["device_id"] = previous["device_id"]; Reject(() => Contract.ReinstallHistoryName(previous, next, true)); next["device_id"] = new string('d', 32);
        next["enrollment_id"] = previous["enrollment_id"]; Reject(() => Contract.ReinstallHistoryName(previous, next, true)); next["enrollment_id"] = new string('e', 32);
        previous["device_id"] = "../escape"; Reject(() => Contract.ReinstallHistoryName(previous, next, true));
    }
    private static void ReinstallFiles(string temporary) {
        // Real ACL/rename tests use disposable files only, never fixed installation paths or SCM.
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) {
            Console.WriteLine("native_reinstall_filesystem_skipped=administrator_token_required"); return;
        }
        string sandbox = Path.Combine(temporary, "reinstall"); Safe.Protected(sandbox);
        string stateRoot = Path.Combine(sandbox, "state"), manager = Path.Combine(stateRoot, "cloud-soc-agent.exe"); Safe.Protected(stateRoot);
        Safe.Atomic(manager, new byte[] {1, 2, 3});
        var previous = Contract.Map("phase", "purged", "purge", true, "device_id", new string('a', 32), "enrollment_id", new string('b', 32), "lab", true, "manager_sha256", Contract.FileHash(manager));
        var next = Contract.Map("device_id", new string('d', 32), "enrollment_id", new string('e', 32));
        Safe.Json(Path.Combine(stateRoot, "state.json"), previous);
        string residue = Path.Combine(stateRoot, "session.dpapi"); Safe.Atomic(residue, new byte[] {4});
        Reject(() => Installer.ArchivePurgedState(stateRoot, manager, previous, next, true, () => { throw new Exception("guard_must_not_run"); }));
        Assert(File.Exists(residue)); File.Delete(residue);
        Reject(() => Installer.ArchivePurgedState(stateRoot, manager, previous, next, true, () => Contract.Require(false, "existing_service")));
        Assert(File.Exists(Path.Combine(stateRoot, "state.json")));
        string originalHash = (string)previous["manager_sha256"]; previous["manager_sha256"] = new string('f', 64);
        Reject(() => Installer.ArchivePurgedState(stateRoot, manager, previous, next, true, () => {})); previous["manager_sha256"] = originalHash;
        int checks = 0;
        Installer.ArchivePurgedState(stateRoot, manager, previous, next, true, () => { checks++; });
        string history = Path.Combine(stateRoot + "-History", Contract.ReinstallHistoryName(previous, next, true));
        Assert(checks == 2 && !Directory.Exists(stateRoot));
        Assert(Contract.FileHash(Path.Combine(history, "cloud-soc-agent.exe")) == originalHash);
        Assert(Contract.Equal(Contract.Parse(Contract.Utf8.GetString(Safe.Read(Path.Combine(history, "state.json"), 131072))), previous));
        Safe.CheckAcl(history);
        // A retry with no new state can use the ordinary fresh path; occupied history is never overwritten.
        Safe.Protected(stateRoot); Safe.Atomic(manager, new byte[] {1, 2, 3}); Safe.Json(Path.Combine(stateRoot, "state.json"), previous);
        Reject(() => Installer.ArchivePurgedState(stateRoot, manager, previous, next, true, () => {}));
        Assert(File.Exists(Path.Combine(stateRoot, "state.json")) && File.Exists(Path.Combine(history, "state.json")));
        Safe.RemoveTree(sandbox, sandbox);
        Console.WriteLine("native_reinstall_filesystem_passed=true");
    }
}

// Explicit test entry point. Never calls Installer/SCM/Task Scheduler/registry writes.
using System;
using System.IO;
using System.IO.Compression;
using CloudSoc.Native;

internal static class NativeInstallerTests {
    private static int count;
    private static void Assert(bool value) { count++; if (!value) throw new Exception("assertion_" + count); }
    private static void Reject(Action action) { bool rejected = false; try { action(); } catch (InvalidDataException) { rejected = true; } Assert(rejected); }
    public static int Main(string[] args) {
        string root = Path.Combine(Path.GetTempPath(), "cloud-soc-contract-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try {
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
            Console.WriteLine("native_contracts_passed=" + count); return 0;
        } finally {
            // Only files created above in this fresh, named test directory.
            Safe.Path(root); foreach (var file in Directory.GetFiles(root)) { Safe.Path(file); File.Delete(file); } Directory.Delete(root, false);
        }
    }
}

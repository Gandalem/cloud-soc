using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Threading;

namespace CloudSoc.Native {
internal sealed class Installer {
    internal const string Version = "9.5.2";
    internal const string BeatSha512 = "cdb07ad1e39e7c65cefcd7c71e1dfcfa4f92b00daafc132c78490e3e04f664f67403cdb925c5873a8441058d6de08d29790bf6776748edc63582f50174c508c8";
    internal static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloud-SOC-Agent");
    internal static readonly string StateRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Cloud-SOC-Native");
    internal static readonly string Manager = Path.Combine(StateRoot, "cloud-soc-agent.exe");
    private static readonly string StatePath = Path.Combine(StateRoot, "state.json"), SecretPath = Path.Combine(StateRoot, "session.dpapi");
    internal static string Beat(string root) { return Path.Combine(root, "filebeat-" + Version + "-windows-x86_64", "filebeat.exe"); }
    private Dictionary<string, object> state, secret, spec;
    private Action<string> report;
    internal Installer(Action<string> report) { this.report = report; }
    private void Phase(string phase) { state["phase"] = phase; state["updated_at"] = DateTime.UtcNow.ToString("o"); Safe.Json(StatePath, state); report(phase); }
    internal static Dictionary<string, object> Load() { Safe.CheckAcl(StatePath); var value = Contract.Parse(Contract.Utf8.GetString(Safe.Read(StatePath, 131072))); Contract.Require(Convert.ToInt32(value["schema"]) == 1 && Object.Equals(value["root"], Root), "state_schema"); return value; }
    internal static void Verify(Dictionary<string, object> state) {
        Safe.CheckAcl(StateRoot); Safe.CheckAcl(Root);
        var files = (Dictionary<string, object>)state["files"];
        foreach (var file in files) { string path = Path.Combine(Root, file.Key); Safe.CheckAcl(path); Contract.Require(Contract.FileHash(path) == (string)file.Value, "installed_integrity"); }
        Safe.CheckAcl(Manager); Contract.Require(Contract.FileHash(Manager) == (string)state["manager_sha256"], "manager_integrity");
    }
    private static byte[] Resource(string name) {
        using (var input = typeof(Installer).Assembly.GetManifestResourceStream(name)) using (var output = new MemoryStream()) { Contract.Require(input != null, "resource_missing"); input.CopyTo(output); return output.ToArray(); }
    }
    private Dictionary<string, object> Request(string action, object body) {
        for (int n = 0; n < 3; n++) {
            CloudSocEnrollmentResponse response = null;
            try { response = CloudSocEnrollmentHttp.Post((string)spec["portal_url"], "/api/installer/" + action, Path.Combine(Root, "ca.crt"), false, (string)secret["token"], Contract.Json.Serialize(body)); }
            catch { if (n == 2) throw new IOException("enrollment_tls_or_network"); }
            if (response != null && response.Status == 200) return Contract.Parse(response.Body);
            if (response != null && response.Status != 409 && response.Status != 503) throw new IOException("enrollment_http_" + response.Status);
            Thread.Sleep(2000);
        }
        throw new IOException("enrollment_unconfirmed");
    }
    private static void NoExisting() {
        Safe.Path(Root); Safe.Path(StateRoot);
        Contract.Require(!Directory.Exists(Root) && !Platform.TaskExists(), "existing_installation");
        Contract.Require(!File.Exists(Root), "existing_installation");
        foreach (var name in new[] {Platform.Service, "cloud-soc-winlogbeat", "winlogbeat", "filebeat", "elastic-agent"}) {
            using (var service = new ServiceController(name)) { bool exists; try { var status = service.Status; exists = true; } catch (InvalidOperationException) { exists = false; } Contract.Require(!exists, "existing_service"); }
        }
        foreach (var name in new[] {"filebeat", "winlogbeat", "elastic-agent"}) Contract.Require(Process.GetProcessesByName(name).Length == 0, "existing_process");
        foreach (var path in new[] {Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Filebeat"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Filebeat-Data"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "filebeat"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Winlogbeat"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Winlogbeat-Data"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Elastic"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "winlogbeat")}) Contract.Require(!Directory.Exists(path), "existing_collector_directory");
    }
    internal static void ArchivePurgedState(string stateRoot, string manager, Dictionary<string, object> previous, Dictionary<string, object> registration, bool lab, Action noExisting) {
        string name = Contract.ReinstallHistoryName(previous, registration, lab);
        Safe.CheckAcl(stateRoot); Safe.CheckAcl(manager);
        Contract.Require(Contract.FileHash(manager) == (string)previous["manager_sha256"], "manager_integrity");
        // A terminal state must contain no retained queues, credentials or unfinished purge tree.
        var allowed = new[] {"state.json", "cloud-soc-agent.exe", "diagnostic.json"};
        foreach (string entry in Directory.GetFileSystemEntries(stateRoot)) {
            Safe.CheckAcl(entry);
            Contract.Require(File.Exists(entry) && allowed.Contains(Path.GetFileName(entry), StringComparer.OrdinalIgnoreCase), "reinstall_state_residue");
        }
        string running = Path.GetFullPath(typeof(Installer).Assembly.Location);
        Contract.Require(!running.StartsWith(Path.GetFullPath(stateRoot) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "reinstall_use_new_bundle");
        noExisting();
        string history = stateRoot + "-History", destination = Path.Combine(history, name);
        Safe.Path(history); Safe.Path(destination);
        if (!Directory.Exists(history)) Safe.Protected(history); else Safe.CheckAcl(history);
        Contract.Require(!Directory.Exists(destination) && !File.Exists(destination), "reinstall_history_exists");
        // Same-volume directory rename: either the previous state remains, or its complete history does.
        // No old receipt/token is copied into the new installation, and no history is overwritten.
        noExisting(); Directory.Move(stateRoot, destination);
    }
    internal void Install(string bundle, bool lab) {
        Safe.Path(bundle);
        string archive = Path.Combine(bundle, "package.zip"); var registration = Contract.Parse(Contract.Utf8.GetString(Safe.Read(Path.Combine(bundle, "registration.json"), 16384)));
        byte[] packageBytes = Safe.Read(archive, 8388608);
        Contract.Require(Contract.Hash(packageBytes) == Contract.Text(registration, "package_sha256", "[a-f0-9]{64}"), "package_hash");
        // Hash and parsing share the SAME immutable byte snapshot; no path-reopen race.
        var members = Contract.Archive(packageBytes, 8388608);
        spec = Contract.ValidatePackage(Contract.Parse(Contract.Utf8.GetString(members["package.json"])), registration);
        var profile = Contract.Parse(Contract.Utf8.GetString(members["collection-profile.json"]));
        Contract.Require(Convert.ToInt32(profile["schema"]) == 1 && Object.Equals(profile["platform"], "windows") && !Contract.Flag(profile, "network") && Contract.Flag(profile, "system") == Contract.Flag(spec, "system"), "profile_binding");
        if (lab) { LabOrigin((string)spec["endpoint"]); LabOrigin((string)spec["portal_url"]); }
        if (File.Exists(StatePath)) {
            var previous = Load();
            if (Object.Equals(previous["phase"], "purged")) {
                Contract.Require(new DriveInfo(Path.GetPathRoot(Root)).AvailableFreeSpace >= 4L * 1024 * 1024 * 1024, "disk_capacity");
                ArchivePurgedState(StateRoot, Manager, previous, registration, lab, NoExisting);
                report("이전 제거 이력을 보존했습니다. 새 장치 등록으로 설치합니다. 이전 키·큐는 복원하지 않습니다.");
            } else if (Object.Equals(previous["phase"], "removed")) throw new IOException("reinstall_preserved_data");
        }
        if (File.Exists(StatePath)) {
            state = Load(); Contract.Require(Object.Equals(state["device_id"], registration["device_id"]) && Object.Equals(state["package_sha256"], registration["package_sha256"]) && Object.Equals(state["enrollment_id"], registration["enrollment_id"]) && Object.Equals(state["lab"], lab), "existing_binding");
            string phase = (string)state["phase"];
            if (phase == "complete") { Verify(state); if (File.Exists(SecretPath)) File.Delete(SecretPath); RegisterUninstaller(); report("이미 설치와 중앙 수신 확인이 완료된 장치입니다."); return; }
            Contract.Require(new[] {"reserved", "exchanging", "session_saved", "prepared", "starting", "awaiting_receipt"}.Contains(phase), "recovery_requires_review");
            Verify(state); secret = Safe.Unseal(SecretPath);
            Contract.Require(Object.Equals(secret["token"], registration["token"]), "registration_changed");
            if (Platform.Exists()) Platform.SetRunning(Root, false);
            if (Platform.TaskExists()) Platform.OwnTask(Manager);
        } else {
            Contract.Require(!Directory.Exists(StateRoot), "existing_partial_state"); NoExisting();
            Contract.Require(new DriveInfo(Path.GetPathRoot(Root)).AvailableFreeSpace >= 4L * 1024 * 1024 * 1024, "disk_capacity");
            Safe.Protected(StateRoot); Safe.Protected(Root);
            state = Contract.Map("schema", 1, "root", Root, "device_id", registration["device_id"], "enrollment_id", registration["enrollment_id"], "package_sha256", registration["package_sha256"], "lab", lab, "files", Contract.Map());
            // From here, every interrupted operation is retained, never silently adopted.
            Phase("preparing");
            File.Copy(typeof(Installer).Assembly.Location, Manager, false); Safe.CheckAcl(Manager); state["manager_sha256"] = Contract.FileHash(Manager);
            Safe.Json(StatePath, state);
            foreach (var directory in new[] {"data", "logs", "inputs"}) Safe.Protected(Path.Combine(Root, directory));
            foreach (var name in new[] {"privacy.js", "site-privacy.js", "security-catalog.json"}) Safe.Atomic(Path.Combine(Root, name), Resource(name));
            foreach (var name in new[] {"ca.crt", "collection-profile.json"}) Safe.Atomic(Path.Combine(Root, name), members[name]);
            Safe.Json(Path.Combine(Root, "discovery-settings.json"), Contract.Map("log_roots", new[] {Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\LogFiles\Firewall")}, "required_channels", new string[0]));
            var files = (Dictionary<string, object>)state["files"];
            foreach (var name in new[] {"privacy.js", "site-privacy.js", "security-catalog.json", "ca.crt", "collection-profile.json", "discovery-settings.json"}) files[name] = Contract.FileHash(Path.Combine(Root, name));
            Safe.Json(StatePath, state);
            CloudSocTlsProbe.Check((string)spec["endpoint"], Path.Combine(Root, "ca.crt"), false);
            // Portal TLS is checked before issuing anything. This request-free probe accepts 200/401 only.
            // The POST helper below still enforces hostname, pinned CA and online revocation independently.
            DownloadBeat();
            files["filebeat-" + Version + "-windows-x86_64\\filebeat.exe"] = Contract.FileHash(Beat(Root));
            secret = Contract.Map("token", registration["token"], "attempt", Contract.Random()); Safe.Seal(SecretPath, secret); Phase("reserved");
        }
        bool verified = false;
        try {
            if (!secret.ContainsKey("reply")) {
                Phase("exchanging");
                var reply = Request("enroll", Contract.Map("attempt", secret["attempt"], "package_id", spec["package_id"], "package_sha256", registration["package_sha256"]));
                Contract.Session(reply, spec, (string)registration["enrollment_id"]); secret["reply"] = reply; Safe.Seal(SecretPath, secret); Phase("session_saved");
            }
            var session = (Dictionary<string, object>)secret["reply"]; var key = Contract.Session(session, spec, (string)registration["enrollment_id"]);
            Configure((string)session["probe"]);
            Contract.Require(Platform.Run(Beat(Root), Platform.BeatArgs(Root) + " keystore create --force", null, 30000) == 0, "keystore_create");
            Contract.Require(Platform.Run(Beat(Root), Platform.BeatArgs(Root) + " keystore add CLOUD_SOC_API_KEY --stdin --force", (string)key["key"] + "\n", 30000) == 0, "keystore_write");
            Contract.Require(Platform.Run(Beat(Root), Platform.BeatArgs(Root) + " test config", null, 30000) == 0, "collector_config");
            Discovery.Refresh(Root, Discovery.Channels()); Phase("prepared");
            if (!Platform.Exists()) Platform.Create(Root); else Platform.OwnService(Root);
            if (!Platform.TaskExists()) Platform.Schedule(Manager); else Platform.OwnTask(Manager);
            Phase("starting"); Platform.SetRunning(Root, true); Phase("awaiting_receipt");
            Receipt(session); verified = true;
            // A failed commit here retains the sealed same session for a receipt-only retry.
            Phase("complete"); File.Delete(SecretPath); RegisterUninstaller(); report("설치와 중앙 로그 수신 확인이 완료되었습니다.");
        } catch {
            if (!verified) {
                bool stopped = true;
                try { if (Platform.Exists()) Platform.SetRunning(Root, false); } catch { stopped = false; }
                try { var result = Request("abort", Contract.Map("attempt", secret["attempt"])); Contract.Require(Object.Equals(result["state"], "cancelled") || Object.Equals(result["state"], "failed"), "abort_result"); Phase(stopped ? "aborted" : "abort_stop_unconfirmed"); }
                catch { Phase("revocation_unconfirmed"); }
            }
            throw;
        }
    }
    internal static void LabOrigin(string value) {
        var uri = new Uri(Contract.Origin(value)); IPAddress ip;
        Contract.Require(IPAddress.TryParse(uri.Host, out ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork, "lab_ip_required");
        var b = ip.GetAddressBytes(); Contract.Require(b[0] == 127 || b[0] == 10 || b[0] == 192 && b[1] == 168 || b[0] == 172 && b[1] >= 16 && b[1] <= 31, "lab_private_only");
    }
    private void DownloadBeat() {
        string zipPath = Path.Combine(Root, "filebeat.zip");
        var request = (HttpWebRequest)WebRequest.Create("https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-" + Version + "-windows-x86_64.zip");
        request.AllowAutoRedirect = false; request.Timeout = 30000; request.ReadWriteTimeout = 30000;
        using (var response = (HttpWebResponse)request.GetResponse()) {
            Contract.Require(response.StatusCode == HttpStatusCode.OK && response.ContentLength <= 209715200, "download_status_or_size");
            using (var input = response.GetResponseStream()) using (var output = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                byte[] buffer = new byte[65536]; long total = 0; int count; var timer = Stopwatch.StartNew();
                while ((count = input.Read(buffer, 0, buffer.Length)) > 0) { total += count; Contract.Require(total <= 209715200 && timer.Elapsed.TotalMinutes < 10, "download_limit"); output.Write(buffer, 0, count); } output.Flush(true);
            }
        }
        using (var sha = SHA512.Create()) using (var file = File.OpenRead(zipPath)) Contract.Require(Contract.Hex(sha.ComputeHash(file)) == BeatSha512, "filebeat_sha512");
        using (var zip = ZipFile.OpenRead(zipPath)) {
            long size = 0; Contract.Require(zip.Entries.Count <= 10000, "beat_archive_count");
            foreach (var entry in zip.Entries) {
                var relative = entry.FullName.Replace('/', '\\'); string target = Path.GetFullPath(Path.Combine(Root, relative));
                Contract.Require(relative.StartsWith("filebeat-" + Version + "-windows-x86_64\\", StringComparison.Ordinal) && target.StartsWith(Root + "\\filebeat-" + Version + "-windows-x86_64\\", StringComparison.OrdinalIgnoreCase) && !relative.Split('\\').Any(p => p == ".." || p.Contains(":")), "beat_archive_path");
                size += entry.Length; Contract.Require(size < 2L * 1024 * 1024 * 1024, "beat_archive_size"); Safe.Path(target);
                if (entry.Name == "") Directory.CreateDirectory(target); else { Directory.CreateDirectory(Path.GetDirectoryName(target)); entry.ExtractToFile(target, false); }
            }
        }
        File.Delete(zipPath); Safe.CheckAcl(Beat(Root));
    }
    private void Configure(string probe) {
        var processors = new object[] {
            Contract.Map("add_host_metadata", Contract.Map()), Contract.Map("add_fields", Contract.Map("target", "organization", "fields", Contract.Map("id", spec["organization"]))),
            Contract.Map("script", Contract.Map("lang", "javascript", "file", "privacy.js", "timeout", "50ms", "tag_on_exception", "_privacy_error")),
            Contract.Map("drop_event", Contract.Map("when", Contract.Map("contains", Contract.Map("tags", "_privacy_error")))),
            Contract.Map("add_fields", Contract.Map("target", "labels", "fields", Contract.Map("installation_probe", probe))) };
        var config = Contract.Map("filebeat.config.inputs", Contract.Map("enabled", true, "path", Path.Combine(Root, @"inputs\*.yml"), "reload.enabled", true, "reload.period", "10s"), "processors", processors,
            "output.elasticsearch", Contract.Map("hosts", new[] {(string)spec["endpoint"]}, "api_key", "${CLOUD_SOC_API_KEY}", "ssl.certificate_authorities", new[] {Path.Combine(Root, "ca.crt")}, "ssl.verification_mode", "full", "index", "soc-host-raw-windows-" + Version + "-%{+yyyy.MM.dd}", "indices", new[] {Contract.Map("index", "soc-agent-health-%{+yyyy.MM.dd}", "when.equals", Contract.Map("labels.log_source", "agent_health"))}, "timeout", 30),
            "setup.ilm.enabled", false, "setup.template.enabled", false, "logging.level", "info", "logging.to_files", true, "logging.to_eventlog", false, "queue.disk", Contract.Map("max_size", "1GB"));
        Safe.Json(Path.Combine(Root, "filebeat.yml"), config);
        ((Dictionary<string, object>)state["files"])["filebeat.yml"] = Contract.FileHash(Path.Combine(Root, "filebeat.yml"));
        Safe.Json(StatePath, state);
    }
    private void Receipt(Dictionary<string, object> session) {
        var timer = Stopwatch.StartNew(); string agent = null;
        while (timer.Elapsed.TotalSeconds < 180) {
            Platform.OwnService(Root);
            using (var service = new ServiceController(Platform.Service)) Contract.Require(service.Status == ServiceControllerStatus.Running, "collector_stopped");
            string meta = Path.Combine(Root, @"data\meta.json");
            if (File.Exists(meta)) { agent = Contract.Text(Contract.Parse(Contract.Utf8.GetString(Safe.Read(meta, 4096))), "uuid", "[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}"); break; }
            Thread.Sleep(500);
        }
        Contract.Require(agent != null, "collector_identity_timeout");
        string eventPath = Path.Combine(Root, "installation-probe.ndjson"), inputPath = Path.Combine(Root, @"inputs\installation-probe.yml");
        if (!File.Exists(eventPath) && !File.Exists(inputPath)) {
            Safe.Atomic(eventPath, Contract.Utf8.GetBytes(Contract.Json.Serialize(Contract.Map("@timestamp", DateTime.UtcNow.ToString("o"), "event", Contract.Map("action", "installation_probe", "kind", "event"), "labels", Contract.Map("installation_probe", session["probe"]), "message", "Cloud SOC installation verification. " + new string('x', 1100))) + "\n"));
            Safe.Json(inputPath, new[] {Contract.Map("type", "filestream", "id", "installation-" + spec["package_id"], "paths", new[] {eventPath}, "parsers", new[] {Contract.Map("ndjson", Contract.Map("target", "", "add_error_key", true))})});
        } else Contract.Require(File.Exists(eventPath) && File.Exists(inputPath), "probe_partial_state");
        while (timer.Elapsed.TotalSeconds < 180) {
            Platform.OwnService(Root); using (var service = new ServiceController(Platform.Service)) Contract.Require(service.Status == ServiceControllerStatus.Running, "collector_stopped");
            var reply = Request("receipt", Contract.Map("attempt", secret["attempt"], "agents", Contract.Map("host", agent)));
            if (Object.Equals(reply["verified"], true) && Object.Equals(reply["state"], "complete") && Object.Equals(reply["id"], session["id"])) return;
            report("중앙 로그 수신을 기다리는 중입니다."); Thread.Sleep(5000);
        }
        throw new IOException("receipt_timeout");
    }
    private void RegisterUninstaller() {
        using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CloudSOCNativeCollector")) {
            key.SetValue("DisplayName", "Cloud SOC Agent"); key.SetValue("DisplayVersion", "1.0.0"); key.SetValue("Publisher", "Cloud SOC"); key.SetValue("UninstallString", Platform.Quote(Manager) + " --uninstall" + (Object.Equals(state["lab"], true) ? " --lab" : "")); key.SetValue("NoModify", 1); key.SetValue("NoRepair", 1);
        }
    }
    internal void Manage(string action, bool purge) {
        state = Load(); string phase = (string)state["phase"];
        if (action == "status") {
            string serviceStatus = "없음";
            if (Platform.Exists()) { Platform.OwnService(Root); using (var service = new ServiceController(Platform.Service)) serviceStatus = service.Status.ToString(); }
            if (Platform.TaskExists()) Platform.OwnTask(Manager);
            report("설치 기록: " + phase + " / 현재 수집 서비스: " + serviceStatus + ". 중앙 키 폐기·일반 로그·경보 상태는 포털에서 확인하세요."); return;
        }
        if (action == "uninstall" && (phase == "purged" || phase == "removed" && !purge)) { report("수집기 제거가 이미 완료되었습니다. 서버 키 폐기는 포털에서 확인하세요."); return; }
        Contract.Require(phase != "purged" && (phase != "removed" || action == "uninstall" && purge), "collector_removed");
        if (phase != "purging") Verify(state);
        if (action == "refresh") { Contract.Require(phase == "complete", "installation_incomplete"); Discovery.Refresh(Root, Discovery.Channels()); return; }
        if (action == "start" || action == "stop") { Contract.Require(phase == "complete", "installation_incomplete"); Platform.SetRunning(Root, action == "start"); report(action == "start" ? "수집기를 시작했습니다." : "수집기를 중지했습니다."); return; }
        Contract.Require(action == "uninstall", "unknown_action");
        // Plan is persisted before each destructive step; retries do not claim success.
        bool retry = phase == "removing" || phase == "purging"; if (retry) Contract.Require(Object.Equals(state["purge"], purge), "uninstall_intent_changed");
        if (phase == "purging") {
            Safe.CheckAcl(StateRoot); Safe.CheckAcl(Manager); Contract.Require(Contract.FileHash(Manager) == (string)state["manager_sha256"] && !Platform.Exists() && !Platform.TaskExists(), "purge_recovery_boundary");
            if (Directory.Exists(Root)) Verify(state);
        }
        if (Platform.Exists()) Platform.OwnService(Root); if (Platform.TaskExists()) Platform.OwnTask(Manager);
        state["purge"] = purge; if (phase != "purging") Phase("removing");
        if (Platform.TaskExists()) Platform.DeleteTask(Manager);
        if (Platform.Exists()) Platform.Remove(Root);
        Contract.Require(!Platform.TaskExists() && !Platform.Exists(), "uninstall_service_pending");
        // Keep protected manager/audit so uncertain remote revocation is never hidden.
        // Default retains the ENTIRE collector tree, including keystore/queue; no reinstall adoption.
        if (purge) {
            string retired = Path.Combine(StateRoot, "retired-" + Contract.Text(state, "device_id", "[a-f0-9]{32}"));
            if (phase != "purging") {
                Contract.Require(!Directory.Exists(retired) && Path.GetPathRoot(Root) == Path.GetPathRoot(retired), "purge_destination");
                // Persist intent before rename; a crash before rename is distinguishable.
                Phase("purging");
            }
            if (Directory.Exists(Root)) { Contract.Require(!Directory.Exists(retired), "purge_destination"); Directory.Move(Root, retired); }
            if (Directory.Exists(retired)) Safe.RemoveTree(retired, retired);
        }
        if (File.Exists(SecretPath)) { Safe.Path(SecretPath); File.Delete(SecretPath); }
        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", true)) if (key != null) key.DeleteSubKeyTree("CloudSOCNativeCollector", false);
        Phase(purge ? "purged" : "removed");
        report(purge ? "수집기·로컬 큐를 삭제했습니다. 보호된 관리 도구와 작업 이력은 남아 있습니다." : "수집기를 제거했습니다. 재전송 자료·큐·관리 도구는 보호된 경로에 보존했습니다.");
        report("서버 키는 자동 폐기하지 않았습니다. 포털에서 이 장치를 종료하세요.");
        if (purge) report("다시 설치하려면 포털에서 새 장치를 등록하고 새 설치 묶음을 실행하세요. 읽기 위치 삭제로 기존 로그가 다시 수집될 수 있습니다.");
    }
}
}

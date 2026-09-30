// cloud-soc-policy-format: 1
// Independent worker: no PowerShell hosting, subprocesses, network or credentials.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal static class Discovery {
    internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16777216 };
    internal static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    internal static string Stage = "arguments";
    internal static Dictionary<string, object> Map(params object[] values) {
        var result = new Dictionary<string, object>();
        for (int i = 0; i < values.Length; i += 2) result.Add((string)values[i], values[i + 1]);
        return result;
    }
    internal static string Id(string value) {
        using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(Utf8.GetBytes(value.ToLowerInvariant()))).Replace("-", "").ToLowerInvariant();
    }
    internal static string LocalPath(string value) {
        if (String.IsNullOrWhiteSpace(value) || !Regex.IsMatch(value, @"^[a-zA-Z]:\\") || Regex.IsMatch(value, "[\\x00-\\x1f\"${}*?\\[\\]]|(^|[\\\\/])\\.\\.?([\\\\/]|$)")) throw new InvalidDataException("invalid_path");
        return Path.GetFullPath(value).TrimEnd('\\');
    }
    internal static bool Linked(string value) {
        for (string path = value; !String.IsNullOrEmpty(path); path = Path.GetDirectoryName(path)) {
            try { if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return true; }
            catch (FileNotFoundException) {} catch (DirectoryNotFoundException) {}
        }
        return false;
    }
    internal static string LogRoot(string value, string outputRoot) {
        string path = LocalPath(value);
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string[] forbidden = { Path.GetPathRoot(path).TrimEnd('\\'), windows, Path.Combine(windows, "System32"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) };
        if (forbidden.Any(p => String.Equals(path, p, StringComparison.OrdinalIgnoreCase)) || Regex.IsMatch(path, @"^[a-zA-Z]:\\Users(\\|$)", RegexOptions.IgnoreCase) || Under(path, outputRoot) || Under(path, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloud-SOC-Agent"))) throw new InvalidDataException("forbidden_log_root");
        return path;
    }
    internal static bool Under(string path, string parent) { return String.Equals(path, parent, StringComparison.OrdinalIgnoreCase) || path.StartsWith(parent.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
    internal static string EncodingOf(string path) {
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
            var bytes = new byte[8192]; int size = stream.Read(bytes, 0, bytes.Length);
            if (size == 0) return "empty_pending";
            if (size >= 4 && bytes[0] == 255 && bytes[1] == 254 && bytes[2] == 0 && bytes[3] == 0) return "unsupported_encoding";
            if (size >= 2 && bytes[0] == 255 && bytes[1] == 254) return "utf-16le-bom";
            if (size >= 2 && bytes[0] == 254 && bytes[1] == 255) return "utf-16be-bom";
            for (int i = 0; i < size; i++) if (bytes[i] < 32 && bytes[i] != 9 && bytes[i] != 10 && bytes[i] != 12 && bytes[i] != 13) return "binary";
            try { Utf8.GetDecoder().GetChars(bytes, 0, size, new char[8192], 0, stream.Position == stream.Length); }
            catch (DecoderFallbackException) { return "unsupported_encoding"; }
            return "utf-8";
        }
    }
    internal static void Write(string path, string text) {
        if (Linked(path)) throw new InvalidDataException("linked_output");
        if (File.Exists(path) && File.ReadAllText(path, Utf8) == text) return;
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { byte[] data = Utf8.GetBytes(text); stream.Write(data, 0, data.Length); stream.Flush(true); }
            if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
        } finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    internal static string[] Strings(object value) {
        if (value is string || !(value is IEnumerable)) throw new InvalidDataException("expected_string_array");
        var result = new List<string>();
        foreach (object entry in (IEnumerable)value) { if (!(entry is string)) throw new InvalidDataException("expected_string"); result.Add((string)entry); }
        return result.ToArray();
    }
    internal static string ReadBounded(string path, long maximum) {
        if (Linked(path) || new FileInfo(path).Length > maximum) throw new InvalidDataException("invalid_input_file");
        return File.ReadAllText(path, Utf8);
    }
    internal static IEnumerable<Dictionary<string, object>> Channels() {
        var result = new List<Dictionary<string, object>>();
        foreach (string name in EventLogSession.GlobalSession.GetLogNames().OrderBy(n => n, StringComparer.OrdinalIgnoreCase)) {
            string status;
            try {
                using (var config = new EventLogConfiguration(name)) {
                    status = !config.IsEnabled ? "disabled" : config.LogType == EventLogType.Analytical || config.LogType == EventLogType.Debug ? "unsupported_direct_channel" : Regex.IsMatch(name, "[\\x00-\\x1f${}]") ? "unsafe_name" : "selected";
                }
            } catch (UnauthorizedAccessException) { status = "enumeration_error"; }
              catch (EventLogException) { status = "enumeration_error"; }
            result.Add(Map("kind", "channel", "name", name, "status", status));
        }
        return result;
    }
    internal static void Refresh(string root, IEnumerable<Dictionary<string, object>> channels) {
        root = LocalPath(root);
        if (!Directory.Exists(root) || !Directory.Exists(Path.Combine(root, "inputs")) || Linked(root)) throw new InvalidDataException("invalid_output_root");
        Stage = "lock";
        string lockPath = Path.Combine(root, "discovery.lock");
        if (Linked(lockPath)) throw new InvalidDataException("linked_lock");
        using (var held = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None)) {
            Stage = "settings";
            var settings = Json.Deserialize<Dictionary<string, object>>(ReadBounded(Path.Combine(root, "discovery-settings.json"), 131072));
            string[] roots = Strings(settings["log_roots"]), required = Strings(settings["required_channels"]), exclusions = new string[0];
            int version = 0;
            string policy = Path.Combine(root, "collection-policy.txt");
            if (File.Exists(policy)) {
                string[] lines = ReadBounded(policy, 131072).Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                if (!Regex.IsMatch(lines[0], @"^version=[0-9]{1,9}$")) throw new InvalidDataException("invalid_policy_version");
                version = Int32.Parse(lines[0].Substring(8), CultureInfo.InvariantCulture);
                var selectedRoots = new List<string>(); var excludedRoots = new List<string>();
                for (int i = 1; i < lines.Length; i++) {
                    if (i == lines.Length - 1 && lines[i] == "") continue;
                    if (lines[i].StartsWith("root=")) selectedRoots.Add(LogRoot(lines[i].Substring(5), root));
                    else if (lines[i].StartsWith("exclude=")) excludedRoots.Add(LogRoot(lines[i].Substring(8), root));
                    else throw new InvalidDataException("invalid_policy_record");
                }
                if (selectedRoots.Count == 0) throw new InvalidDataException("empty_policy_roots");
                roots = selectedRoots.ToArray(); exclusions = excludedRoots.ToArray();
            }
            Stage = "channels";
            var entries = channels.ToList(); var inputs = new List<object>();
            var selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var channel in entries.Where(c => (string)c["status"] == "selected")) {
                string name = (string)channel["name"]; if (!selected.Add(name)) continue;
                inputs.Add(Map("type", "winlog", "id", "cloud-soc-event-" + Id(name), "name", name, "include_xml", false, "ignore_missing_channel", true, "fields_under_root", true, "fields", Map("labels", Map("log_source", "windows_event", "collection_mode", "auto_discovery"))));
            }
            if (selected.Count == 0 || required.Any(name => !selected.Contains(name))) throw new InvalidDataException("required_channel_missing");
            Stage = "files";
            var files = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string value in roots.Distinct(StringComparer.OrdinalIgnoreCase)) {
                string directory = LogRoot(value, root);
                if (Linked(directory) || !Directory.Exists(directory)) { entries.Add(Map("kind", "directory", "name", directory, "status", Linked(directory) ? "reparse_point" : "missing")); continue; }
                var pending = new Stack<string>(); pending.Push(directory);
                while (pending.Count > 0) {
                    directory = pending.Pop(); string[] children;
                    try { children = Directory.GetFileSystemEntries(directory); }
                    catch (IOException) { entries.Add(Map("kind", "directory", "name", directory, "status", "unreadable")); continue; }
                    catch (UnauthorizedAccessException) { entries.Add(Map("kind", "directory", "name", directory, "status", "unreadable")); continue; }
                    foreach (string path in children.OrderBy(p => p, StringComparer.OrdinalIgnoreCase)) {
                        if (!seen.Add(path)) continue;
                        string status = "selected", kind = "file";
                        try {
                            var attributes = File.GetAttributes(path);
                            if ((attributes & FileAttributes.Directory) != 0) kind = "directory";
                            if (Under(path, root) || Under(path, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloud-SOC-Agent")) || exclusions.Any(e => Under(path, e))) status = "policy_excluded";
                            else if ((attributes & FileAttributes.ReparsePoint) != 0) status = "reparse_point";
                            else if (Regex.IsMatch(path, "[\\x00-\\x1f$*?\\[\\]{}]")) status = "unsafe_path";
                            else if (kind == "directory") { pending.Push(path); continue; }
                            else if (Regex.IsMatch(path, @"\.(evtx|etl|gz|zip|7z|cab|dmp|db|sqlite|pem|key|crt|cer|der|pfx|p12|docx?|xlsx?|pdf|kdbx)$|[\\/](\.env|id_rsa|id_ed25519|id_ecdsa|credentials|secrets?)(\.|[\\/]|$)", RegexOptions.IgnoreCase)) status = "binary_archive_or_secret";
                            else {
                                string encoding = EncodingOf(path);
                                if (encoding != "utf-8" && encoding != "utf-16le-bom" && encoding != "utf-16be-bom") status = encoding;
                                else { if (!files.ContainsKey(encoding)) files.Add(encoding, new List<string>()); files[encoding].Add(path.Replace('\\', '/')); }
                            }
                        } catch (IOException) { status = "unreadable"; } catch (UnauthorizedAccessException) { status = "unreadable"; }
                        entries.Add(Map("kind", kind, "name", path, "status", status));
                    }
                }
            }
            foreach (var pair in files) inputs.Add(Map("type", "filestream", "id", "cloud-soc-windows-files-" + pair.Key + "-v2", "paths", pair.Value.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray(), "encoding", pair.Key, "prospector.scanner.symlinks", false, "file_identity.fingerprint", Map("growing", true), "fields_under_root", true, "fields", Map("labels", Map("log_source", "windows_file", "collection_mode", "auto_discovery"))));
            Stage = "publish";
            string generated = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            var report = Map("generated_at", generated, "entries", entries, "selected_channels", selected.Count, "worker", "native-v1");
            Write(Path.Combine(root, "inputs", "discovered.yml"), Json.Serialize(inputs));
            int good = entries.Count(e => (string)e["status"] == "selected"), errors = entries.Count(e => (string)e["status"] == "unreadable" || (string)e["status"] == "enumeration_error");
            var summary = Map("schema", 1, "generated_at", generated, "policy_version", version, "selected", good, "excluded", entries.Count - good - errors, "errors", errors, "total", entries.Count, "sources", entries.Take(200).Select(e => Map("id", Id((string)e["name"]), "status", e["status"])).ToArray(), "queue_state", "unknown", "transport_state", "unknown");
            summary["collector_metrics"] = CollectorMetrics.Read(root, DateTimeOffset.UtcNow);
            summary["rejection_evidence"] = RejectionEvidence.Run(root, DateTimeOffset.UtcNow);
            string spool = Path.Combine(root, "health.ndjson"), previous = Path.Combine(root, "health-previous.ndjson");
            if (Linked(spool) || Linked(previous)) throw new InvalidDataException("linked_spool");
            if (File.Exists(spool) && new FileInfo(spool).Length > 5242880) { if (File.Exists(previous)) File.Replace(spool, previous, null); else File.Move(spool, previous); }
            File.AppendAllText(spool, Json.Serialize(summary) + "\n", Utf8);
            var healthInput = new[] { Map("type", "filestream", "id", "cloud-soc-health-v1", "paths", new[] { Path.Combine(root, "health*.ndjson") }, "prospector.scanner.fingerprint.length", 64, "parsers", new[] { Map("ndjson", Map("target", "cloud_soc.discovery")) }, "fields_under_root", true, "fields", Map("labels", Map("log_source", "agent_health")), "processors", new[] { Map("drop_fields", Map("fields", new[] { "message" }, "ignore_missing", true)) }) };
            Write(Path.Combine(root, "inputs", "health.yml"), Json.Serialize(healthInput));
            Write(Path.Combine(root, "discovery-diagnostic.json"), Json.Serialize(Map("schema", 1, "generated_at", generated, "status", "ok", "worker", "native-v1", "stage", "complete")));
            Write(Path.Combine(root, "discovery-report.json"), Json.Serialize(report));
        }
    }
    public static int Main(string[] args) {
        string root = null;
        try {
            if (args.Length == 2 && args[0] == "--metrics-root") {
                Console.WriteLine(Json.Serialize(CollectorMetrics.Read(LocalPath(args[1]), DateTimeOffset.UtcNow)));
                return 0;
            }
            if (args.Length == 2 && args[0] == "--evidence-root") {
                Console.WriteLine(Json.Serialize(RejectionEvidence.Run(LocalPath(args[1]), DateTimeOffset.UtcNow)));
                return 0;
            }
            if (args.Length != 2 || args[0] != "--root") throw new ArgumentException("usage: cloud-soc-discovery.exe --root <protected-directory>");
            root = LocalPath(args[1]);
            Stage = "channels";
            Refresh(root, Channels());
            return 0;
        } catch (Exception error) {
            // Do not include paths, log text or configuration values in diagnostics.
            Console.Error.WriteLine("Discovery failed at {0} ({1}, HRESULT {2}).", Stage, error.GetType().Name, error.HResult);
            try { if (root != null && Directory.Exists(root) && !Linked(root)) Write(Path.Combine(root, "discovery-diagnostic.json"), Json.Serialize(Map("schema", 1, "generated_at", DateTime.UtcNow.ToString("o"), "status", "error", "stage", Stage, "error_type", error.GetType().Name, "hresult", error.HResult, "worker", "native-v1"))); } catch {}
            return 1;
        }
    }
}

// Monitoring logs contain interval deltas, not lifetime counters. Only numeric
// allowlisted fields leave the host; diagnostic event-data files are never read.
internal static class CollectorMetrics {
    internal static readonly string[][] Fields = {
        new[] {"queue_bytes", "libbeat.pipeline.queue.filled.bytes"},
        new[] {"queue_events", "libbeat.pipeline.queue.filled.events"},
        new[] {"queue_pct", "libbeat.pipeline.queue.filled.pct"},
        new[] {"queue_max_bytes", "libbeat.pipeline.queue.max_bytes"},
        new[] {"pipeline_active", "libbeat.pipeline.events.active"},
        new[] {"output_total", "libbeat.output.events.total"},
        new[] {"output_acked", "libbeat.output.events.acked"},
        new[] {"output_failed", "libbeat.output.events.failed"},
        new[] {"output_dropped", "libbeat.output.events.dropped"},
        new[] {"output_dead_letter", "libbeat.output.events.dead_letter"},
        new[] {"output_failure_store", "libbeat.output.events.failure_store"},
        new[] {"read_errors", "libbeat.output.read.errors"},
        new[] {"write_errors", "libbeat.output.write.errors"}
    };
    internal static object At(object value, string path) {
        foreach (string key in path.Split('.')) {
            var map = value as Dictionary<string, object>;
            if (map == null || !map.TryGetValue(key, out value)) return null;
        }
        return value;
    }
    internal static object Number(object value, bool fraction) {
        if (!(value is int || value is long || value is decimal || value is double)) return null;
        double number = Convert.ToDouble(value, CultureInfo.InvariantCulture);
        if (Double.IsNaN(number) || Double.IsInfinity(number) || number < 0 || number > (fraction ? 1 : 9007199254740991d) || (!fraction && Math.Floor(number) != number)) return null;
        return fraction ? (object)number : (object)Convert.ToInt64(number);
    }
    internal static Dictionary<string, object> Parse(string line) {
        string ignored;
        return Parse(line, out ignored);
    }
    internal static Dictionary<string, object> Parse(string line, out string reason) {
        reason = "line_limit";
        if (line.Length > 524288) return null;
        reason = "not_metrics";
        if (line.IndexOf("\"monitoring\"", StringComparison.Ordinal) < 0) return null;
        reason = "json";
        try {
            var entry = Discovery.Json.Deserialize<Dictionary<string, object>>(line);
            object value;
            reason = "identity";
            if (entry == null || !entry.TryGetValue("log.logger", out value) || !Object.Equals(value, "monitoring") ||
                !entry.TryGetValue("service.name", out value) || !Object.Equals(value, "filebeat")) return null;
            reason = "interval";
            if (!entry.TryGetValue("message", out value) || !(value is string)) return null;
            var interval = Regex.Match((string)value, @"^Non-zero metrics in the last ([1-9][0-9]{0,4})s$");
            if (!interval.Success || !entry.TryGetValue("@timestamp", out value) || !(value is string)) return null;
            if (Int32.Parse(interval.Groups[1].Value, CultureInfo.InvariantCulture) > 86400) return null;
            DateTimeOffset sampled;
            reason = "timestamp";
            if (!DateTimeOffset.TryParse((string)value, CultureInfo.InvariantCulture, DateTimeStyles.None, out sampled)) return null;
            var metrics = At(entry, "monitoring.metrics") as Dictionary<string, object>;
            reason = "metrics_object";
            if (metrics == null) return null;
            var result = Discovery.Map("schema", 1, "state", "observed", "sampled_at", sampled.UtcDateTime.ToString("o"),
                "interval_seconds", Int32.Parse(interval.Groups[1].Value, CultureInfo.InvariantCulture), "counter_scope", "logged_interval_delta");
            foreach (var field in Fields) result[field[0]] = Number(At(metrics, field[1]), field[0] == "queue_pct");
            reason = "ok";
            return result;
        } catch (ArgumentException) { return null; } catch (InvalidOperationException) { return null; }
    }
    internal static bool Problem(Dictionary<string, object> sample) {
        return new[] {"output_dropped", "output_failed", "output_dead_letter", "output_failure_store", "read_errors", "write_errors"}
            .Any(key => sample[key] != null && Convert.ToDouble(sample[key]) > 0);
    }
    internal static Dictionary<string, object> Read(string root, DateTimeOffset now) {
        var missing = Discovery.Map("schema", 1, "state", "unavailable", "reason", "no_sample");
        string logs = Path.Combine(root, "logs");
        Dictionary<string, object> latest = null;
        DateTimeOffset latestTime = DateTimeOffset.MinValue, problemTime = DateTimeOffset.MinValue;
        bool partial = false;
        var skipped = new Dictionary<string, int>();
        try {
            if (Discovery.Linked(logs)) { missing["reason"] = "unsafe_path"; return missing; }
            if (!Directory.Exists(logs)) { missing["reason"] = "no_logs"; return missing; }
            var files = Directory.EnumerateFiles(logs, "filebeat-*.ndjson").Take(129).ToArray();
            if (files.Length > 128) { missing["reason"] = "too_many_files"; return missing; }
            var candidates = files.Where(p => Regex.IsMatch(Path.GetFileName(p), @"^filebeat-[0-9]{8}(?:-[0-9]+)?\.ndjson$"))
                .OrderByDescending(p => File.GetLastWriteTimeUtc(p)).ToArray();
            partial = candidates.Length > 4;
            foreach (string file in candidates.Take(4)) {
                if (Discovery.Linked(file)) { partial = true; continue; }
                try {
                    using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                        long start = Math.Max(0, stream.Length - 1048576);
                        partial |= start > 0;
                        stream.Seek(start, SeekOrigin.Begin);
                        var bytes = new byte[1048576]; int size = 0, count;
                        while (size < bytes.Length && (count = stream.Read(bytes, size, bytes.Length - size)) > 0) size += count;
                        string[] lines = Encoding.UTF8.GetString(bytes, 0, size).Split('\n');
                        // A capped prefix or unfinished trailing line is not a complete record.
                        for (int i = start > 0 ? 1 : 0; i < lines.Length - 1; i++) {
                            string reason;
                            var sample = Parse(lines[i], out reason);
                            if (sample == null) {
                                if (reason != "not_metrics") partial = true;
                                if (!skipped.ContainsKey(reason)) skipped[reason] = 0;
                                skipped[reason]++;
                                continue;
                            }
                            var at = DateTimeOffset.Parse((string)sample["sampled_at"], CultureInfo.InvariantCulture);
                            if (at > latestTime) { latest = sample; latestTime = at; }
                            if (at >= now.AddMinutes(-30) && at <= now.AddSeconds(60) && at > problemTime && Problem(sample)) problemTime = at;
                        }
                    }
                } catch (IOException) { partial = true; } catch (UnauthorizedAccessException) { partial = true; }
            }
        } catch (IOException) { missing["reason"] = "read_error"; partial = true; }
          catch (UnauthorizedAccessException) { missing["reason"] = "read_error"; partial = true; }
        var result = latest ?? missing;
        result["scan_partial"] = partial;
        result["skipped_records"] = skipped;
        result["last_problem_at"] = problemTime == DateTimeOffset.MinValue ? null : (object)problemTime.UtcDateTime.ToString("o");
        return result;
    }
}

// Local administrator evidence only. No network, event export or replay.

internal static class RejectionEvidence {
    internal const int MaxBytes = 16777216, MaxRecords = 2000, Days = 7;
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileIdentity {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out FileIdentity info);
    internal static void SingleLink(string path) {
        if (Directory.Exists(path)) return;
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
            FileIdentity info;
            if (!GetFileInformationByHandle(file.SafeFileHandle, out info) || info.Links != 1) throw new InvalidDataException("evidence_hardlink");
        }
    }
    internal static readonly Regex SecretKey = new Regex(@"password|passwd|pwd|secret|token|authorization|cookie|private[_-]?key|command[_-]?line|task[_-]?content|script[_-]?(block[_-]?text|contents?)|(^|[._-])(api[_-]?key|args|original|xml|body|content)($|[._-])", RegexOptions.IgnoreCase);
    internal static readonly Regex SecretText = new Regex(@"-----BEGIN [^-]*(PRIVATE KEY|CERTIFICATE)-----|(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*[""']?\s*[:=]|\b(Bearer|Basic)\s+\S+|https?://[^\s/]+@|https?://[^\s]*[?#]|\b(AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", RegexOptions.IgnoreCase);
    internal static string Stamp(DateTimeOffset time) { return time.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture); }
    internal static DateTimeOffset Time(object value) {
        string text = value as string;
        if (text == null || !Regex.IsMatch(text, @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$")) throw new InvalidDataException("timestamp");
        // Beats uses compact offsets; avoid machine-local time interpretation.
        text = Regex.Replace(text, @"([+-]\d{2})(\d{2})$", "$1:$2");
        text = Regex.Replace(text, @"(\.\d{7})\d{1,2}(?=Z|[+-])", "$1");
        return DateTimeOffset.Parse(text, CultureInfo.InvariantCulture);
    }
    internal static void Protected(string path) {
        if (Discovery.Linked(path)) throw new InvalidDataException("linked_evidence");
        SingleLink(path);
        FileSystemSecurity acl = Directory.Exists(path) ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
        string owner = acl.GetOwner(typeof(SecurityIdentifier)).Value;
        if (owner != "S-1-5-18" && owner != "S-1-5-32-544") throw new InvalidDataException("evidence_owner");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
            string sid = rule.IdentityReference.Value;
            if (rule.AccessControlType == AccessControlType.Allow && sid != "S-1-5-18" && sid != "S-1-5-32-544") throw new InvalidDataException("evidence_access");
        }
    }
    internal static string Text(object value) {
        string text = value as string;
        if (text == null || !Regex.IsMatch(text, @"^[A-Za-z0-9_. /-]{1,256}$") || SecretText.IsMatch(text)) throw new InvalidDataException("reference");
        return text;
    }
    internal static object Clean(object value, int depth, ref int nodes) {
        if (++nodes > 4096 || depth > 12) throw new InvalidDataException("privacy_limit");
        var map = value as Dictionary<string, object>;
        if (map != null) {
            var clean = new SortedDictionary<string, object>(StringComparer.Ordinal);
            foreach (var pair in map) {
                if (pair.Key == "@metadata" || SecretKey.IsMatch(pair.Key) || SecretText.IsMatch(pair.Key)) continue;
                clean[pair.Key] = Clean(pair.Value, depth + 1, ref nodes);
            }
            return clean;
        }
        if (value is string) return ((string)value).Length > 8192 || SecretText.IsMatch((string)value) ? "[REDACTED]" : value;
        if (value is IEnumerable) {
            var result = new List<object>();
            foreach (object item in (IEnumerable)value) result.Add(Clean(item, depth + 1, ref nodes));
            return result;
        }
        return value;
    }
    internal static string Mac(byte[] key, string text) {
        using (var hash = new System.Security.Cryptography.HMACSHA256(key)) return BitConverter.ToString(hash.ComputeHash(Discovery.Utf8.GetBytes(text))).Replace("-", "").ToLowerInvariant();
    }
    internal static int ObjectEnd(string message, int start) {
        if (start < 0 || start >= message.Length || message[start] != '{') throw new InvalidDataException("unsupported_diagnostic");
        bool quoted = false, escaped = false; int depth = 0;
        for (int n = start; n < message.Length; n++) {
            char c = message[n];
            if (escaped) { escaped = false; continue; }
            if (quoted && c == '\\') { escaped = true; continue; }
            if (c == '"') { quoted = !quoted; continue; }
            if (quoted) continue;
            if (c == '{' || c == '[') depth++;
            if (c == '}' || c == ']') {
                if (--depth == 0) {
                    return n;
                }
            }
        }
        throw new InvalidDataException("partial_diagnostic");
    }
    // Balanced JSON only; never regex-extract identifiers from arbitrary prose.
    internal static string EventJson(string message) {
        const string marker = "Cannot index event '";
        if (!message.StartsWith(marker, StringComparison.Ordinal)) throw new InvalidDataException("unsupported_diagnostic");
        int start = marker.Length, end = ObjectEnd(message, start);
        string tail = message.Substring(end + 1).TrimStart('\r', '\n');
        // 9.5 adds Meta after the event JSON. Validate framing, never retain Meta.
        if (tail.StartsWith(", Meta: none", StringComparison.Ordinal)) tail = tail.Substring(12);
        else if (tail.StartsWith(", Meta: {", StringComparison.Ordinal)) {
            int metaEnd = ObjectEnd(tail, 8);
            Discovery.Json.Deserialize<Dictionary<string, object>>(tail.Substring(8, metaEnd - 7));
            tail = tail.Substring(metaEnd + 1).TrimStart('\r', '\n');
        }
        if (!tail.StartsWith("' (status=400):", StringComparison.Ordinal)) throw new InvalidDataException("diagnostic_suffix");
        return message.Substring(start, end - start + 1);
    }
    internal static Dictionary<string, object> Parse(string line, byte[] key, DateTimeOffset now) {
        if (line.Length > 524288) throw new InvalidDataException("line_limit");
        var entry = Discovery.Json.Deserialize<Dictionary<string, object>>(line);
        object logger, message;
        if (!entry.TryGetValue("log.logger", out logger) || (string)logger != "elasticsearch" || !entry.TryGetValue("message", out message) || !(message is string) || !((string)message).Contains("Cannot index event")) return null;
        var rejected = Time(entry["@timestamp"]);
        if (rejected < now.AddDays(-Days) || rejected > now.AddMinutes(1)) return null;
        var data = Discovery.Json.Deserialize<Dictionary<string, object>>(EventJson((string)message));
        var winlog = (Dictionary<string, object>)data["winlog"];
        var evt = (Dictionary<string, object>)data["event"];
        var agent = (Dictionary<string, object>)data["agent"];
        Guid guid; string agentId = agent["id"] as string;
        if (!Guid.TryParse(agentId, out guid) || guid.ToString() != agentId) throw new InvalidDataException("agent_id");
        string number = Convert.ToString(winlog["record_id"], CultureInfo.InvariantCulture);
        long record;
        if (!Regex.IsMatch(number, @"^[1-9][0-9]{0,18}$") || !Int64.TryParse(number, out record)) throw new InvalidDataException("record_id");
        string code = Convert.ToString(evt["code"], CultureInfo.InvariantCulture);
        if (!Regex.IsMatch(code, @"^[0-9]{1,10}$")) throw new InvalidDataException("event_code");
        string occurred = Stamp(Time(data["@timestamp"]));
        string channel = Text(winlog["channel"]), provider = Text(winlog["provider_name"]);
        data.Remove("message"); // Windows rendered body duplicates sensitive structured values.
        int nodes = 0;
        string fingerprint = Mac(key, Discovery.Json.Serialize(Clean(data, 0, ref nodes)));
        string id = Mac(key, Discovery.Json.Serialize(new object[] { agentId, channel, record, provider, code, occurred, fingerprint }));
        return Discovery.Map("id", id, "agent_id", agentId, "channel", channel, "record_id", record, "provider", provider,
            "event_code", code, "occurred_at", occurred, "rejected_at", Stamp(rejected), "content_hmac", fingerprint,
            "fingerprint_scheme", "redacted-canonical-json-hmac-sha256-v1", "identity_verified", false);
    }
    internal static Dictionary<string, object> Run(string root, DateTimeOffset now) {
        string store = Path.Combine(root, "rejection-evidence");
        if (!Directory.Exists(store)) return Discovery.Map("state", "disabled");
        try { return Collect(root, now, Protected); }
        catch { return Discovery.Map("state", "error", "complete_loss_count", false, "replay_performed", false); }
    }
    internal static Dictionary<string, object> Collect(string root, DateTimeOffset now, Action<string> verify) {
        string store = Path.Combine(root, "rejection-evidence");
        verify(root); verify(store);
        string policyPath = Path.Combine(store, "policy.json"), keyPath = Path.Combine(store, "fingerprint.key");
        verify(policyPath); verify(keyPath);
        var policy = Discovery.Json.Deserialize<Dictionary<string, object>>(Discovery.ReadBounded(policyPath, 4096));
        if (policy.Count != 5 || !policy.ContainsKey("schema") || !policy.ContainsKey("days") || !policy.ContainsKey("max_bytes") || !policy.ContainsKey("max_records") || !policy.ContainsKey("approved") ||
            !Object.Equals(policy["schema"], 1) || !Object.Equals(policy["days"], Days) || !Object.Equals(policy["max_bytes"], MaxBytes) || !Object.Equals(policy["max_records"], MaxRecords) || !Object.Equals(policy["approved"], true)) throw new InvalidDataException("evidence_policy");
        if (new FileInfo(keyPath).Length != 32) throw new InvalidDataException("fingerprint_key");
        byte[] key = File.ReadAllBytes(keyPath);
        string lockPath = Path.Combine(store, "store.lock"), manifestPath = Path.Combine(store, "manifest.json");
        if (File.Exists(lockPath)) verify(lockPath);
        if (File.Exists(manifestPath)) verify(manifestPath);
        var clock = Stopwatch.StartNew();
        using (var held = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None)) {
            FileIdentity lockInfo;
            if (!GetFileInformationByHandle(held.SafeFileHandle, out lockInfo) || lockInfo.Links != 1) throw new InvalidDataException("linked_lock");
            if (new DirectoryInfo(store).GetFileSystemInfos().Any(f => !new[] { "policy.json", "fingerprint.key", "store.lock", "manifest.json" }.Contains(f.Name))) throw new InvalidDataException("unexpected_store_entry");
            var records = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            if (File.Exists(manifestPath)) {
                var old = Discovery.Json.Deserialize<Dictionary<string, object>>(Discovery.ReadBounded(manifestPath, MaxBytes / 2 - 4096));
                if (old.Count != 7 || !Object.Equals(old["schema"], 1) || (string)old["key_id"] != Mac(key, "cloud-soc-evidence-key-v1") || (string)old["scope"] != "retained_diagnostics_only" || !Object.Equals(old["complete_loss_count"], false) || !Object.Equals(old["replay_performed"], false)) throw new InvalidDataException("manifest_identity");
                if (Time(old["updated_at"]) > now.AddMinutes(1)) throw new InvalidDataException("manifest_clock");
                var list = old["records"] as IList;
                if (list == null || list.Count > MaxRecords) throw new InvalidDataException("manifest_count");
                foreach (var item in list) {
                    var record = item as Dictionary<string, object>;
                    ValidateRecord(record);
                    string expected = Mac(key, Discovery.Json.Serialize(new object[] { record["agent_id"], record["channel"], Convert.ToInt64(record["record_id"]), record["provider"], record["event_code"], record["occurred_at"], record["content_hmac"] }));
                    if ((string)record["id"] != expected || Time(record["rejected_at"]) > now.AddMinutes(1)) throw new InvalidDataException("manifest_reference");
                    if (Time(record["rejected_at"]) >= now.AddDays(-Days)) records.Add((string)record["id"], record);
                }
            }
            int rejected = 0, skipped = 0, duplicates = 0; bool partial = false; long read = 0;
            string logs = Path.Combine(root, "logs");
            if (Directory.Exists(logs)) {
                verify(logs);
                var entries = new DirectoryInfo(logs).EnumerateFiles("filebeat*.ndjson").Take(65).ToArray();
                if (entries.Length > 64) partial = true;
                var files = entries.Take(64)
                    .Where(f => Regex.IsMatch(f.Name, @"^filebeat(?:-events-data)?-.*\.ndjson$"))
                    .OrderBy(f => f.Name.StartsWith("filebeat-events-data-") ? 0 : 1).ThenByDescending(f => f.LastWriteTimeUtc).Take(9).ToArray();
                if (files.Length > 8) partial = true;
                foreach (var file in files.Take(8)) {
                    if (clock.Elapsed.TotalSeconds > 5 || read >= MaxBytes) { partial = true; break; }
                    verify(file.FullName);
                    using (var input = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                        int size = (int)Math.Min(8388608, Math.Min(input.Length, MaxBytes - read));
                        long offset = input.Length - size; input.Position = offset;
                        byte[] buffer = new byte[size]; int used = 0, count;
                        while (used < size && (count = input.Read(buffer, used, size - used)) > 0) used += count;
                        read += used; if (offset > 0) partial = true;
                        string[] lines = Discovery.Utf8.GetString(buffer, 0, used).Split('\n');
                        if (lines[lines.Length - 1].Length > 0) partial = true;
                        for (int n = offset > 0 ? 1 : 0; n < lines.Length - 1; n++) {
                            if (clock.Elapsed.TotalSeconds > 5) { partial = true; break; }
                            Dictionary<string, object> record;
                            try { record = Parse(lines[n], key, now); } catch { skipped++; partial = true; continue; }
                            if (record == null) continue;
                            rejected++;
                            string id = (string)record["id"];
                            if (records.ContainsKey(id)) { duplicates++; continue; }
                            if (records.Count >= MaxRecords) {
                                partial = true;
                                var oldest = records.Values.OrderBy(r => Time(r["rejected_at"])).ThenBy(r => (string)r["id"], StringComparer.Ordinal).First();
                                if (Time(record["rejected_at"]) <= Time(oldest["rejected_at"])) continue;
                                records.Remove((string)oldest["id"]);
                            }
                            records.Add(id, record);
                        }
                    }
                }
            } else partial = true;
            var kept = records.Values.OrderByDescending(r => Time(r["rejected_at"])).ThenBy(r => (string)r["id"], StringComparer.Ordinal).Take(MaxRecords).ToArray();
            if (kept.Length < records.Count) partial = true;
            var manifest = Discovery.Map("schema", 1, "key_id", Mac(key, "cloud-soc-evidence-key-v1"), "updated_at", Stamp(now), "records", kept,
                "scope", "retained_diagnostics_only", "complete_loss_count", false, "replay_performed", false);
            string json = Discovery.Json.Serialize(manifest);
            // Reserve room for old+new atomic snapshots and fixed policy/key files.
            if (Discovery.Utf8.GetByteCount(json) > MaxBytes / 2 - 4096) throw new InvalidDataException("manifest_limit");
            Atomic(manifestPath, json, verify);
            return Discovery.Map("state", "observed", "records", kept.Length, "rejections_scanned", rejected, "duplicates", duplicates,
                "skipped", skipped, "scan_partial", partial, "complete_loss_count", false, "replay_performed", false);
        }
    }
    internal static void ValidateRecord(Dictionary<string, object> record) {
        string[] names = { "id", "agent_id", "channel", "record_id", "provider", "event_code", "occurred_at", "rejected_at", "content_hmac", "fingerprint_scheme", "identity_verified" };
        if (record == null || record.Count != names.Length || names.Any(k => !record.ContainsKey(k))) throw new InvalidDataException("record_schema");
        if (!Regex.IsMatch((string)record["id"], "^[a-f0-9]{64}$") || !Regex.IsMatch((string)record["content_hmac"], "^[a-f0-9]{64}$") || !Object.Equals(record["identity_verified"], false) || (string)record["fingerprint_scheme"] != "redacted-canonical-json-hmac-sha256-v1") throw new InvalidDataException("record_fingerprint");
        Text(record["channel"]); Text(record["provider"]); Time(record["occurred_at"]); Time(record["rejected_at"]);
        Guid guid; if (!Guid.TryParse(record["agent_id"] as string, out guid) || guid.ToString() != (string)record["agent_id"]) throw new InvalidDataException("record_agent");
        string id = Convert.ToString(record["record_id"], CultureInfo.InvariantCulture); long number;
        if (!Regex.IsMatch(id, @"^[1-9][0-9]{0,18}$") || !Int64.TryParse(id, out number) || !Regex.IsMatch(Convert.ToString(record["event_code"], CultureInfo.InvariantCulture), @"^[0-9]{1,10}$")) throw new InvalidDataException("record_number");
    }
    internal static void Atomic(string path, string text, Action<string> verify) {
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                byte[] bytes = Discovery.Utf8.GetBytes(text); stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
            }
            verify(temp);
            if (File.Exists(path)) { verify(path); File.Replace(temp, path, null); } else File.Move(temp, path);
        } finally { if (File.Exists(temp) && !Discovery.Linked(temp)) File.Delete(temp); }
    }
}

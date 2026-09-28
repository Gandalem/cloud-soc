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

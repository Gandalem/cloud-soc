using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

internal static class DiscoveryTests {
    static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    static void Reject(Action action) { try { action(); } catch (Exception) { return; } throw new Exception("Expected rejection"); }
    static string MetricLine(string time, object dropped) {
        return Discovery.Json.Serialize(Discovery.Map("@timestamp",time,"log.logger","monitoring","service.name","filebeat",
            "message","Non-zero metrics in the last 30s", "password","CANARY_PRIVATE",
            "monitoring",Discovery.Map("metrics",Discovery.Map("libbeat",Discovery.Map(
                "pipeline",Discovery.Map("queue",Discovery.Map("filled",Discovery.Map("bytes",900,"events",10,"pct",0.9))),
                "output",Discovery.Map("events",Discovery.Map("total",10,"acked",8,"dropped",dropped)))))));
    }
    static void MetricsTests(string root) {
        var now = DateTimeOffset.Parse("2026-09-28T00:10:00Z");
        string line = MetricLine("2026-09-28T00:09:30Z", 2);
        var sample = CollectorMetrics.Parse(line);
        Check(CollectorMetrics.Parse(MetricLine("2026-09-28T14:20:52.068+0900", 2)) != null, "Beats compact timezone");
        Check(Convert.ToInt64(sample["output_dropped"]) == 2 && (double)sample["queue_pct"] == .9, "numeric metrics");
        Check(sample["output_failed"] == null && !Discovery.Json.Serialize(sample).Contains("CANARY"), "missing counters/privacy");
        foreach (object value in new object[] {"2", true, -1, 1.5, 9007199254740992L})
            Check(CollectorMetrics.Parse(MetricLine("2026-09-28T00:09:30Z", value))["output_dropped"] == null, "bad numeric field");
        Check(CollectorMetrics.Parse("{\"monitoring\":invalid}") == null, "invalid JSON");
        Check(CollectorMetrics.Parse(line.Replace("Non-zero metrics in the last 30s", "Total metrics")) == null, "cumulative shutdown counter");
        Check(CollectorMetrics.Parse(line.Replace("filebeat", "packetbeat")) == null, "wrong service");
        Check(CollectorMetrics.Parse(new string('x', 524289)) == null, "line cap");
        Check(CollectorMetrics.Parse(line.Replace("CANARY_PRIVATE", new string('x', 100000))) != null, "many-channel metric record");
        Check((string)CollectorMetrics.Read(root, now)["state"] == "unavailable", "no log directory");
        string logs = Path.Combine(root,"logs"); Directory.CreateDirectory(logs);
        File.WriteAllText(Path.Combine(logs,"filebeat-events-data-20260928.ndjson"),line + "\n");
        Check((string)CollectorMetrics.Read(root, now)["state"] == "unavailable", "event-data excluded");
        string active = Path.Combine(logs,"filebeat-20260928.ndjson");
        File.WriteAllText(active,line + "\n" + MetricLine("2026-09-28T00:10:00Z", null) + "\n" + MetricLine("2026-09-28T00:11:00Z", 99));
        sample = CollectorMetrics.Read(root, now);
        Check((string)sample["sampled_at"] == "2026-09-28T00:10:00.0000000Z" && sample["output_dropped"] == null, "partial trailing line skipped");
        Check((string)sample["last_problem_at"] == "2026-09-28T00:09:30.0000000Z", "preceding problem not erased");
        Check(!Discovery.Json.Serialize(sample).Contains("CANARY"), "private fields leaked");
        File.WriteAllText(active,new string('x',1100000) + "\n" + line + "\n");
        Check((bool)CollectorMetrics.Read(root,now)["scan_partial"], "bounded tail scan");
        File.WriteAllText(active,line);
        Check((string)CollectorMetrics.Read(root,now)["state"] == "unavailable", "unfinished file not parsed");
        File.WriteAllText(active,line + "\n");
        Check(CollectorMetrics.Read(root, now.AddHours(1))["last_problem_at"] == null, "old problem not current");
    }
    public static int Main(string[] args) {
        if (args.Length == 2 && args[0] == "--refresh-fixture") {
            Discovery.Refresh(args[1], new[] { Discovery.Map("kind","channel","name","Cloud-SOC-Synthetic-Nonexistent-Channel","status","selected") });
            return 0;
        }
        string parent = Path.GetFullPath(args[0]);
        string temp = Path.Combine(parent, "soc-native-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try {
            string root = Path.Combine(temp, "agent"), logs = Path.Combine(temp, "logs");
            Directory.CreateDirectory(root); Directory.CreateDirectory(Path.Combine(root, "inputs")); Directory.CreateDirectory(logs);
            MetricsTests(root);
            File.WriteAllText(Path.Combine(root, "discovery-settings.json"), Discovery.Json.Serialize(Discovery.Map("log_roots", new[] {logs}, "required_channels", new[] {"Security"})), Discovery.Utf8);
            File.WriteAllText(Path.Combine(logs, "auth.log"), "synthetic hello\n", Discovery.Utf8);
            File.WriteAllText(Path.Combine(logs, "auth.log.1"), "synthetic rotation\n", Discovery.Utf8);
            File.WriteAllText(Path.Combine(logs, "private.key"), "CANARY_DO_NOT_COLLECT", Discovery.Utf8);
            File.WriteAllBytes(Path.Combine(logs, "binary.log"), new byte[] {0,1,2});
            File.WriteAllText(Path.Combine(logs, "utf16.log"), "synthetic\n", Encoding.Unicode);
            File.WriteAllBytes(Path.Combine(logs, "bad-encoding.log"), new byte[] {0xff,0xff,0xff});
            File.WriteAllText(Path.Combine(logs, "empty.log"), "");
            var channels = new[] { Discovery.Map("kind","channel","name","Security","status","selected"), Discovery.Map("kind","channel","name","Disabled","status","disabled"), Discovery.Map("kind","channel","name","Analytic","status","unsupported_direct_channel") };
            Discovery.Refresh(root, channels);
            string input = Path.Combine(root, "inputs", "discovered.yml");
            string first = File.ReadAllText(input);
            Check(first.Contains("cloud-soc-event-" + Discovery.Id("Security")), "stable channel ID");
            Check(first.Contains("cloud-soc-windows-files-utf-8-v2") && first.Contains("auth.log.1") && first.Contains("utf-16le-bom"), "file IDs/rotation/encoding");
            Check(!first.Contains("private.key") && !first.Contains("binary.log") && !first.Contains("empty.log") && !first.Contains("bad-encoding.log"), "privacy filtering");
            Check(!File.ReadAllText(Path.Combine(root, "health.ndjson")).Contains(logs), "health path disclosure");
            Check(File.ReadAllText(Path.Combine(root, "health.ndjson")).Contains("collector_metrics"), "metric health integration");
            DateTime written = File.GetLastWriteTimeUtc(input);
            Discovery.Refresh(root, channels);
            Check(first == File.ReadAllText(input) && written == File.GetLastWriteTimeUtc(input), "stable reload input");
            using (var held = new FileStream(Path.Combine(root,"discovery.lock"), FileMode.Open, FileAccess.Write, FileShare.None)) Reject(() => Discovery.Refresh(root, channels));
            Reject(() => Discovery.Refresh(root, new List<Dictionary<string,object>>()));
            Check(first == File.ReadAllText(input), "failed discovery replaced input");
            Reject(() => Discovery.LogRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows), root));
            Reject(() => Discovery.LogRoot(root, root));
            Reject(() => Discovery.LocalPath(@"C:\logs\..\Users"));
            File.WriteAllText(Path.Combine(root, "collection-policy.txt"), "version=1\nroot=" + logs + "\nexclude=" + logs + "\n", Discovery.Utf8);
            Discovery.Refresh(root, channels);
            Check(!File.ReadAllText(input).Contains("auth.log"), "policy exclusions");
            Check(File.ReadAllText(Path.Combine(root, "health.ndjson")).Contains("\"policy_version\":1"), "policy version");
            File.WriteAllText(Path.Combine(root, "collection-policy.txt"), "version=oops\n", Discovery.Utf8);
            string preserved = File.ReadAllText(input);
            Reject(() => Discovery.Refresh(root, channels));
            Check(preserved == File.ReadAllText(input), "invalid policy preservation");
            Console.WriteLine("Native Discovery: synthetic channels/files, stable IDs, encodings, exclusions, lock, atomic updates and error preservation passed.");
            return 0;
        } finally {
            if (Path.GetDirectoryName(temp) != parent || !Path.GetFileName(temp).StartsWith("soc-native-test-")) throw new Exception("unsafe cleanup");
            Directory.Delete(temp, true);
        }
    }
}

using System;
using System.IO;

internal static class P2MetricsTests {
    static int checks;
    static void Check(bool condition, string name) { checks++; if (!condition) throw new Exception(name); }
    static string Line(string service, string time) {
        return Discovery.Json.Serialize(Discovery.Map("@timestamp", time, "log.logger", "monitoring", "service.name", service,
            "message", "Non-zero metrics in the last 30s", "secret", "PRIVATE_CANARY",
            "monitoring", Discovery.Map("metrics", Discovery.Map("libbeat", Discovery.Map("output",
                Discovery.Map("events", Discovery.Map("total", 20, "acked", 18, "failed", 2)))))));
    }
    static void Config(string root, string service, string organization, string endpoint, string ca) {
        File.WriteAllText(Path.Combine(root, service + ".yml"), Discovery.Json.Serialize(Discovery.Map(
            "processors", new[] { Discovery.Map("add_fields", Discovery.Map("target", "organization", "fields", Discovery.Map("id", organization))) },
            "output.elasticsearch", Discovery.Map("hosts", new[] { endpoint }, "api_key", "PRIVATE_CANARY",
                "ssl.verification_mode", "full", "ssl.certificate_authorities", new[] { Path.Combine(root, "ca.crt") }))));
        File.WriteAllText(Path.Combine(root, "ca.crt"), ca);
    }
    public static int Main(string[] args) {
        try { return Run(args); }
        catch (Exception error) {
            Console.Error.WriteLine("P2 fixture failed: " + error.GetType().Name + " " + error.Message);
            return 1;
        }
    }
    static int Run(string[] args) {
        string host = Path.Combine(args[0], "p2-host"), network = Path.Combine(args[0], "p2-network");
        Directory.CreateDirectory(host); Directory.CreateDirectory(network); Directory.CreateDirectory(Path.Combine(network, "logs"));
        var now = DateTimeOffset.Parse("2026-10-07T06:00:00Z");
        string record = Line("packetbeat", "2026-10-07T05:59:30Z"), reason;
        Check(CollectorMetrics.Parse(record) == null, "Packetbeat never parsed as Filebeat");
        var parsed = CollectorMetrics.Parse(record, "packetbeat", out reason);
        Check(Convert.ToInt64(parsed["output_failed"]) == 2 && parsed["output_dropped"] == null, "network numeric allowlist");
        Check(!Discovery.Json.Serialize(parsed).Contains("PRIVATE_CANARY"), "privacy");
        Check(CollectorMetrics.Parse(Line("packetbeat", "2026-10-07T05:59:30"), "packetbeat", out reason) == null, "timezone required");
        Check(CollectorMetrics.Parse(Line("packetbeat", "2026-10-07T14:59:30.123456789+0900"), "packetbeat", out reason) != null, "nanosecond compact offset");
        File.WriteAllText(Path.Combine(network, "logs", "packetbeat-events-data-20261007.ndjson"), record + "\n");
        Check((string)CollectorMetrics.Read(network, now, "packetbeat")["state"] == "unavailable", "event-data excluded");
        File.WriteAllText(Path.Combine(network, "logs", "packetbeat-20261007.ndjson"), record + "\n" + Line("packetbeat", "2026-10-07T07:00:00Z"));
        var read = CollectorMetrics.Read(network, now, "packetbeat");
        Check((string)read["sampled_at"] == "2026-10-07T05:59:30.0000000Z", "complete records only");
        Check((bool)read["scan_partial"], "unfinished tail visible");
        Check((string)CollectorMetrics.Read(network, now)["state"] == "unavailable", "Filebeat filenames isolated");
        Config(host, "filebeat", "test", "https://soc.test:9200", "ca");
        Config(network, "packetbeat", "test", "https://soc.test:9200/", "ca");
        Check(CollectorMetrics.Identity(host, "filebeat") == CollectorMetrics.Identity(network, "packetbeat"), "same identity");
        foreach (string variant in new[] { "organization", "endpoint", "ca" }) {
            Config(network, "packetbeat", variant == "organization" ? "different" : "test", variant == "endpoint" ? "https://else.test:9200" : "https://soc.test:9200", variant == "ca" ? "different" : "ca");
            Check(CollectorMetrics.Identity(host, "filebeat") != CollectorMetrics.Identity(network, "packetbeat"), "identity mismatch: " + variant);
        }
        Check((string)CollectorMetrics.ReadNetwork(host, Path.Combine(network, "absent"), now)["state"] == "unavailable", "missing protected network safe");
        Check(DiscoveryTests.Main(new[] { args[0] }) == 0, "original native worker regression");
        Console.WriteLine("P2 metrics checks passed: " + checks);
        return 0;
    }
}

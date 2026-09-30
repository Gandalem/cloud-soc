using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

internal static class EvidenceReferenceCheck {
    static void Require(bool value, string check = "reference_check_failed") { if (!value) throw new InvalidDataException(check); }
    static string Fingerprint(Dictionary<string, object> payload, byte[] key) {
        payload.Remove("message");
        int nodes = 0;
        return RejectionEvidence.Mac(key, Discovery.Json.Serialize(RejectionEvidence.Clean(payload, 0, ref nodes)));
    }
    public static int Main(string[] args) {
        try {
            Require(args.Length == 1);
            string root = args[0], store = Path.Combine(root, "rejection-evidence");
            RejectionEvidence.Protected(store);
            byte[] key = File.ReadAllBytes(Path.Combine(store, "fingerprint.key"));
            var manifest = Discovery.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(store, "manifest.json")));
            var records = (IList)manifest["records"];
            Require(records.Count == 1);
            var record = (Dictionary<string, object>)records[0];
            RejectionEvidence.ValidateRecord(record);
            var expected = Discovery.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(root, "expected.json")));
            foreach (string name in new[] {"agent_id", "channel", "provider", "event_code"})
                Require((string)record[name] == (string)expected[name], "reference_" + name);
            // Beats serializes event timestamps to milliseconds; RecordID disambiguates within that bucket.
            var osTime = RejectionEvidence.Time(expected["occurred_at"]);
            var refTime = RejectionEvidence.Time(record["occurred_at"]);
            Require(osTime >= refTime && osTime < refTime.AddMilliseconds(1), "reference_occurred_at");
            Require(Convert.ToInt64(record["record_id"]) == Convert.ToInt64(expected["record_id"]));
            var payload = Discovery.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(root, "received-payload.json")));
            Require(RejectionEvidence.Stamp(RejectionEvidence.Time(payload["@timestamp"])) == (string)record["occurred_at"], "receiver_time");
            Require((string)record["content_hmac"] == Fingerprint(payload, key), "receiver_fingerprint");
            var winlog = (Dictionary<string, object>)payload["winlog"];
            var data = (Dictionary<string, object>)winlog["event_data"];
            Require((string)data["param1"] == (string)expected["marker"]);
            data["param1"] = "changed-nonsensitive-synthetic-value";
            Require((string)record["content_hmac"] != Fingerprint(payload, key));
            Array.Clear(key, 0, key.Length);
            Console.WriteLine("Actual OS reference and receiver-payload HMAC/tamper comparison: passed.");
            return 0;
        } catch (InvalidDataException error) { Console.Error.WriteLine(error.Message); return 1; }
        catch { Console.Error.WriteLine("Reference/HMAC verification failed; no payload or key emitted."); return 1; }
    }
}

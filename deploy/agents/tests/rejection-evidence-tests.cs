using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

internal static class EvidenceTests {
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
    static extern bool CreateHardLink(string newName, string existing, IntPtr reserved);
    static void Check(bool value, string reason) { if (!value) throw new Exception(reason); }
    static void Reject(Action action) { try { action(); } catch { return; } throw new Exception("Expected rejection"); }
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-30T00:00:00Z");
    static readonly byte[] Key = Enumerable.Repeat((byte)42,32).ToArray();
    internal static string Line(int id = 1, string time = "2026-09-29T23:59:00Z", string secret = "SECRET_CANARY", string channel = "Application", string status = "400", string separator = "") {
        var data = Discovery.Map("@timestamp", "2026-09-29T23:50:00Z", "agent", Discovery.Map("id", "11111111-1111-4111-8111-111111111111"),
            "winlog", Discovery.Map("channel", channel, "provider_name", "Cloud-SOC-Synthetic", "record_id", id, "event_data", Discovery.Map("password", secret, "safe", "normal", "CommandLine", secret)),
            "event", Discovery.Map("code", "1000"), "message", secret, "authorization", secret,
            "secret", secret, "url", "https://example.invalid/?token=" + secret);
        string diagnostic = "Cannot index event '" + Discovery.Json.Serialize(data) + separator + "' (status=" + status + "): {\"type\":\"document_parsing_exception\",\"reason\":\"Limit of total fields [1000]\"}";
        return Discovery.Json.Serialize(Discovery.Map("@timestamp", time, "log.logger", "elasticsearch", "message", diagnostic));
    }
    static void VerifyLocal(string path) { if (Discovery.Linked(path)) throw new Exception("link"); }
    static string Store(string root) {
        string store = Path.Combine(root,"rejection-evidence"); Directory.CreateDirectory(store);
        File.WriteAllText(Path.Combine(store,"policy.json"), "{\"schema\":1,\"days\":7,\"max_bytes\":16777216,\"max_records\":2000,\"approved\":true}");
        File.WriteAllBytes(Path.Combine(store,"fingerprint.key"),Key);
        Directory.CreateDirectory(Path.Combine(root,"logs"));
        return store;
    }
    static void ParserTests() {
        var parsed = RejectionEvidence.Parse(Line(),Key,Now);
        Check((string)parsed["channel"] == "Application" && Convert.ToInt64(parsed["record_id"]) == 1, "reference");
        Check((string)parsed["id"] == (string)RejectionEvidence.Parse(Line(separator:"\n"),Key,Now)["id"], "actual Beat JSON trailing newline");
        Check((string)parsed["id"] == (string)RejectionEvidence.Parse(Line(separator:"\n, Meta: none"),Key,Now)["id"], "actual Beat Meta none suffix");
        Check((string)parsed["id"] == (string)RejectionEvidence.Parse(Line(separator:"\n, Meta: {\"pipeline\":\"SECRET_CANARY\"}"),Key,Now)["id"], "Meta discarded");
        Check(RejectionEvidence.Time("2026-09-29T23:59:00.123456789Z").UtcDateTime.Ticks % 10000000 == 1234567,"nanosecond diagnostic timestamp bounded normalization");
        Check(!Discovery.Json.Serialize(parsed).Contains("CANARY") && parsed.Count == 11, "privacy whitelist");
        Check((string)parsed["id"] == (string)RejectionEvidence.Parse(Line(secret:"OTHER_PRIVATE"),Key,Now)["id"], "redacted fingerprint independence");
        Check((string)parsed["id"] != (string)RejectionEvidence.Parse(Line(id:2),Key,Now)["id"], "reference distinction");
        Check((string)parsed["content_hmac"] != (string)RejectionEvidence.Parse(Line(),new byte[32],Now)["content_hmac"], "key separation");
        Check(RejectionEvidence.Parse(Line(time:"2026-09-01T00:00:00Z"),Key,Now) == null, "expired input");
        Check(RejectionEvidence.Parse(Line(time:"2026-10-01T00:00:00Z"),Key,Now) == null, "future input");
        Check(RejectionEvidence.Parse(Line(time:"2026-09-30T08:59:00+0900"),Key,Now) != null, "compact offset");
        Check(RejectionEvidence.Parse("{}",Key,Now) == null,"non-rejection ignored");
        int badNumber = 0;
        foreach (string bad in new[] {"{broken", Line(channel:"Bearer SECRET_CANARY"), Line(id:0), Line(status:"403"), new string('x',524289)}) {
            badNumber++; bool failed=false;
            try { RejectionEvidence.Parse(bad,Key,Now); } catch { failed=true; }
            Check(failed,"parser invalid case " + badNumber);
        }
        var canonical1 = Discovery.Map("b",2,"a", Discovery.Map("z",9,"safe",1));
        var canonical2 = Discovery.Map("a",Discovery.Map("safe",1,"z",9),"b",2);
        int nodes1=0,nodes2=0;
        Check(Discovery.Json.Serialize(RejectionEvidence.Clean(canonical1,0,ref nodes1)) == Discovery.Json.Serialize(RejectionEvidence.Clean(canonical2,0,ref nodes2)), "canonical key order");
        Reject(() => RejectionEvidence.EventJson("Cannot index event 'malformed {\"record_id\":1}' (status=400):"));
        Reject(() => RejectionEvidence.ValidateRecord(Discovery.Map("message","SECRET_CANARY")));
    }
    static void StoreTests(string parent) {
        string outside=Path.Combine(parent,"outside-test.txt"), linked=Path.Combine(parent,"hardlink-test.txt");
        File.WriteAllText(outside,"unchanged outside fixture");
        Check(CreateHardLink(linked,outside,IntPtr.Zero),"hardlink fixture unavailable");
        Reject(() => RejectionEvidence.SingleLink(linked));
        Check(File.ReadAllText(outside)=="unchanged outside fixture","hardlink target unchanged");
        string root = Path.Combine(parent,"store"); Directory.CreateDirectory(root);
        Check((string)RejectionEvidence.Run(root,Now)["state"] == "disabled", "default off");
        string store = Store(root), source=Path.Combine(root,"logs","filebeat-events-data-20260929.ndjson"), manifest=Path.Combine(store,"manifest.json");
        string input = Line()+"\n"+Line()+"\n"+Line(id:2)+"\n"+Line(id:3);
        File.WriteAllText(source,input);
        var report=RejectionEvidence.Collect(root,Now,VerifyLocal);
        Check((int)report["records"] == 2 && (int)report["duplicates"] == 1 && (bool)report["scan_partial"], "dedup/partial line");
        Check(File.ReadAllText(source) == input && !File.ReadAllText(manifest).Contains("CANARY"), "input and private body preservation");
        Check(!Discovery.Json.Serialize(report).Contains("Application") && !Discovery.Json.Serialize(report).Contains("11111111"), "summary privacy");
        report=RejectionEvidence.Collect(root,Now,VerifyLocal);
        Check((int)report["records"] == 2 && (int)report["duplicates"] == 3, "persistent dedup");
        string before = File.ReadAllText(manifest);
        using(var held=new FileStream(Path.Combine(store,"store.lock"),FileMode.Open,FileAccess.Write,FileShare.None)) Reject(() => RejectionEvidence.Collect(root,Now,VerifyLocal));
        Check(File.ReadAllText(manifest) == before, "concurrent writer preservation");
        Reject(() => RejectionEvidence.Collect(root,Now,p => {VerifyLocal(p); if(p.EndsWith(".tmp")) throw new IOException("synthetic commit failure");}));
        Check(File.ReadAllText(manifest)==before && Directory.GetFiles(store,"*.tmp").Length==0, "atomic failure preservation/owned cleanup");
        File.WriteAllText(Path.Combine(store,"unexpected.txt"),"unowned");
        Reject(() => RejectionEvidence.Collect(root,Now,VerifyLocal));
        Check(File.ReadAllText(manifest)==before && File.ReadAllText(Path.Combine(store,"unexpected.txt"))=="unowned", "unknown entry untouched");
        File.Delete(Path.Combine(store,"unexpected.txt"));
        File.WriteAllBytes(Path.Combine(store,"fingerprint.key"),new byte[32]);
        Reject(() => RejectionEvidence.Collect(root,Now,VerifyLocal));
        Check(File.ReadAllText(manifest)==before,"different key blocked");
        File.WriteAllBytes(Path.Combine(store,"fingerprint.key"),Key);
        File.WriteAllText(manifest,before.Replace("Application","Tampered"));
        Reject(() => RejectionEvidence.Collect(root,Now,VerifyLocal));
        File.WriteAllText(manifest,before);
        report=RejectionEvidence.Collect(root,Now.AddDays(8),VerifyLocal);
        Check((int)report["records"] == 0, "retention expiration");
        Reject(() => RejectionEvidence.Collect(root,Now,VerifyLocal));
        File.Delete(manifest); // Start an independent capacity fixture, not a clock rewind.
        File.WriteAllText(source,String.Join("\n",Enumerable.Range(1,2100).Select(id=>Line(id)))+"\n");
        report=RejectionEvidence.Collect(root,Now,VerifyLocal);
        Check((int)report["records"]<=2000 && (bool)report["scan_partial"], "record capacity");
        Check(Directory.GetFiles(store).Sum(p=>new FileInfo(p).Length)<RejectionEvidence.MaxBytes,"store size");
        File.WriteAllText(source,"{}\n");
        File.WriteAllText(manifest,"{invalid}");
        Check((string)RejectionEvidence.Run(root,Now)["state"]=="error" && File.ReadAllText(manifest)=="{invalid}","protected failure isolated");
        Reject(() => RejectionEvidence.Collect(root,Now,VerifyLocal));
        File.Delete(manifest);
        File.WriteAllText(source, new string('x',8500000)+"\n"+Line()+"\n");
        report=RejectionEvidence.Collect(root,Now,VerifyLocal);
        Check((bool)report["scan_partial"] && (int)report["records"]==1,"bounded tail scan");
        File.WriteAllText(source,"{bad}\n"+Line()+"\n");
        report=RejectionEvidence.Collect(root,Now,VerifyLocal);
        Check((int)report["skipped"]==1 && (bool)report["scan_partial"],"malformed input explicit");
        Check(!(bool)report["complete_loss_count"] && !(bool)report["replay_performed"],"no completeness/replay claim");
    }
    public static int Main(string[] args) {
        if (args.Length == 2 && args[0] == "--format-root") {
            Store(args[1]);
            var report = RejectionEvidence.Collect(args[1],DateTimeOffset.UtcNow,VerifyLocal);
            Console.WriteLine(Discovery.Json.Serialize(report));
            if ((int)report["records"] == 0) {
                foreach (string path in Directory.GetFiles(Path.Combine(args[1],"logs"),"*.ndjson")) {
                    foreach (string line in File.ReadAllLines(path)) {
                        try { RejectionEvidence.Parse(line,Key,DateTimeOffset.UtcNow); }
                        catch (Exception error) {
                            Console.WriteLine("Parse error type: " + error.GetType().Name);
                            if (error is InvalidDataException && System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[a-z_]{1,40}$")) Console.WriteLine("Parse category: " + error.Message);
                        }
                    }
                }
            }
            Check((int)report["records"] >= 1, "Actual Filebeat diagnostic format not captured");
            Check(!File.ReadAllText(Path.Combine(args[1],"rejection-evidence","manifest.json")).Contains("FORMAT_CANARY"), "Filebeat diagnostic canary leaked");
            Console.WriteLine("Actual Filebeat diagnostic capture passed; no event replay or server access.");
            return 0;
        }
        ParserTests(); StoreTests(args[0]);
        Console.WriteLine("Evidence parser/store: privacy, canonical HMAC, bounded input, dedup, lock, atomic failure, retention and no replay passed.");
        return 0;
    }
}

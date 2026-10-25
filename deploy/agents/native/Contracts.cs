// C# 5 / inbox .NET Framework 4.8. No runtime compilation or script host.
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace CloudSoc.Native {
internal static class Contract {
    internal static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 2097152, RecursionLimit = 40 };
    internal static Dictionary<string, object> Map(params object[] pairs) {
        var result = new Dictionary<string, object>(StringComparer.Ordinal);
        for (int n = 0; n < pairs.Length; n += 2) result.Add((string)pairs[n], pairs[n + 1]);
        return result;
    }
    internal static void Require(bool condition, string code) { if (!condition) throw new InvalidDataException(code); }
    internal static string Text(Dictionary<string, object> value, string key, string pattern) {
        object item; Require(value.TryGetValue(key, out item) && item is string && Regex.IsMatch((string)item, "\\A(?:" + pattern + ")\\z"), "invalid_" + key);
        return (string)item;
    }
    internal static bool Flag(Dictionary<string, object> value, string key) {
        object item; Require(value.TryGetValue(key, out item) && item is bool, "invalid_" + key); return (bool)item;
    }
    internal static Dictionary<string, object> Parse(string text) {
        var value = Json.DeserializeObject(text) as Dictionary<string, object>;
        Require(value != null, "invalid_object"); return value;
    }
    internal static string Hash(byte[] bytes) { using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(bytes)); }
    internal static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
    internal static string FileHash(string path) { using (var sha = SHA256.Create()) using (var file = File.OpenRead(path)) return Hex(sha.ComputeHash(file)); }
    internal static string Random() { var bytes = new byte[32]; using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes); return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
    internal static string Origin(string value) {
        Uri uri;
        Require(Uri.TryCreate(value, UriKind.Absolute, out uri) && uri.Scheme == "https" && uri.UserInfo == "" && uri.AbsolutePath == "/" && uri.Query == "" && uri.Fragment == "" && value.TrimEnd('/') == uri.GetLeftPart(UriPartial.Authority), "invalid_https_origin");
        return value.TrimEnd('/');
    }
    // Structural JSON comparison ignores object ordering, never array ordering/types.
    internal static bool Equal(object a, object b) {
        var x = a as Dictionary<string, object>; var y = b as Dictionary<string, object>;
        if (x != null || y != null) return x != null && y != null && x.Count == y.Count && x.All(p => y.ContainsKey(p.Key) && Equal(p.Value, y[p.Key]));
        var aa = a as object[]; var bb = b as object[];
        if (aa != null || bb != null) return aa != null && bb != null && aa.Length == bb.Length && aa.Select((v, i) => Equal(v, bb[i])).All(v => v);
        return Object.Equals(a, b);
    }
    internal static Dictionary<string, byte[]> Archive(string path, long maximum) {
        return Archive(Safe.Read(path, checked((int)maximum)), maximum);
    }
    internal static Dictionary<string, byte[]> Archive(byte[] payload, long maximum) {
        Require(payload.LongLength <= maximum, "archive_size");
        var members = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase); long expanded = 0;
        using (var memory = new MemoryStream(payload, false)) using (var zip = new ZipArchive(memory, ZipArchiveMode.Read)) {
            Require(zip.Entries.Count <= 100, "archive_entries");
            foreach (var entry in zip.Entries) {
                Require(Regex.IsMatch(entry.FullName, @"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\z") && !members.ContainsKey(entry.FullName), "archive_path");
                expanded += entry.Length; Require(expanded <= maximum && entry.Length <= maximum, "archive_expansion");
                using (var input = entry.Open()) using (var output = new MemoryStream()) {
                    var buffer = new byte[8192]; int count;
                    while ((count = input.Read(buffer, 0, buffer.Length)) > 0) { Require(output.Length + count <= entry.Length && output.Length + count <= maximum, "archive_expansion"); output.Write(buffer, 0, count); }
                    Require(output.Length == entry.Length, "archive_length"); members.Add(entry.FullName, output.ToArray());
                }
            }
        }
        return members;
    }
    internal static Dictionary<string, object> ValidatePackage(Dictionary<string, object> spec, Dictionary<string, object> registration) {
        Text(spec, "package_id", "[a-f0-9]{32}"); Text(spec, "managed_device_id", "[a-f0-9]{32}"); Text(spec, "organization", "[A-Za-z0-9][A-Za-z0-9_-]{0,63}");
        Require(Text(spec, "os", "windows") == "windows" && Convert.ToInt32(spec["enrollment_protocol"]) == 1 && !Flag(spec, "network"), "unsupported_scope");
        Flag(spec, "system"); Origin((string)spec["endpoint"]); Origin((string)spec["portal_url"]);
        Require(Text(registration, "device_id", "[a-f0-9]{32}") == (string)spec["managed_device_id"], "device_mismatch");
        Text(registration, "enrollment_id", "[a-f0-9]{32}"); Text(registration, "token", @"[a-f0-9]{32}\.[A-Za-z0-9_-]{43}"); Text(registration, "package_sha256", "[a-f0-9]{64}");
        Require(((string)registration["token"]).StartsWith((string)registration["enrollment_id"] + ".", StringComparison.Ordinal), "enrollment_mismatch");
        Require(Convert.ToInt64(registration["expires"]) > (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds, "registration_expired");
        return spec;
    }
    internal static Dictionary<string, object> Session(Dictionary<string, object> reply, Dictionary<string, object> spec, string enrollment) {
        Require(Text(reply, "id", "[a-f0-9]{32}") == enrollment && Text(reply, "probe", "[a-f0-9]{64}").Length == 64, "session_identity");
        Require(Object.Equals(reply["endpoint"], spec["endpoint"]) && Object.Equals(reply["organization"], spec["organization"]) && !Flag(reply, "receipt_verified"), "session_binding");
        var keys = reply["keys"] as object[]; Require(keys != null && keys.Length == 1, "session_scopes");
        var key = keys[0] as Dictionary<string, object>; Require(key != null && Text(key, "scope", "host") == "host", "session_scope");
        Text(key, "key", "[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"); return key;
    }
}
}

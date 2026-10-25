using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace CloudSoc.Native {
internal static class Safe {
    internal static readonly SecurityIdentifier Admin = new SecurityIdentifier("S-1-5-32-544");
    internal static readonly SecurityIdentifier SystemIdentity = new SecurityIdentifier("S-1-5-18");
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { public int Size; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateDirectory(string path, ref Attributes attributes);
    internal static void Path(string path) {
        string full = System.IO.Path.GetFullPath(path);
        Contract.Require(full.Length < 240 && !full.StartsWith(@"\\") && full.IndexOfAny(new[] {'\r','\n','"','$','{','}'}) < 0, "unsafe_path");
        for (var current = full; current != null; current = System.IO.Path.GetDirectoryName(current)) {
            if (File.Exists(current) || Directory.Exists(current)) Contract.Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "linked_path");
        }
    }
    internal static void Protected(string path) {
        Path(path);
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(Admin);
        foreach (var sid in new[] {Admin, SystemIdentity}) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        byte[] descriptor = acl.GetSecurityDescriptorBinaryForm(); var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try {
            var attributes = new Attributes { Size = Marshal.SizeOf(typeof(Attributes)), Descriptor = pinned.AddrOfPinnedObject(), Inherit = false };
            // Exclusive creation with its FINAL DACL; never adopt an existing/raced directory.
            Contract.Require(CreateDirectory(path, ref attributes), "protected_directory_create");
        } finally { pinned.Free(); }
        CheckAcl(path);
    }
    internal static void CheckAcl(string path) {
        Path(path); var acl = Directory.Exists(path) ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
        Contract.Require(acl.GetOwner(typeof(SecurityIdentifier)).Equals(Admin) || acl.GetOwner(typeof(SecurityIdentifier)).Equals(SystemIdentity), "unsafe_owner");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0)
                Contract.Require(rule.IdentityReference.Equals(Admin) || rule.IdentityReference.Equals(SystemIdentity), "unsafe_write_acl");
        }
    }
    internal static byte[] Read(string path, int maximum) {
        Path(path);
        using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            Contract.Require(input.Length <= maximum, "file_size"); byte[] result = new byte[(int)input.Length]; int used = 0, count;
            while (used < result.Length && (count = input.Read(result, used, result.Length - used)) > 0) used += count;
            Contract.Require(used == result.Length, "file_read"); return result;
        }
    }
    internal static void Atomic(string path, byte[] bytes) {
        Path(path); CheckAcl(System.IO.Path.GetDirectoryName(path)); var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try {
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(path)) { CheckAcl(path); File.Replace(temp, path, null); } else File.Move(temp, path);
        } finally { if (File.Exists(temp)) { Path(temp); File.Delete(temp); } }
    }
    internal static void Json(string path, object value) { Atomic(path, Contract.Utf8.GetBytes(Contract.Json.Serialize(value))); }
    internal static void Seal(string path, object value) {
        byte[] plain = Contract.Utf8.GetBytes(Contract.Json.Serialize(value));
        try { Atomic(path, ProtectedData.Protect(plain, Contract.Utf8.GetBytes("cloud-soc-native-v1"), DataProtectionScope.LocalMachine)); }
        finally { Array.Clear(plain, 0, plain.Length); }
    }
    internal static System.Collections.Generic.Dictionary<string, object> Unseal(string path) {
        CheckAcl(path); var plain = ProtectedData.Unprotect(Read(path, 131072), Contract.Utf8.GetBytes("cloud-soc-native-v1"), DataProtectionScope.LocalMachine);
        try { return Contract.Parse(Contract.Utf8.GetString(plain)); } finally { Array.Clear(plain, 0, plain.Length); }
    }
    internal static void RemoveTree(string path, string expected) {
        Contract.Require(String.Equals(System.IO.Path.GetFullPath(path), System.IO.Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase), "delete_boundary");
        CheckAcl(path);
        // Validate the entire tree before deleting anything. No reparse traversal.
        Inspect(path); Directory.Delete(path, true);
    }
    private static void Inspect(string path) {
        Path(path); foreach (string file in Directory.GetFiles(path)) Path(file);
        foreach (string directory in Directory.GetDirectories(path)) Inspect(directory);
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct TrustFile { public uint Size; public string File; public IntPtr Handle; public IntPtr Subject; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct TrustData {
        public uint Size; public IntPtr Callback; public IntPtr Client; public uint UI; public uint Revocation; public uint Choice; public IntPtr File; public uint Action; public IntPtr State; public IntPtr URL; public uint Flags; public uint Context; public IntPtr SignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)] private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
    internal static void Signed(string path) {
        var file = new TrustFile { Size = (uint)Marshal.SizeOf(typeof(TrustFile)), File = path };
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFile))); Marshal.StructureToPtr(file, ptr, false);
        var data = new TrustData { Size = (uint)Marshal.SizeOf(typeof(TrustData)), UI = 2, Revocation = 1, Choice = 1, File = ptr, Action = 1, Flags = 0x80 };
        Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        try { Contract.Require(WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0, "installer_signature"); }
        finally { data.Action = 2; WinVerifyTrust(new IntPtr(-1), ref action, ref data); Marshal.DestroyStructure(ptr, typeof(TrustFile)); Marshal.FreeHGlobal(ptr); }
    }
}
}

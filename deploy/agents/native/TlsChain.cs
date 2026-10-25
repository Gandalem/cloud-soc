using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CloudSoc.Native {
// .NET Framework ExtraStore is not a private trust anchor. Use a connection-only
// exclusive Windows chain engine; never install certificates into OS stores.
internal static class TlsChain {
    [StructLayout(LayoutKind.Sequential)] private struct Engine {
        public uint Size; public IntPtr RestrictedRoot, RestrictedTrust, RestrictedOther; public uint Count;
        public IntPtr Additional; public uint Flags, Timeout, Cached, Cycle; public IntPtr Root, People; public uint Exclusive;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Usage { public uint Count; public IntPtr Oids; }
    [StructLayout(LayoutKind.Sequential)] private struct Match { public uint Type; public Usage Usage; }
    [StructLayout(LayoutKind.Sequential)] private struct Parameters {
        public uint Size; public Match RequestedUsage, Issuance; public uint Timeout; public int CheckFreshness;
        public uint Freshness; public IntPtr Resync, Strong; public uint StrongFlags;
    }
    [DllImport("crypt32.dll", SetLastError=true)] private static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr crypt, uint flags, IntPtr parameter);
    [DllImport("crypt32.dll", SetLastError=true)] private static extern bool CertAddCertificateContextToStore(IntPtr store, IntPtr cert, uint disposition, IntPtr result);
    [DllImport("crypt32.dll", SetLastError=true)] private static extern bool CertCreateCertificateChainEngine(ref Engine config, out IntPtr engine);
    [DllImport("crypt32.dll", SetLastError=true)] private static extern bool CertGetCertificateChain(IntPtr engine, IntPtr cert, IntPtr time, IntPtr store, ref Parameters parameters, uint flags, IntPtr reserved, out IntPtr context);
    [DllImport("crypt32.dll")] private static extern void CertFreeCertificateChain(IntPtr chain);
    [DllImport("crypt32.dll")] private static extern void CertFreeCertificateChainEngine(IntPtr engine);
    [DllImport("crypt32.dll")] private static extern bool CertCloseStore(IntPtr store, uint flags);
    internal static bool Validate(X509Certificate2 leaf, X509Certificate2 ca, X509Chain supplied) {
        IntPtr roots = IntPtr.Zero, additional = IntPtr.Zero, engine = IntPtr.Zero, context = IntPtr.Zero;
        IntPtr oid = Marshal.StringToHGlobalAnsi("1.3.6.1.5.5.7.3.1"), oids = Marshal.AllocHGlobal(IntPtr.Size);
        try {
            // CERT_STORE_PROV_MEMORY / CREATE_NEW. No system-store handles.
            roots = CertOpenStore(new IntPtr(2), 0, IntPtr.Zero, 0x2000, IntPtr.Zero);
            additional = CertOpenStore(new IntPtr(2), 0, IntPtr.Zero, 0x2000, IntPtr.Zero);
            if (roots == IntPtr.Zero || additional == IntPtr.Zero || !CertAddCertificateContextToStore(roots, ca.Handle, 4, IntPtr.Zero) || !CertAddCertificateContextToStore(additional, ca.Handle, 4, IntPtr.Zero)) return false;
            // Server intermediates may help build a chain, but NEVER become anchors.
            if (supplied != null) foreach (var element in supplied.ChainElements)
                if (!CertAddCertificateContextToStore(additional, element.Certificate.Handle, 4, IntPtr.Zero)) return false;
            var config = new Engine { Size = (uint)Marshal.SizeOf(typeof(Engine)), Root = roots, Timeout = 5000 };
            if (!CertCreateCertificateChainEngine(ref config, out engine)) return false;
            Marshal.WriteIntPtr(oids, oid);
            var parameters = new Parameters { Size = (uint)Marshal.SizeOf(typeof(Parameters)), Timeout = 5000,
                RequestedUsage = new Match { Type = 0, Usage = new Usage { Count = 1, Oids = oids } } };
            // Online revocation EXCLUDE_ROOT + cumulative timeout + disable OS
            // auth-root auto-update. No CACHE_ONLY, unknown/offline/error waivers.
            if (!CertGetCertificateChain(engine, leaf.Handle, IntPtr.Zero, additional, ref parameters, 0x48000100, IntPtr.Zero, out context)) return false;
            using (var chain = new X509Chain(context)) {
                if (chain.ChainStatus.Length != 0 || chain.ChainElements.Count < 2) return false;
                var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                if (Convert.ToBase64String(root.RawData) != Convert.ToBase64String(ca.RawData)) return false;
                DateTime now = DateTime.UtcNow;
                foreach (var element in chain.ChainElements)
                    if (now < element.Certificate.NotBefore.ToUniversalTime() || now > element.Certificate.NotAfter.ToUniversalTime()) return false;
                return true;
            }
        } catch { return false; }
        finally {
            if (context != IntPtr.Zero) CertFreeCertificateChain(context);
            if (engine != IntPtr.Zero) CertFreeCertificateChainEngine(engine);
            if (additional != IntPtr.Zero) CertCloseStore(additional, 0);
            if (roots != IntPtr.Zero) CertCloseStore(roots, 0);
            Marshal.FreeHGlobal(oids); Marshal.FreeHGlobal(oid);
        }
    }
}
}

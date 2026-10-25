// Test entry point for the EXACT native installer's TLS verifier. No trust-store writes.
using System;
internal static class NativeTlsProbeTest {
    public static int Main(string[] args) {
        try { if (args.Length != 2) return 2; CloudSocTlsProbe.Check(args[0], args[1], false); Console.WriteLine("tls_validated"); return 0; }
        catch { Console.WriteLine("tls_rejected"); return 1; }
    }
}

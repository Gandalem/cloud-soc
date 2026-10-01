using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

// Per-connection trust for the bundled CA. Never changes Windows trust stores.
public static class CloudSocTlsProbe
{
    public static bool AcceptChain(X509Chain chain, X509Certificate2 ca, bool allowUnavailable)
    {
        if (chain == null || chain.ChainElements.Count == 0 || ca == null)
            return false;
        X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
        if (!Convert.ToBase64String(root.RawData).Equals(Convert.ToBase64String(ca.RawData), StringComparison.Ordinal))
            return false;
        X509ChainStatusFlags permitted = X509ChainStatusFlags.UntrustedRoot;
        if (allowUnavailable)
            permitted |= X509ChainStatusFlags.OfflineRevocation | X509ChainStatusFlags.RevocationStatusUnknown;
        foreach (X509ChainStatus status in chain.ChainStatus)
            if ((status.Status & ~permitted) != X509ChainStatusFlags.NoError)
                return false;
        DateTime now = DateTime.UtcNow;
        foreach (X509ChainElement element in chain.ChainElements)
            if (now < element.Certificate.NotBefore.ToUniversalTime() || now > element.Certificate.NotAfter.ToUniversalTime())
                return false;
        return true;
    }

    public static int Check(string endpoint, string caPath, bool allowUnavailable)
    {
        Uri uri = new Uri(endpoint, UriKind.Absolute);
        if (uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 || uri.AbsolutePath != "/")
            throw new ArgumentException("HTTPS origin required.");
        string pem = File.ReadAllText(caPath);
        Match match = Regex.Match(pem, @"\A\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*\z");
        if (!match.Success)
            throw new ArgumentException("Exactly one bundled CA certificate is required.");
        using (X509Certificate2 ca = new X509Certificate2(Convert.FromBase64String(match.Groups[1].Value)))
        using (TcpClient tcp = new TcpClient())
        {
            bool isCa = false;
            foreach (X509Extension extension in ca.Extensions)
            {
                if (extension.Oid.Value == "2.5.29.19")
                {
                    X509BasicConstraintsExtension constraints = new X509BasicConstraintsExtension(extension, extension.Critical);
                    isCa = constraints.CertificateAuthority;
                }
            }
            if (!isCa)
                throw new ArgumentException("Bundled certificate is not a CA.");
            var connecting = tcp.ConnectAsync(uri.Host, uri.Port);
            if (!connecting.Wait(10000))
                throw new TimeoutException("Central TLS connection timed out.");
            connecting.GetAwaiter().GetResult();
            tcp.ReceiveTimeout = 20000;
            tcp.SendTimeout = 20000;
            RemoteCertificateValidationCallback validate = delegate(object sender, X509Certificate certificate,
                X509Chain unused, SslPolicyErrors errors)
            {
                // SslStream performs native IP/DNS matching; never waive a name error.
                if (certificate == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
                    return false;
                using (X509Certificate2 leaf = new X509Certificate2(certificate))
                using (X509Chain chain = new X509Chain())
                {
                    chain.ChainPolicy.ExtraStore.Add(ca);
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                    chain.Build(leaf);
                    return AcceptChain(chain, ca, allowUnavailable);
                }
            };
            using (SslStream tls = new SslStream(tcp.GetStream(), false, validate))
            {
                tls.ReadTimeout = 20000;
                tls.WriteTimeout = 20000;
                tls.AuthenticateAsClient(uri.Host, null, SslProtocols.Tls12, true);
                byte[] request = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + uri.Authority + "\r\nConnection: close\r\n\r\n");
                tls.Write(request, 0, request.Length);
                // No credentials or response body are needed for this preflight.
                StringBuilder line = new StringBuilder();
                for (int n = 0; n < 512; n++)
                {
                    int value = tls.ReadByte();
                    if (value < 0)
                        throw new IOException("Missing HTTP status.");
                    if (value == '\n')
                        break;
                    line.Append((char)value);
                }
                Match status = Regex.Match(line.ToString(), @"\AHTTP/1\.[01] (200|401)(?: |\r)");
                if (!status.Success)
                    throw new IOException("Central response must be HTTP 200 or 401.");
                return Int32.Parse(status.Groups[1].Value);
            }
        }
    }
}

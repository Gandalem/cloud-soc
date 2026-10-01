using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

public sealed class CloudSocEnrollmentResponse
{
    public int Status;
    public string Body;
}

// Per-request trust only. Credentials are never arguments to another process.
public static class CloudSocEnrollmentHttp
{
    private static bool AcceptChain(X509Chain chain, X509Certificate2 ca, bool allowUnavailable)
    {
        if (chain.ChainElements.Count == 0)
            return false;
        X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
        bool pinned = Convert.ToBase64String(root.RawData).Equals(Convert.ToBase64String(ca.RawData), StringComparison.Ordinal);
        X509ChainStatusFlags permitted = pinned ? X509ChainStatusFlags.UntrustedRoot : X509ChainStatusFlags.NoError;
        // Revocation compatibility is restricted to this exact private CA.
        if (pinned && allowUnavailable)
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

    public static CloudSocEnrollmentResponse Post(string origin, string path, string caPath,
        bool allowUnavailable, string token, string body)
    {
        Uri uri = new Uri(origin, UriKind.Absolute);
        if (uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.AbsolutePath != "/" ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            (path != "/api/installer/enroll" && path != "/api/installer/receipt" && path != "/api/installer/abort"))
            throw new ArgumentException("Invalid enrollment origin/path.");
        if (!Regex.IsMatch(token, @"\A[a-f0-9]{32}\.[A-Za-z0-9_-]{43}\z"))
            throw new ArgumentException("Invalid enrollment token.");
        Match match = Regex.Match(File.ReadAllText(caPath), @"\A\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*\z");
        if (!match.Success)
            throw new ArgumentException("Exactly one bundled CA required.");
        using (X509Certificate2 ca = new X509Certificate2(Convert.FromBase64String(match.Groups[1].Value)))
        {
            bool isCa = false;
            foreach (X509Extension extension in ca.Extensions)
                if (extension.Oid.Value == "2.5.29.19")
                    isCa = new X509BasicConstraintsExtension(extension, extension.Critical).CertificateAuthority;
            if (!isCa)
                throw new ArgumentException("Bundled certificate is not a CA.");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(origin.TrimEnd('/') + path);
            request.Method = "POST";
            request.AllowAutoRedirect = false;
            request.Proxy = null;
            request.Timeout = 20000;
            request.ReadWriteTimeout = 20000;
            request.MaximumResponseHeadersLength = 16;
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
            request.Headers["X-Cloud-SOC"] = "installer";
            request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate,
                X509Chain supplied, SslPolicyErrors errors)
            {
                if (certificate == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
                    return false;
                // Always rebuild with Online revocation, including public roots.
                using (X509Certificate2 leaf = new X509Certificate2(certificate))
                using (X509Chain chain = new X509Chain())
                {
                    chain.ChainPolicy.ExtraStore.Add(ca);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                    chain.Build(leaf);
                    return AcceptChain(chain, ca, allowUnavailable);
                }
            };
            byte[] data = Encoding.UTF8.GetBytes(body);
            if (data.Length > 8192)
                throw new ArgumentException("Request too large.");
            request.ContentLength = data.Length;
            using (Stream stream = request.GetRequestStream())
                stream.Write(data, 0, data.Length);
            HttpWebResponse response;
            try { response = (HttpWebResponse)request.GetResponse(); }
            catch (WebException error)
            {
                response = error.Response as HttpWebResponse;
                if (response == null)
                    throw new IOException("Enrollment TLS/network request failed.");
            }
            using (response)
            using (Stream stream = response.GetResponseStream())
            using (MemoryStream output = new MemoryStream())
            {
                if (response.ContentLength > 32768)
                    throw new IOException("Enrollment response too large.");
                byte[] buffer = new byte[1024];
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (output.Length + count > 32768)
                        throw new IOException("Enrollment response too large.");
                    output.Write(buffer, 0, count);
                }
                return new CloudSocEnrollmentResponse { Status = (int)response.StatusCode,
                    Body = Encoding.UTF8.GetString(output.ToArray()) };
            }
        }
    }
}

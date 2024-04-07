using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates;

public sealed class CertificateProvider : IDisposable
{
    private bool _disposed;

    private readonly ConcurrentDictionary<string, X509Certificate2> _issuedCertificates;

    public DateTime NotBefore { get; set; } = DateTime.Now;
    public DateTime NotAfter { get; set; } = DateTime.Now.AddMonths(1);

    public ICertificateEngine Engine { get; }
    public X509Certificate2? TrustedRootCA { get; private set; }

    public bool IsDisposingCertificateEngine { get; set; } = true;
    public bool IsDisposingCachedCertificates { get; set; } = true;

    public CertificateProvider()
    {
        _issuedCertificates = [];

        Engine = GetCertificateEngine();
        IsDisposingCertificateEngine = true;
    }
    public CertificateProvider(ICertificateEngine engine, bool ownsEngine = true)
    {
        _issuedCertificates = [];

        Engine = engine;
        IsDisposingCertificateEngine = ownsEngine;
    }

    public X509Certificate2? IssueCertificate(string name)
    {
        if (TrustedRootCA == null)
        {
            throw new InvalidOperationException("Must first add a self-signed certificate authority to the root store before issuing any certificates.");
        }

        if (!_issuedCertificates.TryGetValue(name, out X509Certificate2? certificate))
        {
            certificate = Engine.Create(name, TrustedRootCA, NotBefore, NotAfter);
            if (!_issuedCertificates.TryAdd(name, certificate))
            {
                throw new Exception("Failed to cache the issued certificate: " + certificate);
            }
        }

        return certificate;
    }
    public bool TryCreateTrustedRootCA(string name, string issuerName)
    {
        string subject = $"CN={name}, O={issuerName}";
        if (TrustedRootCA != null && TrustedRootCA.HasPrivateKey && subject == TrustedRootCA.Subject) return true;

        X509Certificate2? trustedRootCA = GetTrustedRootCAFromStore(subject);
        if (trustedRootCA != null && DateTime.Now >= trustedRootCA.NotAfter)
        {
            if (TryRemoveCertificateFromRootStore(trustedRootCA))
            {
                trustedRootCA = null;
            }
        }

        if (trustedRootCA == null)
        {
            X509Certificate2 untrustedRootCA = Engine.CreateSelfSigned(name, issuerName, NotBefore, NotAfter);
            if (TryAddCertificateToRootStore(untrustedRootCA))
            {
                trustedRootCA = untrustedRootCA;
            }
        }

        TrustedRootCA = trustedRootCA;
        return TrustedRootCA != null;
    }
    public bool TryCreateTrustedRootCA(string issuerName) => TryCreateTrustedRootCA($"{issuerName} Root Certificate Authority", issuerName);

    private static ICertificateEngine GetCertificateEngine()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new WindowsCertificateEngine();
        }
        throw new PlatformNotSupportedException("Currently unable to perform certificate generation on current platform.");
    }
    private static X509Certificate2? GetTrustedRootCAFromStore(string subject)
    {
        using var rootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        rootStore.Open(OpenFlags.ReadOnly);

        X509Certificate2? possibleTrustedRootCA;
        for (int i = 0; i < rootStore.Certificates.Count; i++)
        {
            possibleTrustedRootCA = rootStore.Certificates[i];
            if (!possibleTrustedRootCA.HasPrivateKey) continue;
            if (subject != possibleTrustedRootCA.Subject) continue;

            return possibleTrustedRootCA;
        }
        return null;
    }

    private static bool TryAddCertificateToRootStore(X509Certificate2 certificate)
    {
        using var rootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        rootStore.Open(OpenFlags.ReadWrite);

        try { rootStore.Add(certificate); }
        catch { return false; }
        return true;
    }
    private static bool TryRemoveCertificateFromRootStore(X509Certificate2 certificate)
    {
        using var rootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        rootStore.Open(OpenFlags.ReadWrite);

        try { rootStore.Remove(certificate); }
        catch { return false; }
        return true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                if (IsDisposingCertificateEngine)
                {
                    Engine.Dispose();
                }
                TrustedRootCA?.Dispose();

                foreach (X509Certificate2 cachedCertificate in _issuedCertificates.Values)
                {
                    cachedCertificate.Dispose();
                }
                _issuedCertificates.Clear();
            }
            _disposed = true;
        }
    }
}

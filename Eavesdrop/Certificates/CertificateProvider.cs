using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using Eavesdrop.Certificates.Linux;
using Eavesdrop.Certificates.Windows;

namespace Eavesdrop.Certificates;

public sealed class CertificateProvider : IDisposable
{
    private bool _disposed;

    private readonly ConcurrentDictionary<string, X509Certificate2> _issuedCertificates;

    public DateTime NotBefore { get; set; } = DateTime.Now;
    public DateTime NotAfter { get; set; } = DateTime.Now.AddMonths(1);

    public ICertificateEngine Engine { get; }
    public bool IsRootCATrusted { get; private set; }
    public X509Certificate2? RootCertificateAuthority { get; private set; }

    public bool IsDisposingCertificateEngine { get; set; } = true;
    public bool IsDisposingCachedCertificates { get; set; } = true;

    public CertificateProvider()
        : this(GetCertificateEngine(), true)
    { }
    public CertificateProvider(ICertificateEngine engine, bool ownsEngine = true)
    {
        _issuedCertificates = [];

        Engine = engine;
        IsDisposingCertificateEngine = ownsEngine;
    }

    public X509Certificate2? IssueCertificate(string name)
    {
        return _issuedCertificates.GetOrAdd(name, CreateCertificate);
    }
    private X509Certificate2 CreateCertificate(string name)
    {
        return RootCertificateAuthority != null
            ? Engine.Create(name, RootCertificateAuthority, NotBefore, NotAfter)
            : throw new InvalidOperationException("Must first add a self-signed certificate authority to the root store before issuing any certificates.");
    }

    public bool TryCreateTrustedRootCA(string organization, string commonName, bool addToUserStore = true)
    {
        string subject = $"CN={commonName}, O={organization}";
        if (RootCertificateAuthority != null && RootCertificateAuthority.HasPrivateKey && subject == RootCertificateAuthority.Subject) return true;

        X509Certificate2? rootCA = GetTrustedRootCAFromStore(subject);
        if (rootCA != null) // Check for existing trusted CA
        {
            // Ensure CA is still valid
            IsRootCATrusted = DateTime.Now < rootCA.NotAfter;
            if (!IsRootCATrusted)
            {
                // Remove expired/invalid CA
                _ = TryRemoveCertificateFromRootStore(rootCA);
                rootCA = null;
            }
        }

        // Attempt to generate, and add CA to trusted user store if necessary.
        if (rootCA == null)
        {
            rootCA = Engine.CreateSelfSigned(commonName, organization, NotBefore, NotAfter);
            IsRootCATrusted = addToUserStore && TryAddCertificateToRootStore(RootCertificateAuthority);
        }

        RootCertificateAuthority = rootCA;
        return RootCertificateAuthority != null;
    }
    public bool TryCreateTrustedRootCA(string organization) => TryCreateTrustedRootCA(organization, $"{organization} Root Certificate Authority");

    private static ICertificateEngine GetCertificateEngine()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new WindowsCertificateEngine();
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return new LinuxCertificateEngine();
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
        if (!disposing || _disposed) return;

        if (IsDisposingCertificateEngine)
        {
            Engine.Dispose();
        }
        RootCertificateAuthority?.Dispose();

        if (IsDisposingCachedCertificates)
        {
            foreach (X509Certificate2 cachedCertificate in _issuedCertificates.Values)
            {
                cachedCertificate.Dispose();
            }
        }
        _issuedCertificates.Clear();
        _disposed = true;
    }
}
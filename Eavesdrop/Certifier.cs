using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

#if NETSTANDARD2_0
using System.Collections.ObjectModel;
#endif

namespace Eavesdrop;

public sealed class Certifier : ICertifier, IDisposable
{
    private const int KEY_SIZE = 2048;

    private readonly RSA _sharedKeys;
    private readonly X509Store _rootStore, _myStore;
    private readonly IDictionary<string, X509Certificate2> _certificateCache;

    public string Issuer { get; }
    public string CertificateAuthorityName { get; }

    public DateTime NotAfter { get; set; }
    public DateTime NotBefore { get; set; }
    public bool IsCachingSignedCertificates { get; set; }

    public X509Certificate2? Authority { get; private set; }

    public Certifier()
        : this("Eavesdrop")
    { }
    public Certifier(string issuer)
        : this(issuer, $"{issuer} Root Certificate Authority", StoreLocation.CurrentUser)
    { }
    public Certifier(string issuer, string certificateAuthorityName)
        : this(issuer, certificateAuthorityName, StoreLocation.CurrentUser)
    { }
    public Certifier(string issuer, string certificateAuthorityName, StoreLocation location)
    {
        _sharedKeys = RSA.Create();
        _sharedKeys.KeySize = KEY_SIZE;

        _myStore = new X509Store(StoreName.My, location);
        _rootStore = new X509Store(StoreName.Root, location);
        _certificateCache = new Dictionary<string, X509Certificate2>();

        NotBefore = DateTime.Now;
        NotAfter = NotBefore.AddMonths(1);

        Issuer = issuer;
        CertificateAuthorityName = certificateAuthorityName;
    }

    public bool CreateTrustedRootCertificate()
    {
        return (Authority = InstallCertificate(_rootStore, CertificateAuthorityName)) != null;
    }
    public bool DestroyTrustedRootCertificate()
    {
        return DestroyCertificates(_rootStore);
    }
    public bool ExportTrustedRootCertificate(string path)
    {
        X509Certificate2? rootCertificate = InstallCertificate(_rootStore, CertificateAuthorityName);

        path = Path.GetFullPath(path);
        if (rootCertificate != null)
        {
            byte[] data = rootCertificate.Export(X509ContentType.Cert);
            File.WriteAllBytes(path, data);
        }
        return File.Exists(path);
    }

    public X509Certificate2? GenerateCertificate(string certificateName)
    {
        return InstallCertificate(_myStore, certificateName);
    }

#if NETSTANDARD2_0
    private X509Certificate2 CreateCertificate(string subjectName, string alternateName)
    {
        Type certificateRequestType = typeof(RSACertificateExtensions).Assembly.GetType("System.Security.Cryptography.X509Certificates.CertificateRequest");
        object request = certificateRequestType.GetConstructor([typeof(string), typeof(RSA), typeof(HashAlgorithmName), typeof(RSASignaturePadding)])
            .Invoke([subjectName, _sharedKeys, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1]);

        var publicKey = (PublicKey)certificateRequestType.GetProperty("PublicKey").GetValue(request);
        var extensions = (Collection<X509Extension>)certificateRequestType.GetProperty("CertificateExtensions").GetValue(request);
        extensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        extensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, false));

        if (Authority == null)
        {
            using var certificate = (X509Certificate2)certificateRequestType.GetMethod("CreateSelfSigned")
                .Invoke(request, [(DateTimeOffset)NotBefore, (DateTimeOffset)NotAfter]);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                certificate.FriendlyName = alternateName;
            }
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
        else
        {
            Type subjectAlternateNameBuilderType = typeof(RSACertificateExtensions).Assembly.GetType("System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder");
            object sanBuilder = subjectAlternateNameBuilderType.GetConstructor([]).Invoke(null);
            subjectAlternateNameBuilderType.GetMethod("AddDnsName").Invoke(sanBuilder, [alternateName]);

            extensions.Add((X509Extension)subjectAlternateNameBuilderType.GetMethod("Build").Invoke(sanBuilder, [false]));

            using var certificate = (X509Certificate2)certificateRequestType
                .GetMethod("Create", [typeof(X509Certificate2), typeof(DateTimeOffset), typeof(DateTimeOffset), typeof(byte[])])
                .Invoke(request, [Authority, (DateTimeOffset)Authority.NotBefore, (DateTimeOffset)Authority.NotAfter, Guid.NewGuid().ToByteArray()]);

            // TODO: Copy with private key

            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
    }
#elif NET6_0_OR_GREATER
    public X509Certificate2 CreateCertificate(string subjectName, string alternateName)
    {
        var certificateRequest = new CertificateRequest(subjectName, _sharedKeys, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (Authority == null)
        {
            certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

            using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(NotBefore.ToUniversalTime(), NotAfter.ToUniversalTime());

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                certificate.FriendlyName = alternateName;
            }
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
        else
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(alternateName);

            certificateRequest.CertificateExtensions.Add(sanBuilder.Build());
            certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

            using X509Certificate2 certificate = certificateRequest.Create(Authority, Authority.NotBefore, Authority.NotAfter, Guid.NewGuid().ToByteArray());
            using X509Certificate2 certificateWithPrivateKey = certificate.CopyWithPrivateKey(_sharedKeys);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                certificateWithPrivateKey.FriendlyName = alternateName;
            }
            return new X509Certificate2(certificateWithPrivateKey.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
    }
#endif

    private X509Certificate2? InstallCertificate(X509Store store, string certificateName)
    {
        if (_certificateCache.TryGetValue(certificateName, out X509Certificate2? certificate))
        {
            if (DateTime.Now >= certificate.NotAfter)
            {
                _certificateCache.Remove(certificateName);
            }
            else return certificate;
        }
        lock (store)
        {
            try
            {
                store.Open(OpenFlags.ReadWrite);
                string subjectName = $"CN={certificateName}, O={Issuer}";

                certificate = FindCertificates(store, subjectName)?[0];
                if (certificate != null && DateTime.Now >= certificate.NotAfter)
                {
                    if (Authority == null)
                    {
                        DestroyCertificates();
                        store.Open(OpenFlags.ReadWrite);
                    }
                    else
                    {
                        store.Remove(certificate);
                    }
                    certificate = null;
                }

                if (certificate == null)
                {
                    certificate = CreateCertificate(subjectName, certificateName);
                    if (certificate != null)
                    {
                        if (store == _rootStore || IsCachingSignedCertificates)
                        {
                            store.Add(certificate);
                        }
                    }
                }

                return certificate;
            }
            catch { return certificate = null; }
            finally
            {
                store.Close();
                if (certificate != null && !_certificateCache.ContainsKey(certificateName))
                {
                    _certificateCache.Add(certificateName, certificate);
                }
            }
        }
    }

    public bool DestroyCertificates(X509Store store)
    {
        lock (store)
        {
            try
            {
                store.Open(OpenFlags.ReadWrite);
                X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByIssuerName, Issuer, false);

                store.RemoveRange(certificates);
                IEnumerable<string> subjectNames = certificates.Cast<X509Certificate2>().Select(c => c.GetNameInfo(X509NameType.SimpleName, false));

                foreach (string subjectName in subjectNames)
                {
                    if (!_certificateCache.ContainsKey(subjectName)) continue;
                    _certificateCache.Remove(subjectName);
                }
                return true;
            }
            catch { return false; }
            finally { store.Close(); }
        }
    }
    public bool DestroyCertificates() => DestroyCertificates(_myStore) && DestroyCertificates(_rootStore);

    private static X509Certificate2Collection? FindCertificates(X509Store store, string subjectName)
    {
        X509Certificate2Collection certificates = store.Certificates
            .Find(X509FindType.FindBySubjectDistinguishedName, subjectName, false);

        return certificates.Count > 0 ? certificates : null;
    }

    public void Dispose()
    {
        _myStore.Close();
        _rootStore.Close();

        _myStore.Dispose();
        _rootStore.Dispose();
    }
}
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates.Windows;

[SupportedOSPlatform("Windows")]
public sealed partial class WindowsCertificateEngine
{
    public WindowsCertificateEngine(RSA rsa)
    {
        _rsa = rsa;
    }
    public WindowsCertificateEngine(int keySize)
    {
        _rsa = RSA.Create(keySize);
    }

    private X509Certificate2 ConductCertificateRequest(string subjectName, string alternativeName, X509Certificate2? issuerCertificate, DateTime notBefore, DateTime notAfter)
    {
        X509Certificate2? certificateToExport = null;
        var certificateRequest = new CertificateRequest(subjectName, _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

        if (issuerCertificate != null)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(alternativeName);

            certificateRequest.CertificateExtensions.Add(sanBuilder.Build());

            using X509Certificate2 certificate = certificateRequest.Create(
                issuerCertificate, issuerCertificate.NotBefore, issuerCertificate.NotAfter, Guid.NewGuid().ToByteArray());

            certificateToExport = certificate.CopyWithPrivateKey(_rsa);
        }
        else
        {
            certificateToExport = certificateRequest.CreateSelfSigned(
                notBefore.ToUniversalTime(), notAfter.ToUniversalTime());
        }

        using (certificateToExport)
        {
            certificateToExport.FriendlyName = alternativeName;
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(certificateToExport.Export(X509ContentType.Pfx, string.Empty),
                string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
#else
            return new X509Certificate2(certificateToExport.Export(X509ContentType.Pfx, string.Empty),
                string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
#endif
        }
    }

    private void Dispose(bool disposing)
    {
        if (!disposing || _disposed) return;

        _rsa.Dispose();
        _disposed = true;
    }
}
#endif
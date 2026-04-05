#if NET5_0_OR_GREATER
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates.Windows;

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
        var certificateRequest = new CertificateRequest(subjectName, _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (issuerCertificate == null)
        {
            certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

            using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(notBefore.ToUniversalTime(), notAfter.ToUniversalTime());

            certificate.FriendlyName = alternativeName;
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
        else
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(alternativeName);

            certificateRequest.CertificateExtensions.Add(sanBuilder.Build());
            certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

            using X509Certificate2 certificate = certificateRequest.Create(issuerCertificate, issuerCertificate.NotBefore, issuerCertificate.NotAfter, Guid.NewGuid().ToByteArray());
            using X509Certificate2 certificateWithPrivateKey = certificate.CopyWithPrivateKey(_rsa);

            certificateWithPrivateKey.FriendlyName = alternativeName;
            return new X509Certificate2(certificateWithPrivateKey.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
    }

    private void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _rsa.Dispose();
            }
            _disposed = true;
        }
    }
}
#endif
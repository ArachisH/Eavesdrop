using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates;

public sealed partial class WindowsCertificateEngine : ICertificateEngine
{
    const int DEFAULT_RSA_KEY_SIZE = 1024;

    private readonly RSA _rsa;

    private bool _disposed;

    public WindowsCertificateEngine()
        : this(DEFAULT_RSA_KEY_SIZE)
    { }

    public X509Certificate2 CreateSelfSigned(string name, string issuerName, DateTime notBefore, DateTime notAfter)
    {
        return Create(name, issuerName, null, notBefore, notAfter, true);
    }
    public X509Certificate2 Create(string name, X509Certificate2 issuerCertificate, DateTime notBefore, DateTime notAfter)
    {
        return Create(name, issuerCertificate.IssuerName.Name, issuerCertificate, notBefore, notAfter, false);
    }

    private X509Certificate2 Create(string name, string issuerName, X509Certificate2? issuerCertificate, DateTime notBefore, DateTime notAfter, bool isSelfSigning)
    {
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(issuerName))
        {
            throw new Exception("The provided name for the certificate are not valid.");
        }

        if (!isSelfSigning && issuerCertificate == null)
        {
            throw new NullReferenceException("Issuing certificate required when not creating a self-signed certificate.");
        }

        string subjectName = $"CN={name}, O={issuerName}";
        return ConductCertificateRequest(subjectName, name, issuerCertificate, notBefore, notAfter);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
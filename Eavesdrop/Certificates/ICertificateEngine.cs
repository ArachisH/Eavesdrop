using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates;

public interface ICertificateEngine : IDisposable
{
    X509Certificate2 CreateSelfSigned(string name, string issuerName, DateTime notBefore, DateTime notAfter);
    X509Certificate2 Create(string name, X509Certificate2 issuerCertificate, DateTime notBefore, DateTime notAfter);
}
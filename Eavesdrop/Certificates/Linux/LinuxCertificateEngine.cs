using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates.Linux;

public sealed class LinuxCertificateEngine : ICertificateEngine
{
    private bool _disposed;

    public X509Certificate2 CreateSelfSigned(string name, string issuerName, DateTime notBefore, DateTime notAfter)
    {
        throw new NotImplementedException();
    }
    public X509Certificate2 Create(string name, X509Certificate2 issuerCertificate, DateTime notBefore, DateTime notAfter)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        Dispose(true);
    }
    private void Dispose(bool disposing)
    {
        if (!disposing || _disposed) return;
        // TODO: Disposed managed objects.
        _disposed = true;
    }
}
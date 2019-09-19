using System;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates
{
    public interface ICertificateEngine
    {
        int KeyLength { get; set; }
        DateTime NotAfter { get; set; }
        DateTime NotBefore { get; set; }

        X509Certificate2 CreateCertificate(string subjectName, string alternateName, X509Certificate2 authority);
    }
}
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop;

public interface ICertifier
{
    X509Certificate2? GenerateCertificate(string certificateName);
}
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates
{
    public class WindowsCertificateEngine : ICertificateEngine
    {
        public DateTime NotAfter { get; set; }
        public DateTime NotBefore { get; set; }
        public int KeyLength { get; set; } = 1024;

        public WindowsCertificateEngine()
        {
            NotBefore = DateTime.Now;
            NotAfter = NotBefore.AddMonths(1);
        }

        public X509Certificate2 CreateCertificate(string subjectName, string alternateName, X509Certificate2 authority)
        {
            var rsa = authority == null
                ? new RSACryptoServiceProvider(KeyLength)
                : new RSACryptoServiceProvider(KeyLength, new CspParameters(1, "Microsoft Base Cryptographic Provider v1.0", Guid.NewGuid().ToString()));

            if (authority == null)
            {
                var authorityCertificateRequest = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                authorityCertificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                authorityCertificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(authorityCertificateRequest.PublicKey, false));

                authority = authorityCertificateRequest.CreateSelfSigned(NotBefore.ToUniversalTime(), NotAfter.ToUniversalTime());
                return new X509Certificate2(authority.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }
            else
            {
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(alternateName);

                var certificateRequest = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                certificateRequest.CertificateExtensions.Add(sanBuilder.Build());
                certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, true));
                certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
                certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

                X509Certificate2 certificate = certificateRequest.Create(authority, authority.NotBefore.ToUniversalTime(), authority.NotAfter.ToUniversalTime(), Guid.NewGuid().ToByteArray());
                certificate = certificate.CopyWithPrivateKey(rsa);

                return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }
        }
    }
}
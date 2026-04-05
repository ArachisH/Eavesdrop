#if NETSTANDARD2_0
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Certificates.Windows;

public sealed partial class WindowsCertificateEngine
{
    private readonly RSA _rsaWithPrivate;

    // CertificateRequest Reflection Traits
    private static readonly Type CertificateRequestType;
    private static readonly ConstructorInfo CertificateRequestConstructor;
    private static readonly MethodInfo CreateMethod;
    private static readonly MethodInfo CreateSelfSignedMethod;
    private static readonly PropertyInfo PublicKeyProperty;
    private static readonly PropertyInfo CertificateExtensionsProperty;

    // SubjectAlternativeNameBuilder Reflection Traits
    private static readonly Type SubjectAlternativeNameBuilderType;
    private static readonly ConstructorInfo SubjectAlternativeNameBuilderConstructor;
    private static readonly MethodInfo AddDnsNameMethod;
    private static readonly MethodInfo BuildMethod;

    public WindowsCertificateEngine(RSA rsa)
    {
        _rsa = rsa;
        _rsaWithPrivate = GetWithPrivateKey(_rsa);
    }
    public WindowsCertificateEngine(int keySize)
    {
        _rsa = new RSACryptoServiceProvider(keySize);
        _rsaWithPrivate = GetWithPrivateKey(_rsa);
    }

    static WindowsCertificateEngine()
    {
        CertificateRequestType = typeof(RSACertificateExtensions).Assembly.GetType("System.Security.Cryptography.X509Certificates.CertificateRequest");
        CertificateRequestConstructor = CertificateRequestType.GetConstructor([typeof(string), typeof(RSA), typeof(HashAlgorithmName), typeof(RSASignaturePadding)]);
        CreateMethod = CertificateRequestType.GetMethod("Create", [typeof(X509Certificate2), typeof(DateTimeOffset), typeof(DateTimeOffset), typeof(byte[])]);
        CertificateExtensionsProperty = CertificateRequestType.GetProperty("CertificateExtensions");
        CreateSelfSignedMethod = CertificateRequestType.GetMethod("CreateSelfSigned");
        PublicKeyProperty = CertificateRequestType.GetProperty("PublicKey");

        SubjectAlternativeNameBuilderType = typeof(RSACertificateExtensions).Assembly.GetType("System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder");
        SubjectAlternativeNameBuilderConstructor = SubjectAlternativeNameBuilderType.GetConstructor([]);
        AddDnsNameMethod = SubjectAlternativeNameBuilderType.GetMethod("AddDnsName");
        BuildMethod = SubjectAlternativeNameBuilderType.GetMethod("Build");
    }

    private X509Certificate2 ConductCertificateRequest(string subjectName, string alternativeName, X509Certificate2? issuerCertificate, DateTime notBefore, DateTime notAfter)
    {
        object request = CertificateRequestConstructor.Invoke([subjectName, _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1]);

        var publicKey = (PublicKey)PublicKeyProperty.GetValue(request);
        var extensions = (Collection<X509Extension>)CertificateExtensionsProperty.GetValue(request);
        extensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        extensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, false));

        if (issuerCertificate == null)
        {
            using var certificate = (X509Certificate2)CreateSelfSignedMethod.Invoke(request, [(DateTimeOffset)notBefore, (DateTimeOffset)notAfter]);
            certificate.FriendlyName = alternativeName;

            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
        else
        {
            object sanBuilder = SubjectAlternativeNameBuilderConstructor.Invoke(null);
            AddDnsNameMethod.Invoke(sanBuilder, [alternativeName]);
            extensions.Add((X509Extension)BuildMethod.Invoke(sanBuilder, [false]));

            using var certificate = (X509Certificate2)CreateMethod.Invoke(request,
                [issuerCertificate, (DateTimeOffset)issuerCertificate.NotBefore, (DateTimeOffset)issuerCertificate.NotAfter, Guid.NewGuid().ToByteArray()]);

            certificate.PrivateKey = _rsaWithPrivate;
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, string.Empty), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
    }

    private static RSA GetWithPrivateKey(RSA rsa)
    {
        // Create an RSA instance that exposes the private keys by default when applying to a certificate.
        var privateKeyParams = new CspParameters
        {
            Flags = CspProviderFlags.NoFlags,
            KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant(),
            ProviderType = Environment.OSVersion.Version.Major > 5 || Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1 ? 0x18 : 1
        };

        var _rsaWithPrivateKey = new RSACryptoServiceProvider(privateKeyParams);
        _rsaWithPrivateKey.ImportParameters(rsa.ExportParameters(true));

        return _rsaWithPrivateKey;
    }

    private void Dispose(bool disposing)
    {
        if (!disposing || _disposed) return;

        _rsa.Dispose();
        _rsaWithPrivate.Dispose();
        _disposed = true;
    }
}
#endif
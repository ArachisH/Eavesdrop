using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

#if !NET5_0_OR_GREATER
using System.Reflection;
using System.Collections.ObjectModel;
#endif

namespace Eavesdrop.Tests.Certificates;

public sealed class SelfSignedCertificateHandler : ICertifier
{
#if !NET5_0_OR_GREATER
    #region CertificateRequest Reflection Traits
    private static readonly Type CertificateRequestType;
    private static readonly ConstructorInfo CertificateRequestConstructor;
    private static readonly MethodInfo CreateSelfSignedMethod;
    private static readonly PropertyInfo PublicKeyProperty;
    private static readonly PropertyInfo CertificateExtensionsProperty;
    #endregion

    static SelfSignedCertificateHandler()
    {
        CertificateRequestType = typeof(RSACertificateExtensions).Assembly.GetType("System.Security.Cryptography.X509Certificates.CertificateRequest");
        CertificateRequestConstructor = CertificateRequestType.GetConstructor([typeof(string), typeof(RSA), typeof(HashAlgorithmName), typeof(RSASignaturePadding)]);
        CertificateExtensionsProperty = CertificateRequestType.GetProperty("CertificateExtensions");
        CreateSelfSignedMethod = CertificateRequestType.GetMethod("CreateSelfSigned");
        PublicKeyProperty = CertificateRequestType.GetProperty("PublicKey");
    }
#endif

#if NET5_0_OR_GREATER
    public X509Certificate2 GenerateCertificate(string certificateName)
    {
        using var rsa = RSA.Create();
        rsa.KeySize = 1024;

        var certificateRequest = new CertificateRequest($"CN={certificateName}, O=EavesNodeTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

        using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(DateTime.Now, DateTime.Now.AddDays(1));
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = certificateName;
        }
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
    }
#else
    public X509Certificate2 GenerateCertificate(string certificateName)
    {
        using var rsa = RSA.Create();
        rsa.KeySize = 1024;

        object request = CertificateRequestConstructor.Invoke([$"CN={certificateName}, O=EavesNodeTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1]);

        var publicKey = (PublicKey)PublicKeyProperty.GetValue(request);
        var extensions = (Collection<X509Extension>)CertificateExtensionsProperty.GetValue(request);
        extensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        extensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, false));

        using var certificate = (X509Certificate2)CreateSelfSignedMethod.Invoke(request, [(DateTimeOffset)DateTime.Now, (DateTimeOffset)DateTime.Now.AddDays(1)]);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = certificateName;
        }
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
    }
#endif
}
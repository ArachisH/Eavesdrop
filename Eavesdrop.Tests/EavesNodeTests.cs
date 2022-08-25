using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Eavesdrop.Network;

namespace Eavesdrop.Tests;

public class EavesNodeTests
{
    private sealed class SelfSignedCertifier : ICertifier
    {
        public X509Certificate2? GenerateCertificate(string certificateName)
        {
            using var rsa = RSA.Create(1024);

            var certificateRequest = new CertificateRequest($"CN={certificateName}, O=EavesNodeTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

            using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(DateTime.Now, DateTime.Now.AddDays(1));

            certificate.FriendlyName = certificateName;
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
        }
    }

    public async Task<(Socket Client, Socket Server)> CreateConnectedPairAsync()
    {
        using Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();

        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(listener.LocalEndPoint!);
        var server = await listener.AcceptAsync();

        return (client, server);
    }

    public async Task<SslStream> AuthenticateAsClientAsync(Stream clientStream, string hostname, 
        RemoteCertificateValidationCallback? validationCallback = default)
    {
        await clientStream.WriteAsync(Encoding.UTF8.GetBytes($"CONNECT {hostname}:443 HTTP/1.1\r\n\r\n"));
        await clientStream.FlushAsync();

        byte[] okBytesBuffer = new byte[32];
        int read = await clientStream.ReadAsync(okBytesBuffer);

        string okResponse = Encoding.UTF8.GetString(okBytesBuffer[..read]);
        Assert.Equal("HTTP/1.1 200 OK\r\n\r\n", okResponse);

        var sslClientStream = new SslStream(clientStream, false,
            new RemoteCertificateValidationCallback(static (_, _, _, _) => true));

        await sslClientStream.AuthenticateAsClientAsync(hostname, null, false);
        Assert.True(sslClientStream.IsAuthenticated);

        return sslClientStream;
    }

    [Fact]
    public async Task InterceptGetRequest_Http_RequestLineWithAbsoluteUri()
    {
        var (client, server) = await CreateConnectedPairAsync();

        using var node = new EavesNode(server, null);
        using var clientStream = new NetworkStream(client, true);

        await clientStream.WriteAsync("GET http://example.com/foo HTTP/1.1\r\nHost: example.com\r\n\r\n"u8.ToArray());

        var request = await node.ReceiveHttpRequestAsync();
        
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(HttpVersion.Version11, request.Version);
        Assert.Equal("http://example.com/foo", request.RequestUri?.ToString());
    }

    [Fact]
    public async Task InterceptGetRequest_Https_RequestLineWithRelativePath()
    {
        var emptyCertifier = new SelfSignedCertifier();
        var (client, server) = await CreateConnectedPairAsync();

        using var node = new EavesNode(server, emptyCertifier);
        using var clientStream = new NetworkStream(client, true);

        Task<HttpRequestMessage> serverReceiveTask = node.ReceiveHttpRequestAsync();

        using var sslClientStream = await AuthenticateAsClientAsync(clientStream, "example.com");
        await sslClientStream.WriteAsync("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n"u8.ToArray());

        var request = await serverReceiveTask;

        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(HttpVersion.Version11, request.Version);
        Assert.Equal("https://example.com/foo", request.RequestUri?.ToString());
    }
}
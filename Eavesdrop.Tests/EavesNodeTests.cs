using System.IO;
using System.Net;
using System.Text;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.Security;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using Eavesdrop.Network;
using Eavesdrop.Tests.Certificates;

namespace Eavesdrop.Tests;

public class EavesNodeTests
{
    [Fact]
    public async Task InterceptGetRequest_Http_RequestLineWithAbsoluteUri()
    {
        var (client, server) = await CreateConnectedPairAsync();

        using var node = new EavesNode(server, null);
        using var clientStream = new NetworkStream(client, true);

        byte[] getBytes = Encoding.UTF8.GetBytes("GET http://example.com/foo HTTP/1.1\r\nHost: example.com\r\n\r\n");
        await clientStream.WriteAsync(getBytes, 0, getBytes.Length);

        var request = await node.ReceiveHttpRequestAsync();

        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("http://example.com/foo", request.RequestUri?.ToString());
    }

    [Fact]
    public async Task InterceptGetRequest_Https_RequestLineWithRelativePath()
    {
        /*
         * [xUnit.net 00:00:00.64]     Eavesdrop.Tests.EavesNodeTests.InterceptGetRequest_Https_RequestLineWithRelativePath [FAIL]
         * Failed Eavesdrop.Tests.EavesNodeTests.InterceptGetRequest_Https_RequestLineWithRelativePath [127 ms]
         * Error Message: System.Security.Authentication.AuthenticationException : Authentication failed, see inner exception. 
         * ---- Interop+OpenSsl+SslException : SSL Handshake failed with OpenSSL error - SSL_ERROR_SSL. 
         * -------- Interop+Crypto+OpenSslCryptographicException : error:1409442E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version 
         * Stack Trace: 
         * at System.Net.Security.SslStream.ForceAuthenticationAsync[TIOAdapter](Boolean receiveFirst, Byte[] reAuthenticationData, CancellationToken cancellationToken) 
         * at Eavesdrop.Tests.EavesNodeTests.AuthenticateAsClientAsync(Stream clientStream, String hostname, RemoteCertificateValidationCallback validationCallback) in /Eavesdrop/Eavesdrop.Tests/EavesNodeTests.cs:line 63 
         * at Eavesdrop.Tests.EavesNodeTests.InterceptGetRequest_Https_RequestLineWithRelativePath() in /Eavesdrop/Eavesdrop.Tests/EavesNodeTests.cs:line 99 
         * --- End of stack trace from previous location ---
         * ----- Inner Stack Trace -----
         * at Interop.OpenSsl.DoSslHandshake(SafeSslHandle context, ReadOnlySpan`1 input, Byte[]& sendBuf, Int32& sendCount)
         * at System.Net.Security.SslStreamPal.HandshakeInternal(SafeDeleteSslContext& context, ReadOnlySpan`1 inputBuffer, Byte[]& outputBuffer, SslAuthenticationOptions sslAuthenticationOptions, SelectClientCertificate clientCertificateSelectionCallback)
         * ----- Inner Stack Trace -----
         * Although Windows support is the primary focus for this project, it would be nice to have it work on linux systems.
         */
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        var emptyCertifier = new SelfSignedCertificateHandler();
        var (client, server) = await CreateConnectedPairAsync();

        using var node = new EavesNode(server, emptyCertifier, false);
        using var clientStream = new NetworkStream(client, true);

        Task<HttpRequestMessage> serverReceiveTask = node.ReceiveHttpRequestAsync();

        using var sslClientStream = await AuthenticateAsClientAsync(clientStream, "example.com");
        byte[] getBytes = Encoding.UTF8.GetBytes("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n");
        await sslClientStream.WriteAsync(getBytes, 0, getBytes.Length);

        var request = await serverReceiveTask;

        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://example.com/foo", request.RequestUri?.ToString());
    }

    private static async Task<(Socket Client, Socket Server)> CreateConnectedPairAsync()
    {
        using Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);

        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(listener.LocalEndPoint!);
        var server = await listener.AcceptAsync();

        return (client, server);
    }
    private static async Task<SslStream> AuthenticateAsClientAsync(Stream clientStream, string hostname, RemoteCertificateValidationCallback? validationCallback = default)
    {
        byte[] connectBytes = Encoding.UTF8.GetBytes($"CONNECT {hostname}:443 HTTP/1.1\r\n\r\n");

        await clientStream.WriteAsync(connectBytes, 0, connectBytes.Length);
        await clientStream.FlushAsync();

        byte[] okBytesBuffer = new byte[32];
        int read = await clientStream.ReadAsync(okBytesBuffer, 0, okBytesBuffer.Length);

        string okResponse = Encoding.UTF8.GetString(okBytesBuffer, 0, read);
        Assert.Equal("HTTP/1.1 200 OK\r\n\r\n", okResponse);

        var sslClientStream = new SslStream(clientStream, false,
            validationCallback ?? (static (_, _, _, _) => true));

        await sslClientStream.AuthenticateAsClientAsync(hostname);
        Assert.True(sslClientStream.IsAuthenticated);

        return sslClientStream;
    }
}
using System.Net;
using System.Text;
using System.Buffers;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Eavesdrop.Network.Http;

namespace Eavesdrop.Network;

public sealed class EavesNode : IDisposable
{
    private const short MINIMUM_HTTP_BUFFER_SIZE = 1024;

    private static readonly Dictionary<string, HttpMethod> _httpMethodTable;
    private static readonly HttpResponseMessage _okResponse = new(HttpStatusCode.OK);

    private static ReadOnlySpan<byte> _eolBytes => "\r\n"u8;
    private static ReadOnlySpan<byte> _eofBytes => "\r\n\r\n"u8;

    private readonly ICertifier? _certifier;

    private bool _disposed;
    private Stream _stream;

    public Stream Stream => _stream;
    public bool IsHandlingConnectRequests { get; }
    public bool IsSecure => _stream is SslStream sslStream && sslStream.IsAuthenticated;

    static EavesNode()
    {
        _httpMethodTable = new Dictionary<string, HttpMethod>(9)
        {
            ["DELETE"] = HttpMethod.Delete,
            ["GET"] = HttpMethod.Get,
            ["HEAD"] = HttpMethod.Head,
            ["OPTIONS"] = HttpMethod.Options,
            ["POST"] = HttpMethod.Post,
            ["PUT"] = HttpMethod.Put,
            ["TRACE"] = HttpMethod.Trace,

            // Compatibility for .NET Standard 2.0
            ["PATCH"] = AdditionalHttpMethods.Patch,
            ["CONNECT"] = AdditionalHttpMethods.Connect
        };
    }
    public EavesNode(Socket socket, ICertifier? certifier, bool isHandlingConnectRequests = true)
    {
        IsHandlingConnectRequests = isHandlingConnectRequests;

        socket.NoDelay = true;

        _certifier = certifier;
        _stream = new NetworkStream(socket, ownsSocket: true);
    }

    public async Task<HttpRequestMessage> ReceiveHttpRequestAsync(CancellationToken cancellationToken = default)
    {
        using var firstBufferedHttpSegment = new BufferedHttpSegment(MINIMUM_HTTP_BUFFER_SIZE, out Memory<byte> buffer);
        BufferedHttpSegment lastBufferedHttpSegment = firstBufferedHttpSegment;

        Uri? baseUri = null;
        HttpRequestMessage? request = null;
        while (_stream.CanRead && request == null)
        {
            int bytesRead = await _stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (!TryParseHttpRequest(firstBufferedHttpSegment, lastBufferedHttpSegment, baseUri, out request, out int unconsumedBytes))
            {
                lastBufferedHttpSegment = lastBufferedHttpSegment.Grow(MINIMUM_HTTP_BUFFER_SIZE, out buffer);
                continue;
            }

            if (request?.Method == AdditionalHttpMethods.Connect && request.RequestUri != null)
            {
                // Return the raw CONNECT request so that it may instead be forwarded to another proxy server.
                if (IsHandlingConnectRequests) return request;

                await SendHttpResponseAsync(_okResponse, cancellationToken).ConfigureAwait(false);
                if (_certifier == null)
                {
                    throw new NotSupportedException("Cannot process HTTPS upgrade without a certifier.");
                }

                X509Certificate2? certificate = _certifier?.GenerateCertificate(request.RequestUri.DnsSafeHost);
                if (certificate == null)
                {
                    throw new NullReferenceException($"Failed to generate a self-signed certificate for '{request.RequestUri.DnsSafeHost}'.");
                }

                var sslStream = new SslStream(_stream);
#if !NETSTANDARD2_0
                var sslOptions = new SslServerAuthenticationOptions()
                {
                    ServerCertificate = certificate
                };
                await sslStream.AuthenticateAsServerAsync(sslOptions, cancellationToken).ConfigureAwait(false);
#else
                await sslStream.AuthenticateAsServerAsync(certificate).ConfigureAwait(false);
#endif
                _stream = sslStream;

                baseUri = request.RequestUri;
                request.Dispose();
                request = null;

                firstBufferedHttpSegment.Collapse();
                lastBufferedHttpSegment = firstBufferedHttpSegment;
            }
            else if (unconsumedBytes > 0 && request?.Content?.Headers.ContentLength != null)
            {
                int unconsumedStart = buffer.Length - unconsumedBytes;
                ReadOnlyMemory<byte> unconsumed = lastBufferedHttpSegment.Memory.Slice(unconsumedStart, bytesRead - unconsumedStart);
                await BufferHttpRequestContentAsync(request, unconsumed, _stream, cancellationToken).ConfigureAwait(false);
            }
        }

        return request ?? throw new NullReferenceException("Failed to parse the HTTP request.");
    }
    public async Task SendHttpResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken = default)
    {
        static int ApplyChunkHeader(int size, Span<byte> buffer)
        {
            Span<char> hex = stackalloc char[8];
            size.TryFormat(hex, out int charsWritten, "X");
            hex = hex.Slice(0, charsWritten);

            return Encoding.ASCII.GetBytes(hex, buffer);
        }

        using var responseWriter = new HttpResponseWriter(MINIMUM_HTTP_BUFFER_SIZE);

        Encoding.UTF8.GetBytes($"HTTP/{response.Version.ToString(2)} {(int)response.StatusCode} {response.ReasonPhrase}", responseWriter);
        responseWriter.AppendLine();

        if (response.Content != null && response.Content != _okResponse.Content)
        {
            foreach ((string name, var values) in response.Content.Headers.NonValidated)
            {
                Encoding.UTF8.GetBytes($"{name}: ", responseWriter);
                Encoding.UTF8.GetBytes(string.Join("; ", values), responseWriter);
                responseWriter.AppendLine();
            }
        }

        foreach ((string name, var values) in response.Headers.NonValidated)
        {
            Encoding.UTF8.GetBytes($"{name}: ", responseWriter);
            Encoding.UTF8.GetBytes(string.Join("; ", values), responseWriter);
            responseWriter.AppendLine();
        }

        responseWriter.AppendLine();
        await responseWriter.WriteToAsync(_stream, cancellationToken).ConfigureAwait(false);
        if (response.Content == null || response.Content == _okResponse.Content || response.RequestMessage?.Method == AdditionalHttpMethods.Connect) return;

        if (response.Headers.TransferEncodingChunked == true)
        {
#if !NETSTANDARD2_0
            using Stream chunkedEncodingStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#else
            using Stream chunkedEncodingStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
            using IMemoryOwner<byte> chunkBufferOwner = MemoryPool<byte>.Shared.Rent((MINIMUM_HTTP_BUFFER_SIZE / 4) + 16);

            Memory<byte> endOfLine = chunkBufferOwner.Memory.Slice(0, 2);
            Memory<byte> chunkBuffer = chunkBufferOwner.Memory.Slice(16, MINIMUM_HTTP_BUFFER_SIZE / 4);
            Memory<byte> chunkHeaderBuffer = chunkBufferOwner.Memory.Slice(2, 16);

            int bytesRead = 0;
            _eolBytes.CopyTo(endOfLine.Span);
            do
            {
                bytesRead = await chunkedEncodingStream.ReadAsync(chunkBuffer, cancellationToken).ConfigureAwait(false);

                int headerSize = ApplyChunkHeader(bytesRead, chunkHeaderBuffer.Span);
                await _stream.WriteAsync(chunkHeaderBuffer.Slice(0, headerSize), cancellationToken).ConfigureAwait(false);
                await _stream.WriteAsync(endOfLine, cancellationToken).ConfigureAwait(false);

                if (bytesRead > 0)
                {
                    await _stream.WriteAsync(chunkBuffer.Slice(0, bytesRead), cancellationToken).ConfigureAwait(false);
                }
                await _stream.WriteAsync(endOfLine, cancellationToken).ConfigureAwait(false);
            }
            while (bytesRead > 0);
        }
        else
        {
#if !NETSTANDARD2_0
            await response.Content.CopyToAsync(_stream, cancellationToken).ConfigureAwait(false);
#else
            await response.Content.CopyToAsync(_stream).ConfigureAwait(false);
#endif
        }
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static bool TryParseHttpRequest(BufferedHttpSegment first, BufferedHttpSegment last, Uri? baseUri, out HttpRequestMessage? request, out int unconsumedBytes)
    {
        request = null;
        unconsumedBytes = 0;
        ReadOnlySpan<byte> httpSpan, httpHeadersSpan;

        if (first == last)
        {
            httpSpan = first.Memory.Span;

            // Find the EOF bytes.
            int eofStart = httpSpan.IndexOf(_eofBytes);

            // More segments are required to complete the HTTP request as no EOF bytes were found.
            if (eofStart == -1) return false;

            httpHeadersSpan = httpSpan.Slice(0, eofStart);
            unconsumedBytes = httpSpan.Length - eofStart - _eofBytes.Length;
        }
        else // This will allocate a buffer to place the merged span on. 
        {
            // TODO: Manually enumerate the memory segments to construct the HTTP request.
            var reader = new SequenceReader<byte>(new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length));

            // No segments contain the EOF bytes, continue to read more data.
            if (!reader.TryReadTo(out httpHeadersSpan, _eofBytes, true)) return false;

            unconsumedBytes = (int)reader.Remaining;
        }

        // Parse HTTP Method/Uri
        int uriStart = httpHeadersSpan.IndexOf((byte)' ') + 1;
        int uriEnd = httpHeadersSpan.Slice(uriStart).IndexOf((byte)' ');
        string uri = Encoding.UTF8.GetString(httpHeadersSpan.Slice(uriStart, uriEnd));
        string method = Encoding.UTF8.GetString(httpHeadersSpan.Slice(0, uriStart - 1));

        request = new HttpRequestMessage(_httpMethodTable[method], string.Empty);

        request.RequestUri = request.Method == AdditionalHttpMethods.Connect
            ? new Uri("https://" + uri)
            : new Uri((baseUri?.GetLeftPart(UriPartial.Authority) ?? string.Empty) + uri, UriKind.RelativeOrAbsolute);

        // Parse HTTP Request Headers
        httpHeadersSpan = httpHeadersSpan.Slice(httpHeadersSpan.IndexOf(_eolBytes) + _eolBytes.Length);
        while (!httpHeadersSpan.IsEmpty)
        {
            int nameEnd = httpHeadersSpan.IndexOf((byte)':');
            string name = Encoding.UTF8.GetString(httpHeadersSpan.Slice(0, nameEnd));
            httpHeadersSpan = httpHeadersSpan.Slice(nameEnd + 2);

            int valueEnd = httpHeadersSpan.IndexOf(_eolBytes);
            if (valueEnd == -1)
            {
                valueEnd = httpHeadersSpan.Length;
            }
            string value = Encoding.UTF8.GetString(httpHeadersSpan.Slice(0, valueEnd));
            httpHeadersSpan = httpHeadersSpan.Slice(valueEnd + (valueEnd == httpHeadersSpan.Length ? 0 : _eolBytes.Length));

            if (name.StartsWith("content-", StringComparison.OrdinalIgnoreCase))
            {
                request.Content ??= new UnbufferedHttpContent();
                request.Content.Headers.TryAddWithoutValidation(name, value);
            }
            else request.Headers.TryAddWithoutValidation(name, value);
        }

        return true;
    }
    private static async Task BufferHttpRequestContentAsync(HttpRequestMessage request, ReadOnlyMemory<byte> bufferedContent, Stream stream, CancellationToken cancellationToken = default)
    {
        int minBufferSize = (int)(request.Content?.Headers.ContentLength ?? -1);

        var content = new BufferedHttpContent(minBufferSize);
        foreach ((string name, var values) in request.Content.Headers.NonValidated)
        {
            content.Headers.TryAddWithoutValidation(name, values);
        }

        request.Content?.Dispose();
        request.Content = content;

        int totalBytesRead = 0;
        if (bufferedContent.Length > 0)
        {
            bufferedContent.CopyTo(content.Memory);
            totalBytesRead += bufferedContent.Length;
        }

        while (totalBytesRead < minBufferSize)
        {
            totalBytesRead += await stream.ReadAsync(content.Memory.Slice(totalBytesRead), cancellationToken).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _stream.Dispose();
            _disposed = true;
        }
    }
}
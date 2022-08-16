using System.Net;
using System.Text;
using System.Buffers;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Eavesdrop.Network.Http;

namespace Eavesdrop.Network;

public sealed class EavesNode : IDisposable
{
    private const short MINIMUM_HTTP_BUFFER_SIZE = 1024;

    private static readonly HttpMethod _connectMethod;
    private static readonly HttpResponseMessage _okResponse;
    private static readonly byte[] _eolBytes = new byte[2] { (byte)'\r', (byte)'\n' };
    private static readonly byte[] _eofBytes = new byte[4] { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };
    private static readonly byte[] _connectBytes = new byte[7] { (byte)'C', (byte)'O', (byte)'N', (byte)'N', (byte)'E', (byte)'C', (byte)'T' };

    private readonly Socket _client;
    private readonly CertificateManager _certifier;

    private bool _disposed;
    private Stream _stream;

    public bool IsSecure { get; private set; }

    static EavesNode()
    {
        _connectMethod = new HttpMethod("CONNECT");
        _okResponse = new HttpResponseMessage(HttpStatusCode.OK);
    }
    public EavesNode(Socket client, CertificateManager certifier)
    {
        _client = client;
        _certifier = certifier;

        _client.NoDelay = true;
        _stream = new NetworkStream(client, FileAccess.ReadWrite, true);
    }

    public async Task<HttpRequestMessage> ReceiveHttpRequestAsync()
    {
        using var firstBufferedHttpSegment = new BufferedHttpSegment(MINIMUM_HTTP_BUFFER_SIZE, out Memory<byte> buffer);
        BufferedHttpSegment lastBufferedHttpSegment = firstBufferedHttpSegment;

        Uri? baseUri = null;
        HttpRequestMessage? request = null;
        while (_client.Connected && _stream.CanRead && request == null)
        {
            int bytesRead = await _stream.ReadAsync(buffer).ConfigureAwait(false);
            if (!TryParseHttpRequest(firstBufferedHttpSegment, lastBufferedHttpSegment, baseUri, bytesRead, out request, out int unconsumedBytes))
            {
                lastBufferedHttpSegment = lastBufferedHttpSegment.Grow(MINIMUM_HTTP_BUFFER_SIZE, out buffer);
                continue;
            }

            if (request?.Method == _connectMethod && request.RequestUri != null)
            {
                await SendHttpResponseAsync(_okResponse).ConfigureAwait(false);

                X509Certificate2? certificate = _certifier.GenerateCertificate(request.RequestUri.DnsSafeHost);
                if (certificate == null)
                {
                    throw new NullReferenceException($"Failed to generate a self-signed certificate for '{request.RequestUri.DnsSafeHost}'.");
                }

                var secureStream = new SslStream(_stream);
                secureStream.AuthenticateAsServer(certificate, false, SslProtocols.None, false);
                _stream = secureStream;

                baseUri = request.RequestUri;
                request.Dispose();
                request = null;

                firstBufferedHttpSegment.Collapse();
                lastBufferedHttpSegment = firstBufferedHttpSegment;
            }
            else if (unconsumedBytes > 0 && request?.Content != null)
            {
                int unconsumedStart = buffer.Length - unconsumedBytes;
                ReadOnlyMemory<byte> unconsumed = lastBufferedHttpSegment.Memory.Slice(unconsumedStart, bytesRead - unconsumedStart);
                await BufferHttpRequestContentAsync(request, unconsumed, _stream).ConfigureAwait(false);
            }
        }

        return request ?? throw new NullReferenceException("Failed to parse the HTTP request.");
    }
    public async Task SendHttpResponseAsync(HttpResponseMessage response)
    {
        using var responseWriter = new HttpResponseWriter(MINIMUM_HTTP_BUFFER_SIZE);

        Encoding.UTF8.GetBytes($"HTTP/{response.Version.ToString(2)} {(int)response.StatusCode} {response.ReasonPhrase}", responseWriter);
        responseWriter.AppendLine();

        if (response.Content != null && response.Content != _okResponse.Content)
        {
            foreach ((string name, IEnumerable<string>? values) in response.Content.Headers)
            {
                Encoding.UTF8.GetBytes($"{name}: ", responseWriter);
                Encoding.UTF8.GetBytes(string.Join("; ", values), responseWriter);
                responseWriter.AppendLine();
            }
        }

        foreach ((string name, IEnumerable<string>? values) in response.Headers)
        {
            Encoding.UTF8.GetBytes($"{name}: ", responseWriter);
            Encoding.UTF8.GetBytes(string.Join("; ", values), responseWriter);
            responseWriter.AppendLine();
        }

        responseWriter.AppendLine();
        await responseWriter.WriteToAsync(_stream).ConfigureAwait(false);
        if (response.Content == null || response.Content == _okResponse.Content) return;

        if (response.Headers.TransferEncodingChunked == true)
        {
            using Stream chunkedEncodingStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using IMemoryOwner<byte> chunkedBufferOwner = MemoryPool<byte>.Shared.Rent(MINIMUM_HTTP_BUFFER_SIZE);

            var chunkHeadBuffer = new byte[6];
            chunkHeadBuffer[4] = (byte)'\r';
            chunkHeadBuffer[5] = (byte)'\n';

            int bytesRead = 0;
            Memory<byte> chunkedBuffer = chunkedBufferOwner.Memory;
            do
            {
                bytesRead = await chunkedEncodingStream.ReadAsync(chunkedBuffer).ConfigureAwait(false);

                int hexWritten = Encoding.UTF8.GetBytes(bytesRead.ToString("X"), chunkHeadBuffer);
                await _stream.WriteAsync(chunkHeadBuffer, 0, hexWritten).ConfigureAwait(false);
                await _stream.WriteAsync(chunkHeadBuffer, 4, 2).ConfigureAwait(false);

                if (bytesRead > 0)
                {
                    await _stream.WriteAsync(chunkedBuffer.Slice(0, bytesRead)).ConfigureAwait(false);
                }
                await _stream.WriteAsync(chunkHeadBuffer, 4, 2).ConfigureAwait(false);
            }
            while (bytesRead > 0);
        }
        else await response.Content.CopyToAsync(_stream).ConfigureAwait(false);

        await _stream.FlushAsync().ConfigureAwait(false);
    }

    private static async Task BufferHttpRequestContentAsync(HttpRequestMessage request, ReadOnlyMemory<byte> bufferedContent, Stream stream)
    {
        if (request.Content == null)
        {
            throw new NullReferenceException("The content property of the request message is null.");
        }

        int minBufferSize = (int)(request.Content.Headers.ContentLength ?? MINIMUM_HTTP_BUFFER_SIZE);
        var content = new BufferedHttpContent(minBufferSize);
        foreach ((string name, IEnumerable<string>? values) in request.Content.Headers)
        {
            content.Headers.Add(name, values);
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
            totalBytesRead += await stream.ReadAsync(content.Memory.Slice(totalBytesRead)).ConfigureAwait(false);
        }
    }
    private static bool TryParseHttpRequest(BufferedHttpSegment first, BufferedHttpSegment last, Uri? baseUri, int lastBytesRead, out HttpRequestMessage? request, out int unconsumedBytes)
    {
        request = null;
        unconsumedBytes = 0;
        ReadOnlySpan<byte> httpSpan = null, httpHeadersSpan = null;

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

        request = new HttpRequestMessage
        {
            Method = httpHeadersSpan.StartsWith(_connectBytes) ? _connectMethod : new HttpMethod(method),
            RequestUri = new Uri((httpHeadersSpan.StartsWith(_connectBytes) ? "https://" : baseUri?.GetLeftPart(UriPartial.Authority) ?? string.Empty) + uri)
        };
        if (request.Method == _connectMethod) return true;

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
                if (request.Content == null)
                {
                    request.Content = new UnbufferedHttpContent();
                }
                request.Content.Headers.Add(name, value);
            }
            else
            {
                bool isConnectionHeader = name.Equals("connection", StringComparison.OrdinalIgnoreCase) || name.Equals("proxy-connection", StringComparison.OrdinalIgnoreCase);
                bool isRequestingKeepAlive = value.Equals("keep-alive", StringComparison.OrdinalIgnoreCase);
                if (!isConnectionHeader || !isRequestingKeepAlive)
                {
                    request.Headers.TryAddWithoutValidation(name, value);
                }
            }
        }
        return true;
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
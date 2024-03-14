using System.Buffers;
using System.Net.Http.Headers;

namespace Eavesdrop.Network.Http;

public sealed class HttpResponseWriter : IBufferWriter<byte>, IDisposable
{
    private bool _disposed;
    private IMemoryOwner<byte> _bufferOwner;

    public int Written { get; private set; }
    public Memory<byte> Memory { get; private set; }

    public HttpResponseWriter(int minBufferSize = -1)
    {
        _bufferOwner = MemoryPool<byte>.Shared.Rent(minBufferSize);
        Memory = _bufferOwner.Memory;
    }

    public async Task WriteToAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        await stream.WriteAsync(Memory.Slice(0, Written), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        Written = 0;
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        if (sizeHint > (Memory.Length - Written))
        {
            var bufferOwner = MemoryPool<byte>.Shared.Rent(Math.Max(Memory.Length * 2, sizeHint + Memory.Length));
            Memory.Slice(0, Written).CopyTo(bufferOwner.Memory);
            Memory = bufferOwner.Memory;

            _bufferOwner.Dispose();
            _bufferOwner = bufferOwner;
        }
        return Memory.Span.Slice(Written);
    }
    public void Advance(int count) => Written += count;
    public Memory<byte> GetMemory(int sizeHint = 0) => throw new NotImplementedException();

    public void AppendLine()
    {
        Span<byte> eofBytes = GetSpan(2);
        eofBytes[0] = (byte)'\r';
        eofBytes[1] = (byte)'\n';
        Advance(2);
    }
    public void Write(HttpHeaders headers)
    {
        // TODO
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _bufferOwner.Dispose();
            _disposed = true;
        }
    }
}
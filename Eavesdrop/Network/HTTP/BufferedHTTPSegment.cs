using System.Buffers;

namespace Eavesdrop.Network.HTTP;

public sealed class BufferedHTTPSegment : ReadOnlySequenceSegment<byte>, IDisposable
{
    private bool _disposed;

    private readonly IMemoryOwner<byte> _bufferOwner;

    public BufferedHTTPSegment(int minBufferSize, out Memory<byte> buffer)
    {
        _bufferOwner = MemoryPool<byte>.Shared.Rent(minBufferSize);

        buffer = _bufferOwner.Memory;
        Memory = _bufferOwner.Memory;
    }

    public void Collapse()
    {
        (Next as BufferedHTTPSegment)?.Dispose();
        Next = null;
    }
    public BufferedHTTPSegment Grow(int minBufferSize, out Memory<byte> buffer)
    {
        var httpSegment = new BufferedHTTPSegment(minBufferSize, out buffer)
        {
            RunningIndex = RunningIndex + Memory.Length
        };

        Next = httpSegment;
        return httpSegment;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    private void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            _bufferOwner?.Dispose();
            (Next as BufferedHTTPSegment)?.Dispose();
        }
        _disposed = true;
    }
}
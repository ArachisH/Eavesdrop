using System.Buffers;

namespace Eavesdrop.Network.Http;

public sealed class BufferedHttpSegment : ReadOnlySequenceSegment<byte>, IDisposable
{
    private bool _disposed;

    private readonly IMemoryOwner<byte> _bufferOwner;

    public BufferedHttpSegment(int minBufferSize, out Memory<byte> buffer)
    {
        _bufferOwner = MemoryPool<byte>.Shared.Rent(minBufferSize);

        buffer = _bufferOwner.Memory;
        Memory = _bufferOwner.Memory;
    }

    public void Collapse()
    {
        (Next as BufferedHttpSegment)?.Dispose();
        Next = null;
    }
    public BufferedHttpSegment Grow(int minBufferSize, out Memory<byte> buffer)
    {
        var httpSegment = new BufferedHttpSegment(minBufferSize, out buffer)
        {
            RunningIndex = RunningIndex + Memory.Length
        };

        Next = httpSegment;
        return httpSegment;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _bufferOwner?.Dispose();
            (Next as BufferedHttpSegment)?.Dispose();

            _disposed = true;
        }
    }
}
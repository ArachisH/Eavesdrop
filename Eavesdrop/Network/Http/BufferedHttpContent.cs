using System.Net;
using System.Buffers;

namespace Eavesdrop.Network.Http;

public sealed class BufferedHttpContent : HttpContent
{
    private readonly IMemoryOwner<byte> _contentBufferOwner;

    public Memory<byte> Memory { get; }

    public BufferedHttpContent(int minBufferSize = -1)
    {
        _contentBufferOwner = MemoryPool<byte>.Shared.Rent(minBufferSize);

        Memory = _contentBufferOwner.Memory;
    }

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        if (Headers.ContentLength != null)
        {
            length = (long)Headers.ContentLength;
            return true;
        }
        else return false;
    }
    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        if (TryComputeLength(out long length))
        {
            await stream.WriteAsync(Memory.Slice(0, (int)length)).ConfigureAwait(false);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _contentBufferOwner.Dispose();
        }
    }
}
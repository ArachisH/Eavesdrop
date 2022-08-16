using System.Net;

namespace Eavesdrop.Network.Http;

internal sealed class UnbufferedHttpContent : HttpContent
{
    protected override bool TryComputeLength(out long length) { length = 0; return false; }
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.CompletedTask;
}
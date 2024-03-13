#if NETSTANDARD2_0
using System.Runtime.InteropServices;

namespace Eavesdrop;

internal static class StreamMemoryExtensions
{
    public static Task<int> ReadAsync(this Stream stream, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> array)
            ? stream.ReadAsync(array.Array, array.Offset, array.Count, cancellationToken)
            : throw new Exception("Failed to grab underlying byte array.");
    }

    public static Task WriteAsync(this Stream stream, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> array)
            ? stream.WriteAsync(array.Array, array.Offset, array.Count, cancellationToken)
            : throw new Exception("Failed to grab underlying byte array.");
    }
}
#endif
#if NETSTANDARD2_0
using System.Text;
using System.Buffers;

namespace Eavesdrop;

internal static class CompatibleEncodingExtensions
{
    public static unsafe int GetBytes(this Encoding encoding, string value, IBufferWriter<byte> writer)
    {
        int byteCount = encoding.GetByteCount(value);
        Span<byte> buffer = writer.GetSpan(byteCount);

        fixed (char* valuePtr = value)
        fixed (byte* bufferPtr = buffer)
        {
            int written = encoding.GetBytes(valuePtr, value.Length, bufferPtr, buffer.Length);
            writer.Advance(written);
            return written;
        }
    }
    public static unsafe int GetBytes(this Encoding encoding, ReadOnlySpan<char> chars, Span<byte> buffer)
    {
        fixed (char* charsPtr = chars)
        fixed (byte* bufferPtr = buffer)
        {
            return encoding.GetBytes(charsPtr, chars.Length, bufferPtr, buffer.Length);
        }
    }
}
#endif
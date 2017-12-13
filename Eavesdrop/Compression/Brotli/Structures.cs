
using size_t = Eavesdrop.Compression.Brotli.Brotli.SizeT;

namespace Eavesdrop.Compression.Brotli
{
    public static partial class Brotli
    {
        internal unsafe delegate void* brotli_alloc_func(void* opaque, size_t size);

        internal unsafe delegate void brotli_free_func(void* opaque, void* address);
    }
}
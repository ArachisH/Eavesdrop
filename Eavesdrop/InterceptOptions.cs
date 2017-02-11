using System;

namespace Eavesdrop
{
    [Flags]
    public enum InterceptOptions
    {
        InterceptHTTP = 1,
        InterceptHTTPS = 2,

        Default = (InterceptHTTP | InterceptHTTPS),

        InterceptFTP = 4,
        InterceptSocks = 8,

        All = (InterceptHTTP | InterceptHTTPS | InterceptFTP | InterceptSocks)
    }
}
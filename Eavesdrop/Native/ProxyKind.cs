namespace Eavesdrop;

/// <summary>
/// Represents the proxy connection type.
/// </summary>
[Flags]
internal enum ProxyKind : int
{
    /// <summary>
    /// The connection does not use a proxy server.
    /// </summary>
    PROXY_TYPE_DIRECT = 1,

    /// <summary>
    /// The connection uses an explicitly set proxy server.
    /// </summary>
    PROXY_TYPE_PROXY = 2,

    /// <summary>
    /// The connection downloads and processes an automatic configuration script at a specified URL.
    /// </summary>
    PROXY_TYPE_AUTO_PROXY_URL = 4,

    /// <summary>
    /// The connection automatically detects settings.
    /// </summary>
    PROXY_TYPE_AUTO_DETECT = 8
}

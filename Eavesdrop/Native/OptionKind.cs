namespace Eavesdrop;

/// <summary>
/// Option type to be queried or set.
/// </summary>
internal enum OptionKind : int
{
    /// <summary>
    /// Sets or retrieves the connection type. 
    /// </summary>
    INTERNET_PER_CONN_FLAGS = 1,

    /// <summary>
    /// Sets or retrieves a string containing the proxy servers.
    /// </summary>
    INTERNET_PER_CONN_PROXY_SERVER = 2,

    /// <summary>
    /// Sets or retrieves a string containing the URLs that do not use the proxy server.
    /// </summary>
    INTERNET_PER_CONN_PROXY_BYPASS = 3,

    /// <summary>
    /// Sets or retrieves a string containing the URL to the automatic configuration script.
    /// </summary>
    INTERNET_PER_CONN_AUTOCONFIG_URL = 4
}
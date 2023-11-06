using System.Net;

namespace Eavesdrop.Network;

internal sealed class SelfBypassWebProxy : IWebProxy
{
    public IWebProxy? Proxy { get; set; }

    public ICredentials? Credentials
    {
        get => Proxy?.Credentials;
        set
        {
            if (Proxy != null)
            {
                Proxy.Credentials = value;
            }
        }
    }

    public Uri? GetProxy(Uri destination) => Proxy?.GetProxy(destination);
    public bool IsBypassed(Uri host) => Proxy == null || Proxy.IsBypassed(host) || Proxy.GetProxy(host) == host;
}
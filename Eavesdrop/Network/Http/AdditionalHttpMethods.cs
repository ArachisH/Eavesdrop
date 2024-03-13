namespace Eavesdrop.Network.Http;

public static class AdditionalHttpMethods
{
    public static HttpMethod Patch { get; }
    public static HttpMethod Connect { get; }

    static AdditionalHttpMethods()
    {
#if NETSTANDARD2_0
        Patch = new HttpMethod("PATCH");
        Connect = new HttpMethod("CONNECT");
#else
        Patch = HttpMethod.Patch;
        Connect = HttpMethod.Connect;
#endif
    }
}
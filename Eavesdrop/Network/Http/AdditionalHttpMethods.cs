namespace Eavesdrop.Network.Http;

public static class AdditionalHttpMethods
{
    public static HttpMethod Patch { get; }
    public static HttpMethod Connect { get; }

    static AdditionalHttpMethods()
    {
#if NET7_0_OR_GREATER
        Patch = HttpMethod.Patch;
        Connect = HttpMethod.Connect;
#else
        Patch = new HttpMethod("PATCH");
        Connect = new HttpMethod("CONNECT");
#endif
    }
}
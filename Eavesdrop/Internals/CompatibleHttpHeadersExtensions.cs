using System.Net.Http.Headers;

namespace Eavesdrop;

public static class CompatibleHttpHeadersExtensions
{
    public static IEnumerable<(string Name, IEnumerable<string> Values)> AsTuplePairs(this HttpHeaders? headers)
    {
        if (headers == null) yield break;

#if NET6_0_OR_GREATER
        foreach ((string name, HeaderStringValues values) in headers.NonValidated)
        {
            yield return (name, values);
        }
#else
        foreach (KeyValuePair<string, IEnumerable<string>> header in headers)
        {
            yield return (header.Key, header.Value);
        }
#endif
    }
}
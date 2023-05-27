using System.ComponentModel;
using System.Net.Http.Headers;

namespace Eavesdrop;

public sealed class RequestInterceptedEventArgs : CancelEventArgs
{
    public HttpMethod Method
    {
        get => Request.Method;
        set => Request.Method = value;
    }
    public HttpContent? Content
    {
        get => Request.Content;
        set => Request.Content = value;
    }

    public Uri? Uri => Request.RequestUri;
    public Version Version => Request.Version;
    public HttpRequestHeaders Headers => Request.Headers;

    public HttpRequestMessage Request { get; set; }
    public HttpResponseMessage? Response { get; set; }

    public bool IsInterceptingResponse { get; set; } = true;

    public RequestInterceptedEventArgs(HttpRequestMessage request)
    {
        Request = request;
    }
}
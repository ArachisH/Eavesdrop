using System.ComponentModel;
using System.Net.Http.Headers;

namespace Eavesdrop;

public sealed class RequestInterceptedEventArgs : CancelEventArgs
{
    private readonly HttpRequestMessage _request;

    public HttpMethod Method
    {
        get => _request.Method;
        set => _request.Method = value;
    }
    public HttpContent? Content
    {
        get => _request.Content;
        set => _request.Content = value;
    }

    public Uri? Uri => _request.RequestUri;
    public Version Version => _request.Version;
    public HttpRequestHeaders Headers => _request.Headers;

    public RequestInterceptedEventArgs(HttpRequestMessage request)
    {
        _request = request;
    }
}
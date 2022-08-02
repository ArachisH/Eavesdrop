using System.Net;
using System.ComponentModel;
using System.Net.Http.Headers;

namespace Eavesdrop;

public sealed class ResponseInterceptedEventArgs : CancelEventArgs
{
    private readonly HttpResponseMessage _response;

    public Uri? Uri => Request?.RequestUri;
    public HttpRequestMessage? Request => _response.RequestMessage;

    public Version Version
    {
        get => _response.Version;
        set => _response.Version = value;
    }
    public HttpContent Content
    {
        get => _response.Content;
        set => _response.Content = value;
    }
    public string? ReasonPhrase
    {
        get => _response.ReasonPhrase;
        set => _response.ReasonPhrase = value;
    }
    public HttpStatusCode StatusCode
    {
        get => _response.StatusCode;
        set => _response.StatusCode = value;
    }

    public bool IsSuccessStatusCode => _response.IsSuccessStatusCode;

    public HttpResponseHeaders Headers => _response.Headers;
    public HttpResponseHeaders TrailingHeaders => _response.TrailingHeaders;

    public ResponseInterceptedEventArgs(HttpResponseMessage response)
    {
        _response = response;
    }
}
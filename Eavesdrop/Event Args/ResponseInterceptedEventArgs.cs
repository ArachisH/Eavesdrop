using System.Net;
using System.ComponentModel;
using System.Net.Http.Headers;

namespace Eavesdrop;

public sealed class ResponseInterceptedEventArgs : CancelEventArgs
{
    private readonly HttpResponseMessage _response;

    public Version Version => _response.Version;
    public Uri? Uri => _response.RequestMessage?.RequestUri;
    public HttpRequestMessage? Request => _response.RequestMessage;

    public string? ReasonPhrase => _response.ReasonPhrase;
    public HttpStatusCode StatusCode => _response.StatusCode;
    public bool IsSuccessStatusCode => _response.IsSuccessStatusCode;

    public HttpContent Content => _response.Content;
    public HttpResponseHeaders Headers => _response.Headers;
    public HttpResponseHeaders TrailingHeaders => _response.TrailingHeaders;

    public ResponseInterceptedEventArgs(HttpResponseMessage response)
    {
        _response = response;
    }
}
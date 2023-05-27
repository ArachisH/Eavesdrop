using System.Net;
using System.ComponentModel;
using System.Net.Http.Headers;

namespace Eavesdrop;

public sealed class ResponseInterceptedEventArgs : CancelEventArgs
{
    public Uri? Uri => Request?.RequestUri;
    public HttpRequestMessage? Request => Response.RequestMessage;
    public bool IsSuccessStatusCode => Response.IsSuccessStatusCode;

    public Version Version
    {
        get => Response.Version;
        set => Response.Version = value;
    }
    public HttpContent Content
    {
        get => Response.Content;
        set => Response.Content = value;
    }
    public string? ReasonPhrase
    {
        get => Response.ReasonPhrase;
        set => Response.ReasonPhrase = value;
    }
    public HttpStatusCode StatusCode
    {
        get => Response.StatusCode;
        set => Response.StatusCode = value;
    }

    public HttpResponseHeaders Headers => Response.Headers;
    public HttpResponseHeaders TrailingHeaders => Response.TrailingHeaders;

    public HttpResponseMessage Response { get; set; }

    public ResponseInterceptedEventArgs(HttpResponseMessage response)
    {
        Response = response;
    }
}
using System.Net;
using System.Net.Http;
using System.ComponentModel;

namespace Eavesdrop
{
    public abstract class InterceptedEventArgs : CancelEventArgs
    {
        public HttpContent Content { get; set; }
        public abstract CookieContainer CookieContainer { get; }
    }
}
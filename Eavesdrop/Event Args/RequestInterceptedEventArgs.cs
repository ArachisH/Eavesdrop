using System.Net;
using System.ComponentModel;

namespace Eavesdrop
{
    public class RequestInterceptedEventArgs : CancelEventArgs
    {
        public byte[] Payload { get; set; }
        public WebRequest Request { get; set; }

        public RequestInterceptedEventArgs(WebRequest request)
        {
            Request = request;
        }
    }
}
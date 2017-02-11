using System.Net;
using System.ComponentModel;

namespace Eavesdrop
{
    public class ResponseInterceptedEventArgs : CancelEventArgs
    {
        public byte[] Payload { get; set; }
        public WebResponse Response { get; set; }

        public ResponseInterceptedEventArgs(WebResponse response)
        {
            Response = response;
        }
    }
}
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.ComponentModel;
using System.Threading.Tasks;

using Eavesdrop.Network;

namespace Eavesdrop
{
    public class ResponseInterceptedEventArgs : CancelEventArgs
    {
        private HttpWebResponse _httpResponse;

        private WebResponse _response;
        public WebResponse Response
        {
            get => _response;
            private set
            {
                _response = value;

                _httpResponse = (value as HttpWebResponse);
                if (_httpResponse != null)
                {
                    CookieContainer = new CookieContainer();
                    CookieContainer.Add(_httpResponse.Cookies);
                }
                else CookieContainer = null;
            }
        }

        public WebRequest Request { get; }
        public Uri Uri => Response?.ResponseUri;

        public HttpContent Content { get; set; }
        public CookieContainer CookieContainer { get; private set; }

        public string ContentType
        {
            get => Response?.ContentType;
            set
            {
                if (Response != null)
                {
                    Response.ContentType = value;
                }
            }
        }
        public WebHeaderCollection Headers
        {
            get => Response?.Headers;
            set
            {
                if (Response == null) return;
                foreach (string header in value.AllKeys)
                {
                    Response.Headers[header] = value[header];
                }
            }
        }

        public ResponseInterceptedEventArgs(WebRequest request, WebResponse response)
        {
            Request = request;
            Response = response;
        }

        public Task ChangeResponseAsync(WebResponse response)
        {
            return ChangeResponseAsync(response, true);
        }
        public async Task ChangeResponseAsync(WebResponse response, bool overrideContent)
        {
            Response = response;
            if (!overrideContent) return;

            using (Stream responseInput = response.GetResponseStream())
            {
                Content = await EavesNode.GetContentAsync(responseInput, response.ContentLength).ConfigureAwait(false);
            }
        }
    }
}
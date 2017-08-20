using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;

using Eavesdrop.Network;

namespace Eavesdrop
{
    public class ResponseInterceptedEventArgs : InterceptedEventArgs
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
                    _cookieContainer = new CookieContainer();
                    CookieContainer.Add(_httpResponse.Cookies);
                }
                else _cookieContainer = null;
            }
        }

        public Uri Uri => Response?.ResponseUri;

        private CookieContainer _cookieContainer;
        public override CookieContainer CookieContainer => _cookieContainer;

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

        public ResponseInterceptedEventArgs(WebResponse response)
        {
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
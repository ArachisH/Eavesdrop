using System;
using System.IO;
using System.Web;
using System.Net;
using System.Text;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.Security;
using System.Globalization;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop.Network
{
    public class EavesNode : IDisposable
    {
        private SslStream _secureStream;
        private readonly TcpClient _client;
        private readonly CertificateManager _certifier;
        private static readonly Regex _responseCookieSplitter;

        public bool IsSecure => (_secureStream != null);

        static EavesNode()
        {
            _responseCookieSplitter = new Regex(",(?! )");
        }
        public EavesNode(CertificateManager certifier, TcpClient client)
        {
            _client = client;
            _certifier = certifier;
        }

        public Task<ByteArrayContent> GetRequestContentAsync(long length)
        {
            return GetContentAsync(GetStream(), length);
        }

        public Task<HttpWebRequest> ReadRequestAsync()
        {
            return ReadRequestAsync(null);
        }
        private async Task<HttpWebRequest> ReadRequestAsync(Uri baseUri)
        {
            string method = null;
            var headers = new List<string>();
            string requestUrl = baseUri?.OriginalString;

            string command = ReadNonBufferedLine();
            if (string.IsNullOrWhiteSpace(command)) return null;

            if (string.IsNullOrWhiteSpace(command)) return null;
            string[] values = command.Split(' ');

            method = values[0];
            requestUrl += values[1];
            while (_client.Connected)
            {
                string header = ReadNonBufferedLine();
                if (string.IsNullOrWhiteSpace(header)) break;

                headers.Add(header);
            }

            if (method == "CONNECT")
            {
                baseUri = new Uri("https://" + requestUrl);
                await SendResponseAsync(HttpStatusCode.OK).ConfigureAwait(false);

                if (!SecureTunnel(baseUri.Host)) return null;
                return await ReadRequestAsync(baseUri).ConfigureAwait(false);
            }
            else return CreateRequest(method, headers, new Uri(requestUrl));
        }

        public Task SendResponseAsync(WebResponse response, HttpContent content)
        {
            HttpStatusCode status = ((response as HttpWebResponse)?.StatusCode ?? HttpStatusCode.OK);
            return SendResponseAsync(status, response.Headers, content);
        }
        public Task SendResponseAsync(HttpStatusCode status)
        {
            return SendResponseAsync(status, null, null);
        }
        public Task SendResponseAsync(HttpStatusCode status, WebHeaderCollection headers)
        {
            return SendResponseAsync(status, headers, null);
        }
        public async Task SendResponseAsync(HttpStatusCode status, WebHeaderCollection headers, HttpContent content)
        {
            string description = HttpWorkerRequest.GetStatusDescription((int)status);
            string command = $"HTTP/{HttpVersion.Version10} {(int)status} {description}";

            byte[] payload = null;
            if (content != null)
            {
                payload = await content.ReadAsByteArrayAsync().ConfigureAwait(false);
            }

            using (StreamWriter output = WrapStreamWriter())
            {
                await output.WriteLineAsync(command).ConfigureAwait(false);
                if (headers != null)
                {
                    foreach (string header in headers.AllKeys)
                    {
                        string value = headers[header];
                        if (header.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                        {
                            value = (payload?.Length.ToString() ?? "0");
                        }
                        if (header.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                        {
                            foreach (string setCookie in _responseCookieSplitter.Split(value))
                            {
                                await output.WriteLineAsync($"{header}: {setCookie}").ConfigureAwait(false);
                            }
                        }
                        else await output.WriteLineAsync($"{header}: {value}").ConfigureAwait(false);
                    }
                }
                if (payload != null)
                {
                    await output.WriteLineAsync().ConfigureAwait(false);
                    await output.FlushAsync().ConfigureAwait(false);

                    await output.BaseStream.WriteAsync(payload, 0, payload.Length).ConfigureAwait(false);
                }
                await output.WriteLineAsync().ConfigureAwait(false);
            }
        }

        public Stream GetStream()
        {
            return ((Stream)_secureStream ?? _client.GetStream());
        }
        private StreamWriter WrapStreamWriter()
        {
            return new StreamWriter(GetStream(), Encoding.UTF8, 1024, true);
        }
        private StreamReader WrapStreamReader(int bufferSize = 1024)
        {
            return new StreamReader(GetStream(), Encoding.UTF8, true, bufferSize, true);
        }

        private string ReadNonBufferedLine()
        {
            string line = string.Empty;
            try
            {
                using (var binaryInput = new BinaryReader(GetStream(), Encoding.UTF8, true))
                {
                    do { line += binaryInput.ReadChar(); }
                    while (!line.EndsWith("\r\n"));
                }
            }
            catch (EndOfStreamException) { line += "\r\n"; }
            return line.Substring(0, line.Length - 2);
        }
        private bool SecureTunnel(string host)
        {
            try
            {
                X509Certificate2 certificate = _certifier.GenerateCertificate(host);

                _secureStream = new SslStream(GetStream());
                _secureStream.AuthenticateAsServer(certificate, false, SslProtocols.Default, false);

                return true;
            }
            catch { return false; }
        }
        private IEnumerable<Cookie> GetCookies(string cookieHeader, string host)
        {
            foreach (string cookie in cookieHeader.Split(';'))
            {
                int nameEndIndex = cookie.IndexOf('=');
                if (nameEndIndex == -1) continue;

                string name = cookie.Substring(0, nameEndIndex).Trim();
                string value = cookie.Substring(nameEndIndex + 1).Trim();

                yield return new Cookie(name, value, "/", host);
            }
        }
        private HttpWebRequest CreateRequest(string method, List<string> headers, Uri requestUri)
        {
            HttpWebRequest request = WebRequest.CreateHttp(requestUri);
            request.AutomaticDecompression = (DecompressionMethods.GZip | DecompressionMethods.Deflate);
            request.ProtocolVersion = HttpVersion.Version10;
            request.CookieContainer = new CookieContainer();
            request.AllowAutoRedirect = false;
            request.KeepAlive = false;
            request.Method = method;
            request.Proxy = null;

            foreach (string header in headers)
            {
                int delimiterIndex = header.IndexOf(':');
                if (delimiterIndex == -1) continue;

                string name = header.Substring(0, delimiterIndex);
                string value = header.Substring(delimiterIndex + 2);
                switch (name.ToLower())
                {
                    case "range":
                    case "expect":
                    case "keep-alive":
                    case "connection":
                    case "proxy-connection": break;

                    case "host": request.Host = value; break;
                    case "accept": request.Accept = value; break;
                    case "referer": request.Referer = value; break;
                    case "user-agent": request.UserAgent = value; break;
                    case "content-type": request.ContentType = value; break;

                    case "content-length":
                    {
                        request.ContentLength =
                            long.Parse(value, CultureInfo.InvariantCulture);

                        break;
                    }
                    case "cookie":
                    {
                        foreach (Cookie cookie in GetCookies(value, request.Host))
                        {
                            try
                            {
                                request.CookieContainer.Add(cookie);
                            }
                            catch (CookieException) { }
                        }
                        request.Headers[name] = value;
                        break;
                    }
                    case "if-modified-since":
                    {
                        request.IfModifiedSince = DateTime.Parse(
                            value.Split(';')[0], CultureInfo.InvariantCulture);

                        break;
                    }

                    default: request.Headers[name] = value; break;
                }
            }
            return request;
        }

        public void Dispose()
        {
            Dispose(true);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                GetStream().Close();
                _client.Close();
            }
        }

        public static async Task<ByteArrayContent> GetContentAsync(Stream input, long length)
        {
            byte[] payload = null;
            if (length >= 0)
            {
                int totalBytesRead = 0;
                payload = new byte[length];
                do
                {
                    int bytesLeft = (payload.Length - totalBytesRead);
                    int bytesRead = input.Read(payload, totalBytesRead, bytesLeft);

                    totalBytesRead += bytesRead;
                }
                while (totalBytesRead != payload.Length);
            }
            else
            {
                using (var output = new MemoryStream())
                {
                    await input.CopyToAsync(output).ConfigureAwait(false);
                    payload = output.ToArray();
                }
            }
            if (payload.Length == 0) return null;
            return new ByteArrayContent(payload);
        }
    }
}
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Net.Security;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

namespace Eavesdrop
{
    public class EavesNode : IDisposable
    {
        private static readonly Regex _cookieSplitter;

        public Socket Client { get; }
        public Certifier Certifier { get; }
        public Stream DataStream { get; private set; }

        public bool IsSecure { get; private set; }
        public bool IsDisposed { get; private set; }

        static EavesNode()
        {
            _cookieSplitter = new Regex(@",(?! )");
        }
        public EavesNode(Socket client, Certifier certifier)
        {
            Client = client;
            Certifier = certifier;
            DataStream = new NetworkStream(client, false);
        }

        public byte[] Receive(int length)
        {
            return Receive(DataStream, length);
        }
        public byte[] Receive(Stream dataStream, int length)
        {
            try
            {
                byte[] buffer = null;
                if (length < 0)
                {
                    using (var bufferDataStream = new MemoryStream())
                    {
                        dataStream.CopyTo(bufferDataStream);
                        buffer = bufferDataStream.ToArray();
                    }
                }
                else
                {
                    int totalRead = 0;
                    buffer = new byte[length];

                    while (totalRead != length)
                    {
                        totalRead += dataStream.Read(
                            buffer, totalRead, length - totalRead);
                    }
                }
                return buffer;
            }
            catch (IOException) { return null; }
        }

        public HttpWebRequest ReceiveWebRequest()
        {
            HttpWebRequest request = ReceiveWebRequest(string.Empty);
            if (request == null) return null;

            if (request.Method == "CONNECT")
            {
                SendWebResponse($"HTTP/1.0 200 OK\r\n\r\n");

                if (!SecureTunnel(request.Host))
                {
                    return null;
                }
                request = ReceiveWebRequest(request.RequestUri.OriginalString);
            }
            return request;
        }
        protected HttpWebRequest ReceiveWebRequest(string baseUri)
        {
            string[] requestHeaders = ReceiveWebRequestHeaders();
            if (requestHeaders == null) return null;

            string[] requestCommands = requestHeaders[0].Split(' ');
            if (requestCommands[0] == "CONNECT")
            {
                requestCommands[1] =
                    ("https://" + requestCommands[1]);
            }

            var request = (HttpWebRequest)WebRequest.Create(new Uri(baseUri + requestCommands[1]));
            request.AutomaticDecompression = (DecompressionMethods.GZip | DecompressionMethods.Deflate);
            request.ProtocolVersion = Version.Parse("1.0");
            request.Method = requestCommands[0];
            request.AllowAutoRedirect = false;
            request.KeepAlive = false;
            request.Proxy = null;

            for (int i = 1; i < requestHeaders.Length; i++)
            {
                string requestHeader = requestHeaders[i];
                int headerEndIndex = requestHeader.IndexOf(':');

                string header = requestHeader.Substring(0, headerEndIndex);
                string value = requestHeader.Substring(headerEndIndex + 2);

                switch (header.ToLower())
                {
                    case "range":
                    case "expect":
                    case "keep-alive":
                    case "connection":
                    case "proxy-connection": break;
                    default: request.Headers[header] = value; break;

                    case "host": request.Host = value; break;
                    case "accept": request.Accept = value; break;
                    case "referer": request.Referer = value; break;
                    case "user-agent": request.UserAgent = value; break;
                    case "content-type": request.ContentType = value; break;

                    case "content-length":
                    {
                        request.ContentLength = long.Parse(
                            value, CultureInfo.InvariantCulture);

                        break;
                    }

                    case "if-modified-since":
                    {
                        request.IfModifiedSince = DateTime.Parse(
                            value.Split(';')[0], CultureInfo.InvariantCulture);

                        break;
                    }
                }
            }
            return request;
        }

        public void SendWebResponse(byte[] data)
        {
            try
            {
                if (data != null && Client.Connected)
                {
                    DataStream.Write(data, 0, data.Length);
                }
            }
            catch (IOException) { }
        }
        public void SendWebResponse(string head)
        {
            SendWebResponse(Encoding.UTF8.GetBytes(head));
        }
        public void SendWebResponse(WebResponse response, byte[] responseBody)
        {
            string responseHeaders = response.Headers.ToString();
            string formattedCookies = FormatResponseCookies(response);
            if (!string.IsNullOrWhiteSpace(formattedCookies))
            {
                string unformattedCookies = response.Headers["Set-Cookie"];
                unformattedCookies = $"Set-Cookie: {unformattedCookies}\r\n";

                responseHeaders = responseHeaders.Replace(
                    unformattedCookies, formattedCookies);
            }
            if (responseBody != null &&
                responseHeaders.Contains("Content-Length") &&
                !responseHeaders.Contains($"Content-Length: {responseBody.Length}\r\n"))
            {
                int contentLengthStartIndex = responseHeaders.IndexOf("Content-Length");
                int contentLengthEndIndex = responseHeaders.IndexOf("\r\n", contentLengthStartIndex);

                string contentLength = responseHeaders.Substring(
                    contentLengthStartIndex, contentLengthEndIndex - contentLengthStartIndex);

                responseHeaders = responseHeaders
                    .Replace(contentLength, $"Content-Length: {responseBody.Length}");
            }

            int statusCode = 200;
            string statusDesc = "OK";
            var hRes = (response as HttpWebResponse);
            if (hRes != null)
            {
                statusCode = (int)hRes.StatusCode;
                statusDesc = hRes.StatusDescription;
            }

            string responseCommand = string.Format("HTTP/1.0 {0} {1}\r\n{2}",
                statusCode, statusDesc, responseHeaders);

            SendWebResponse(responseCommand);
            SendWebResponse(responseBody);
        }

        public bool SecureTunnel(string host)
        {
            host = host.Split(':')[0];
            SslStream secureDataStream = null;
            try
            {
                secureDataStream = new SslStream(DataStream, false);
                X509Certificate2 certificate = Certifier.GenerateCertificate(host);
                secureDataStream.AuthenticateAsServer(certificate, false, SslProtocols.Default, false);
            }
            catch { secureDataStream = null; }
            finally
            {
                if (secureDataStream != null)
                {
                    DataStream = secureDataStream;
                }
            }
            return (IsSecure = (secureDataStream == DataStream));
        }
        public string[] ReceiveWebRequestHeaders()
        {
            try
            {
                string requestHeaders = string.Empty;
                var requestHeaderReader = new BinaryReader(DataStream);
                while (!requestHeaders.EndsWith("\r\n\r\n"))
                {
                    requestHeaders += requestHeaderReader.ReadChar();
                }

                return requestHeaders.Trim().Split(new[] { "\r\n" },
                    StringSplitOptions.RemoveEmptyEntries);
            }
            catch (Exception) { return null; }
        }

        protected string FormatResponseCookies(WebResponse response)
        {
            string setCookie = response.Headers["Set-Cookie"];
            if (string.IsNullOrWhiteSpace(setCookie)) return string.Empty;

            string[] cookies = _cookieSplitter.Split(setCookie);
            var cookieBuilder = new StringBuilder();
            foreach (string cookie in cookies)
            {
                cookieBuilder.AppendFormat(
                    "Set-Cookie: {0}\r\n", cookie);
            }
            return cookieBuilder.ToString();
        }

        public void Dispose()
        {
            Dispose(true);
        }
        protected virtual void Dispose(bool disposing)
        {
            if (IsDisposed) return;
            if (disposing)
            {
                try
                {
                    Client.Shutdown(SocketShutdown.Both);
                }
                catch (SocketException) { }
                finally
                {
                    DataStream.Close();
                    Client.Close();
                }
            }
            IsDisposed = true;
        }
    }
}
using System;

using Microsoft.Win32;

namespace Eavesdrop.Utilities
{
    public static class INETOptions
    {
        private readonly static RegistryKey _proxyKey;

        public static string FTPAddress
        {
            get { return GetAddress("ftp"); }
            set { SetAddress("ftp", value); }
        }
        public static string HTTPAddress
        {
            get { return GetAddress("http"); }
            set { SetAddress("http", value); }
        }
        public static string SocksAddress
        {
            get { return GetAddress("socks"); }
            set { SetAddress("socks", value); }
        }
        public static string SecureAddress
        {
            get { return GetAddress("https"); }
            set { SetAddress("https", value); }
        }

        public static bool IsProxyEnabled
        {
            get
            {
                object proxyEnable = _proxyKey.GetValue("ProxyEnable");
                if (proxyEnable == null) return false;

                return ((int)proxyEnable == 1);
            }
            set
            {
                _proxyKey.SetValue("ProxyEnable", (value ? 1 : 0));
                Refresh();
            }
        }

        static INETOptions()
        {
            _proxyKey = Registry.CurrentUser.OpenSubKey(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", true);
        }

        private static void Refresh()
        {
            NativeMethods.InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            NativeMethods.InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
        private static string GetAddress(string proxyType)
        {
            var proxyServer =
             ((string)_proxyKey.GetValue("ProxyServer") + ";");

            int proxyAddressStartIndex = proxyServer.IndexOf($"{proxyType}=");
            if (proxyAddressStartIndex != -1)
            {
                proxyAddressStartIndex +=
                    (proxyType.Length + 1);

                int proxyAddressEndIndex =
                    proxyServer.IndexOf(';', proxyAddressStartIndex);

                string proxyAddress = proxyServer.Substring(proxyAddressStartIndex,
                    proxyAddressEndIndex - proxyAddressStartIndex);

                return proxyAddress;
            }
            else return string.Empty;
        }
        private static void SetAddress(string proxyType, string addess)
        {
            proxyType += "=";
            if (!string.IsNullOrWhiteSpace(addess) && !addess.StartsWith(proxyType))
            {
                addess = (proxyType + addess);
            }

            var joinedAddresses = ((string)_proxyKey.GetValue("ProxyServer") ?? string.Empty);
            if (!joinedAddresses.Contains(proxyType))
            {
                joinedAddresses += (";" + addess);
            }

            string proxyServer = "{http}{https}{ftp}{socks}";
            string[] proxyAddresses = joinedAddresses.Split(';');
            foreach (string proxyAddress in proxyAddresses)
            {
                if (string.IsNullOrWhiteSpace(proxyAddress)) continue;

                int addressTypeEndIndex = proxyAddress.IndexOf('=');
                if (addressTypeEndIndex == -1) continue;

                string addressType = proxyAddress.Substring(0, addressTypeEndIndex);

                string addressValue = proxyAddress.Substring(
                    addressTypeEndIndex, proxyAddress.Length - addressTypeEndIndex);

                if (!string.IsNullOrWhiteSpace(addess))
                {
                    proxyServer = proxyServer
                        .Replace($"{{{addressType}}}", proxyAddress + ";");
                }
            }

            proxyServer = proxyServer
                .Replace("{http}", string.Empty)
                .Replace("{https}", string.Empty)
                .Replace("{ftp}", string.Empty)
                .Replace("{socks}", string.Empty);

            if (proxyServer.EndsWith(";"))
            {
                proxyServer = proxyServer
                    .Substring(0, proxyServer.Length - 1);
            }
            _proxyKey.SetValue("ProxyServer", proxyServer);
            Refresh();
        }
    }
}
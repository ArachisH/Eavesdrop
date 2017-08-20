using System;
using System.Collections.Generic;

using Microsoft.Win32;

namespace Eavesdrop
{
    public static class INETOptions
    {
        private static readonly object _stateLock;
        private static readonly RegistryKey _proxyKey;

        public static List<string> Overrides { get; }

        public static string HTTPAddress { get; set; }
        public static string HTTPSAddress { get; set; }

        public static bool IsProxyEnabled { get; set; }
        public static bool IsIgnoringLocalTraffic { get; set; }

        static INETOptions()
        {
            _stateLock = new object();
            _proxyKey = Registry.CurrentUser.OpenSubKey(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", true);

            Overrides = new List<string>();
            Load();
        }

        public static void Save()
        {
            lock (_stateLock)
            {
                SaveAddresses();
                SaveOverrides();

                _proxyKey.SetValue("ProxyEnable", (IsProxyEnabled ? 1 : 0));
                Apply();
            }
        }
        public static void Load()
        {
            lock (_stateLock)
            {
                LoadAddresses();
                LoadOverrides();

                object proxyEnable = _proxyKey.GetValue("ProxyEnable");
                if (proxyEnable != null)
                {
                    IsProxyEnabled = ((int)proxyEnable == 1);
                }
            }
        }

        private static void SaveAddresses()
        {
            var addresses = new List<string>(2);
            if (!string.IsNullOrWhiteSpace(HTTPAddress))
            {
                addresses.Add("http=" + HTTPAddress);
            }
            if (!string.IsNullOrWhiteSpace(HTTPSAddress))
            {
                addresses.Add("https=" + HTTPSAddress);
            }
            if (addresses.Count > 0)
            {
                _proxyKey.SetValue("ProxyServer", string.Join(";", addresses));
            }
            else if (_proxyKey.GetValue("ProxyServer") != null)
            {
                _proxyKey.DeleteValue("ProxyServer");
            }
        }
        private static void LoadAddresses()
        {
            var proxyServer = (string)_proxyKey.GetValue("ProxyServer");
            if (string.IsNullOrWhiteSpace(proxyServer)) return;

            string[] values = proxyServer.Split(';');
            foreach (string value in values)
            {
                string[] pair = value.Split('=');
                string protocol = pair[0];
                string address = pair[1];

                switch (protocol)
                {
                    case "http": HTTPAddress = address; break;
                    case "https": HTTPSAddress = address; break;
                }
            }
        }

        private static void SaveOverrides()
        {
            var overrides = new List<string>(Overrides);
            if (IsIgnoringLocalTraffic)
            {
                overrides.Add("<local>");
            }
            if (overrides.Count > 0)
            {
                _proxyKey.SetValue("ProxyOverride", string.Join(";", overrides));
            }
            else if (_proxyKey.GetValue("ProxyOverride") != null)
            {
                _proxyKey.DeleteValue("ProxyOverride");
            }
        }
        private static void LoadOverrides()
        {
            var proxyOverride = (string)_proxyKey.GetValue("ProxyOverride");
            if (string.IsNullOrWhiteSpace(proxyOverride)) return;

            string[] overrides = proxyOverride.Split(';');
            foreach (string @override in overrides)
            {
                if (@override == "<local>")
                {
                    IsIgnoringLocalTraffic = true;
                }
                else if (!Overrides.Contains(@override))
                {
                    Overrides.Add(@override);
                }
            }
        }

        private static void Apply()
        {
            NativeMethods.InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            NativeMethods.InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
    }
}
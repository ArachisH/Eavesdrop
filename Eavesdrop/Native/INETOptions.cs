using System.ComponentModel;
using System.Runtime.InteropServices;

using Microsoft.Win32;

namespace Eavesdrop;

public static class INETOptions
{
    private static readonly object _stateLock;
    private static readonly RegistryKey? _proxyKey;

    public static HashSet<string> Overrides { get; }

    public static string? HttpAddress { get; set; }
    public static string? HttpsAddress { get; set; }

    public static bool IsProxyEnabled { get; set; }
    public static bool IsIgnoringLocalTraffic { get; set; }

    static INETOptions()
    {
        _stateLock = new object();
        _proxyKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true);

        Overrides = new HashSet<string>();
        Load();
    }

    public unsafe static void Save()
    {
        const int INTERNET_OPTION_REFRESH = 37;
        const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        const int INTERNET_OPTION_PER_CONNECTION_OPTION = 75;

        lock (_stateLock)
        {
            string? addresses = IsProxyEnabled ? GetJoinedAddresses() : string.Empty;
            string? overrides = IsProxyEnabled ? GetJoinedOverrides() : string.Empty;

            fixed (char* addressesPtr = addresses)
            fixed (char* overridesPtr = overrides)
            {
                int optionsCount = 1;
                Span<INETOption> options = stackalloc INETOption[3];

                ProxyKind kind = ProxyKind.PROXY_TYPE_DIRECT;
                if (!string.IsNullOrWhiteSpace(addresses))
                {
                    kind |= ProxyKind.PROXY_TYPE_PROXY;

                    options[optionsCount++] = new INETOption(OptionKind.INTERNET_PER_CONN_PROXY_SERVER, addressesPtr);
                    if (!string.IsNullOrWhiteSpace(overrides))
                    {
                        options[optionsCount++] = new INETOption(OptionKind.INTERNET_PER_CONN_PROXY_BYPASS, overridesPtr);
                    }
                }
                options[0] = new INETOption(OptionKind.INTERNET_PER_CONN_FLAGS, (int)kind);

                fixed (INETOption* optionsPtr = options)
                {
                    Span<INETOptionList> inetOptionList = stackalloc INETOptionList[1];
                    inetOptionList[0] = new INETOptionList
                    {
                        Size = sizeof(INETOptionList),
                        Connection = null,
                        OptionCount = optionsCount,
                        OptionError = 0,
                        OptionsPtr = optionsPtr
                    };

                    fixed (INETOptionList* optionListPtr = inetOptionList)
                    {
                        if (!NativeMethods.InternetSetOption(null, INTERNET_OPTION_PER_CONNECTION_OPTION, optionListPtr, sizeof(INETOptionList)))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                        
                        NativeMethods.InternetSetOption(null, INTERNET_OPTION_SETTINGS_CHANGED, optionListPtr, sizeof(INETOptionList));
                        NativeMethods.InternetSetOption(null, INTERNET_OPTION_REFRESH, optionListPtr, sizeof(INETOptionList));
                    }
                }
            } 
        }
    }
    public static void Load()
    {
        lock (_stateLock)
        {
            LoadAddresses();
            LoadOverrides();
            IsProxyEnabled = _proxyKey?.GetValue("ProxyEnable")?.ToString() == "1";
        }
    }

    private static void LoadOverrides()
    {
        string? proxyOverride = _proxyKey?.GetValue("ProxyOverride")?.ToString();
        if (string.IsNullOrWhiteSpace(proxyOverride)) return;

        string[] overrides = proxyOverride.Split(';');
        foreach (string @override in overrides)
        {
            if (@override == "<local>")
            {
                IsIgnoringLocalTraffic = true;
            }
            else Overrides.Add(@override);
        }
    }
    private static void LoadAddresses()
    {
        string? proxyServer = _proxyKey?.GetValue("ProxyServer")?.ToString();
        if (string.IsNullOrWhiteSpace(proxyServer)) return;

        string[] values = proxyServer.Split(';');
        foreach (string value in values)
        {
            string[] pair = value.Split('=');
            if (pair.Length != 2)
            {
                HttpAddress = value;
                HttpsAddress = value;
                return;
            }

            string address = pair[1];
            string protocol = pair[0];
            switch (protocol)
            {
                case "http": HttpAddress = address; break;
                case "https": HttpsAddress = address; break;
            }
        }
    }

    private static string GetJoinedAddresses()
    {
        return string.Join(";",
            !string.IsNullOrWhiteSpace(HttpAddress) ? $"http={HttpAddress}" : string.Empty,
            !string.IsNullOrWhiteSpace(HttpsAddress) ? $"https={HttpsAddress}" : string.Empty);
    }
    private static string GetJoinedOverrides()
    {
        return string.Join(";", Overrides) +
            (IsIgnoringLocalTraffic ? ";<local>" : string.Empty);
    }
}
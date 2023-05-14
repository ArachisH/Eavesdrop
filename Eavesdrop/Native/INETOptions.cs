﻿using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Eavesdrop;

public static class INETOptions
{
    private static readonly object _stateLock;

    static INETOptions()
    {
        _stateLock = new object();
    }

    public unsafe static void Save(string? autoConfigUrl = null)
    {
        if (autoConfigUrl != null)
        {
            // Allows for a new PAC file url to be requested(avoid cache) if the previous session was not terminated properly.
            Save(null);
        }

        const int INTERNET_OPTION_REFRESH = 37;
        const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        const int INTERNET_OPTION_PER_CONNECTION_OPTION = 75;

        lock (_stateLock)
        {
            fixed (char* autoConfigUrlPtr = autoConfigUrl)
            {
                ProxyKind kind = string.IsNullOrWhiteSpace(autoConfigUrl) ? ProxyKind.PROXY_TYPE_DIRECT : ProxyKind.PROXY_TYPE_AUTO_PROXY_URL;

                Span<INETOption> options = stackalloc INETOption[2];
                options[0] = new INETOption(OptionKind.INTERNET_PER_CONN_FLAGS, (int)kind);
                options[1] = new INETOption(OptionKind.INTERNET_PER_CONN_AUTOCONFIG_URL, autoConfigUrlPtr);

                fixed (INETOption* optionsPtr = options)
                {
                    INETOptionList inetOptionList = new()
                    {
                        Size = sizeof(INETOptionList),
                        OptionError = 0,
                        Connection = null,
                        OptionsPtr = optionsPtr,
                        OptionCount = options.Length
                    };

                    if (!NativeMethods.InternetSetOption(null, INTERNET_OPTION_PER_CONNECTION_OPTION, &inetOptionList, sizeof(INETOptionList)))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    NativeMethods.InternetSetOption(null, INTERNET_OPTION_SETTINGS_CHANGED, &inetOptionList, sizeof(INETOptionList));
                    NativeMethods.InternetSetOption(null, INTERNET_OPTION_REFRESH, &inetOptionList, sizeof(INETOptionList));
                }
            }
        }
    }
}
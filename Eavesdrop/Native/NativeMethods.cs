using System.Runtime.InteropServices;

namespace Eavesdrop;

// TODO-FUTURE: .NET 7 LibraryImport generator
internal unsafe static class NativeMethods
{
    /// <summary>
    /// Sets an Internet option.
    /// </summary>
    /// <param name="hInternet">Handle on which to set information.</param>
    /// <param name="dwOption">Internet option to be set. This can be one of the <see cref="OptionKind"/> values.</param>
    /// <param name="lpBuffer">Pointer to a buffer that contains the option setting.</param>
    /// <param name="dwBufferLength">Size of the lpBuffer buffer.</param>
    /// <returns>Returns <c>true</c> if successful, or <c>false</c> otherwise. To get a specific error message, call <see cref="Marshal.GetLastWin32Error"/>.</returns>
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool InternetSetOption(void* hInternet, int dwOption, void* lpBuffer, int dwBufferLength);
}
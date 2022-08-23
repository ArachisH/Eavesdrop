using System.Runtime.InteropServices;

namespace Eavesdrop;

/// <summary>
/// Contains the list of options for a particular Internet connection.
/// </summary>
/// <remarks>INTERNET_PER_CONN_OPTION_LIST structure (wininet.h)</remarks>
[StructLayout(LayoutKind.Sequential)]
internal unsafe ref struct INETOptionList
{
    /// <summary>
    /// Size of the structure, in bytes.
    /// </summary>
    public int Size;

    /// <summary>
    /// Pointer to a string that contains the name of the RAS connection or NULL, which indicates the default or LAN connection, to set or query options on.
    /// </summary>
    public char* Connection;

    /// <summary>
    /// Number of options to query or set.
    /// </summary>
    public int OptionCount;

    /// <summary>
    /// Options that failed, if an error occurs.
    /// </summary>
    public int OptionError;

    /// <summary>
    /// Pointer to an array of <see cref="INETOption"/> structures containing the options to query or set.
    /// </summary>
    public INETOption* OptionsPtr;
}

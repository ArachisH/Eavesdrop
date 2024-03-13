using System.Runtime.InteropServices;

#if NET5_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

namespace Eavesdrop;

/// <summary>
/// Contains the value of an option.
/// </summary>
/// <remarks>INTERNET_PER_CONN_OPTION structure (wininet.h)</remarks>
[StructLayout(LayoutKind.Sequential)]
internal unsafe readonly struct INETOption
{
    private readonly OptionKind _kind;
    private readonly INETOptionValue _value;

    public INETOption(OptionKind kind, int value)
    {
        _kind = kind;
        _value = new(value);
    }
    public INETOption(OptionKind kind, char* stringPtr)
    {
        _kind = kind;
        _value = new(stringPtr);
    }

    /// <summary>
    /// Represents the option value union.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    private unsafe readonly struct INETOptionValue
    {
        [FieldOffset(0)]
        private readonly int _intValue;

        [FieldOffset(0)]
        private readonly char* _stringPtr;

        [FieldOffset(0)]
        private readonly ulong _fileTime;

        public INETOptionValue(int intValue)
        {
#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out this);
#endif
            _intValue = intValue;
        }
        public INETOptionValue(char* stringPtr)
        {
#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out this);
#endif
            _stringPtr = stringPtr;
        }
    }
}
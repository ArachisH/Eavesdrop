using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

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
            Unsafe.SkipInit(out this);
            _intValue = intValue;
        }
        public INETOptionValue(char* stringPtr)
        {
            Unsafe.SkipInit(out this);
            _stringPtr = stringPtr;
        }
    }
}
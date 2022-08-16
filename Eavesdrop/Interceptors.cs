namespace Eavesdrop;

[Flags]
public enum Interceptors
{
    None = 0,
    Http = 1,
    Https = 2,

    Default = (Http | Https)
}
using System;
using System.Linq;
using System.Collections.Generic;

namespace Eavesdrop
{
    internal static class EavesExtensions
    {
        /// <summary>
        /// Reference: http://stackoverflow.com/questions/4171140/iterate-over-values-in-flags-enum
        /// </summary>
        public static IEnumerable<Enum> GetUniqueFlags(this Enum flags)
        {
            ulong flag = 1;
            foreach (var value in Enum.GetValues(flags.GetType()).Cast<Enum>())
            {
                ulong bits = Convert.ToUInt64(value);
                while (flag < bits)
                {
                    flag <<= 1;
                }
                if (flag == bits && flags.HasFlag(value))
                {
                    yield return value;
                }
            }
        }
    }
}
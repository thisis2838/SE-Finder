using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SE_Finder_Rewrite.Utils
{
    static class StringExtensions
    {
        public static IEnumerable<String> SplitInParts(this string s, int partLength)
        {
            if (s == null)
                throw new ArgumentNullException(nameof(s));
            if (partLength <= 0)
                throw new ArgumentException("Part length has to be positive.", nameof(partLength));

            for (var i = 0; i < s.Length; i += partLength)
                yield return s.Substring(i, Math.Min(partLength, s.Length - i));
        }

        public static string GetByteString(this uint o)
        {
            return BitConverter.ToString(BitConverter.GetBytes(o)).Replace("-", " ");
        }

        public static string ConvertToHex(this string o)
        {
            string output = "";
            foreach (char i in o)
                output += ((byte)i).ToString("x2") + " ";

            return output;
            //return BitConverter.ToString(Encoding.Default.GetBytes(o)).Replace("-", " ");
        }

        public static string GetByteString(this int o) => GetByteString((uint)o);
        public static string GetByteString(this IntPtr o) => GetByteString((uint)o);
    }
}

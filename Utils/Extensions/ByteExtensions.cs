using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SE_Finder_Rewrite.Utils
{
    enum ByteCompareType
    {
        Full,
        Any,
        UpperNibble,
        LowerNibble
    }

    static class ByteExtensions
    {
        static public byte GetUpperNibble(this byte a)
        {
            return (byte)((a & 0xF0) >> 4);
        }
        static public byte GetLowerNibble(this byte a)
        {
            return (byte)(a & 0x0F);
        }

        static public bool CompareNibble(this byte a, byte b, bool upperA = true, bool upperB = true)
        {
            byte nibbleA = !upperA ? GetLowerNibble(a) : GetUpperNibble(a);
            byte nibbleB = !upperB ? GetLowerNibble(b) : GetUpperNibble(b);

            return nibbleA == nibbleB;
        }

        static public bool CompareByte(this byte a , byte b, ByteCompareType t)
        {
            switch (t)
            {
                case ByteCompareType.Full:
                    return (a == b);
                case ByteCompareType.Any:
                    return true;
                case ByteCompareType.LowerNibble:
                    return a.CompareNibble(b, false, true);
                case ByteCompareType.UpperNibble:
                    return a.CompareNibble(b, false, false);
            }
            return false;
        }
    }

}

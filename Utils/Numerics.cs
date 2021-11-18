using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SE_Finder_Rewrite.Utils.Extensions
{
    static class Numerics
    {
        static public int Abs(this int a)
        {
            return (a ^ (a >> 31)) - (a >> 31);
        }
    }
}

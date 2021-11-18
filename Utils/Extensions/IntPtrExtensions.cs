using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SE_Finder_Rewrite.Utils
{
    static class IntPtrExtensions
    {
        static public void Report(this IntPtr ptr, string name = "", PrintLevel level = PrintLevel.Normal)
        {
            name = $"{(string.IsNullOrWhiteSpace(name) ? "ptr" : name)}";
            if (ptr == IntPtr.Zero)
                PrintHelper.Print($"{name} wasn't found!", PrintLevel.Warning);
            else PrintHelper.Print($"{name} found at 0x{ptr.ToString("X2")}", level);
        }

        static public void Report(this IntPtr ptr, Printer printer, string name = "", PrintLevel level = PrintLevel.Normal)
        {
            name = $"{(string.IsNullOrWhiteSpace(name) ? "ptr" : name)}";
            if (ptr == IntPtr.Zero)
                printer.Print($"{name} wasn't found!", PrintLevel.Warning);
            else printer.Print($"{name} found at 0x{ptr.ToString("X2")}", level);
        }

        static public bool IsSmaller(this IntPtr ptr, IntPtr other)
        {
            return (long)ptr < (long)other;
        }

        static public IntPtr Bound(this IntPtr ptr, IntPtr start, IntPtr end)
        {
            if (ptr.IsSmaller(start))
                ptr = start;
            if (!ptr.IsSmaller(end))
                ptr = end;

            return ptr;
        }

        static public IntPtr Subtract(this IntPtr ptr, IntPtr other)
        {
            return (IntPtr)((int)ptr - (int)other);
        }

        static public int SubtractI(this IntPtr ptr, IntPtr other)
        {
            return (int)ptr - (int)other;
        }

        static public IntPtr Add(this IntPtr ptr, IntPtr other)
        {
            return (IntPtr)((int)ptr + (int)other);
        }

        static public int AddI(this IntPtr ptr, IntPtr other)
        {
            return (int)ptr + (int)other;
        }
    }
}

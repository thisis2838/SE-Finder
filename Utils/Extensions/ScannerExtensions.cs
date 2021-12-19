using LiveSplit.ComponentUtil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static SE_Finder_Rewrite.Program;

namespace SE_Finder_Rewrite.Utils.Extensions
{
    public struct BackTraceArgs
    {
        public int Boundary;
        public int InterruptAmount;
        public bool CheckVFTable;
        public int CheckCallBoundary;

        public static BackTraceArgs Fast = new BackTraceArgs
        {
            Boundary = 0x600,
            InterruptAmount = 3,
            CheckVFTable = false,
            CheckCallBoundary = 0
        };

        public static BackTraceArgs Intermediate = new BackTraceArgs
        {
            Boundary = 0x700,
            InterruptAmount = 3,
            CheckVFTable = false,
            CheckCallBoundary = 0x10000
        };

        public static BackTraceArgs Slow = new BackTraceArgs
        {
            Boundary = 0x1000,
            InterruptAmount = 3,
            CheckVFTable = true,
            CheckCallBoundary = 0x100000
        };

        public static BackTraceArgs Extreme = new BackTraceArgs
        {
            Boundary = 0x2000,
            InterruptAmount = 3,
            CheckVFTable = true,
            CheckCallBoundary = 0x500000
        };

        public static BackTraceArgs Custom(int boundary, int interrupt, bool vftable, int checkCall)
        {
            return new BackTraceArgs()
            {
                Boundary = boundary,
                InterruptAmount = interrupt,
                CheckVFTable = vftable,
                CheckCallBoundary = checkCall
            };
        }

        public BackTraceArgs Modify(
            int boundary = -1,
            int interrupt = -1,
            int vftable = -1,
            int checkCall = -1)
        {
            BackTraceArgs newArgs = this;

            if (boundary != -1)
                newArgs.Boundary = boundary;
            if (interrupt != -1)
                newArgs.InterruptAmount = interrupt;
            if (vftable != -1)
                newArgs.CheckVFTable = vftable == 1;
            if (checkCall != -1)
                newArgs.CheckCallBoundary = checkCall;

            return newArgs;
        }
    }

    static class ScannerExtensions
    {
        static private int[] _endianMapping = new int[] { 6, 7, 4, 5, 2, 3, 0, 1 };

        static private Tag _context = new Tag("");
        static private Printer _pr = new Printer(new Tag("Util", ConsoleColor.Cyan, ConsoleColor.Black), _context);

        public static List<IntPtr> FindRelativeCalls(this SigScanner scanner, IntPtr ptr, int boundary, int delta = 0)
        {
            IntPtr start = (ptr - boundary).Bound(scanner.Start, scanner.End);
            IntPtr end = (ptr + boundary).Bound(scanner.Start, scanner.End);
            return scanner.FindRelativeCalls(ptr, start, end, delta);
        }

        public static List<IntPtr> FindRelativeCalls(this SigScanner scanner, IntPtr ptr, IntPtr start, IntPtr end, int delta = 0)
        {
            _context.Update($"Relative Calls : 0x{ptr.ToString("X")}", ConsoleColor.Green);
            StationaryPrint sp = new StationaryPrint(_pr);

            char[] posArr = new char[8];

            int boundary = 0;
            int deltaEnd = end.SubtractI(ptr).Abs();
            int deltaStart = start.SubtractI(ptr).Abs();
            boundary = deltaEnd > deltaStart ? deltaEnd : deltaStart;

            for (int i = 0x10000000, j = 0; i >= 1; i /= 0x10, j++)
                posArr[_endianMapping[j]] = boundary > i ? '?' : '0';

            string pos = new string(posArr);
            string neg = pos.Replace('0', 'F');

            SigCollection s = new SigCollection();
            s.Add("E8 " + neg);
            s.Add("E8 " + pos);
            s.Add("E9 " + neg);
            s.Add("E9 " + pos);

            SigScanner newScanner = new SigScanner(
                scanner.Process,
                start,
                (int)end.Subtract(start));

            s.EvaluateMatch = (a) =>
            {
                if ((int)(Math.Abs(a.SubtractI(ptr))) < boundary &&
                Math.Abs(scanner.Process.ReadRelativeReference(a).SubtractI(ptr)) <= delta)
                {
                    sp.Print($"Match at 0x{a.ToString("X")}");
                    return true;
                }
                return false;
            };

            try { return newScanner.ScanAll(s); }
            finally { sp.Return(); }
        }


        public static List<IntPtr> FindVFTableEntries(this SigScanner scanner, IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return new List<IntPtr>();

            Signature p = new Signature(ptr.GetByteString());
            p.EvaluateMatch = (a) =>
            {
                bool aligned = (int)a % 4 == 0;
                bool valid = scanner.IsWithin(Game.ReadPointer(a + 0x4)) 
                && scanner.IsWithin(Game.ReadPointer(a - 0x4));

                return (aligned && valid);
            };

            return scanner.ScanAll(p);
        }

        private static byte[] _backTraceBytes = new byte[] { 0xCC, 0x90, 0xC2, 0xC3 };
        public static IntPtr BackTraceToFuncStart(
            this SigScanner scanner,
            IntPtr ptr,
            int boundary = 0x600,
            int interruptAmount = 3,
            bool checkVFTable = false,
            int checkCallBoundary = 0)
        {
            if (ptr == IntPtr.Zero)
                return IntPtr.Zero;

            List<IntPtr> foundFunctions = new List<IntPtr>(); 
            if (checkCallBoundary > 0)
            {
                foundFunctions = scanner.FindRelativeCalls(ptr - (boundary >> 1), checkCallBoundary, boundary >> 1);
                foundFunctions = foundFunctions.ConvertAll(x => Program.Game.ReadRelativeReference(x));
            }
            //calls.ForEach(x => x.Report());

            _context.Update($"Backtrace : 0x{ptr.ToString("X")}", ConsoleColor.Blue);
            StationaryPrint sp = new StationaryPrint(_pr);

            IntPtr curPtr = ptr;
            while (boundary > 0 && !curPtr.IsSmaller(scanner.Start))
            {
                boundary--;
                curPtr = curPtr - 1;

                byte curByte = scanner.Process.ReadValue<byte>(curPtr, 1);
                byte lastByte = scanner.Process.ReadValue<byte>(curPtr + 1);

                sp.Print($"{boundary} bytes left, 0x{curPtr.ToString("X")} : {curByte:X02} {lastByte:X02}");

                if (!_backTraceBytes.Contains(curByte) || _backTraceBytes.Contains(lastByte))
                    continue;

                try
                {
                    if (interruptAmount > 0 && (curByte == 0x90 || curByte == 0xCC))
                    {
                        byte[] interruptBytes = scanner.Process.ReadBytes(curPtr - interruptAmount, interruptAmount);
                        if (interruptBytes.All(x => x == 0x90 || x == 0xCC))
                            return curPtr + 1;
                    }

                    IntPtr tmp = curPtr + ((curByte == 0xC2) ? 0x3 : 0x1);

                    if (checkVFTable)
                    {
                        if (scanner.FindVFTableEntries(tmp).Count != 0x0)
                            return tmp;
                    }

                    if (checkCallBoundary > 0 && foundFunctions.Count() > 0)
                    {
                        if (foundFunctions.Contains(tmp))
                            return tmp;
                    }
                }
                finally { sp.Return(); }
            }

            return IntPtr.Zero;
        }

        public static IntPtr BackTraceToFuncStart(
            this SigScanner scanner, 
            IntPtr ptr,
            BackTraceArgs args)
            => BackTraceToFuncStart(
                scanner, 
                ptr, 
                args.Boundary, 
                args.InterruptAmount, 
                args.CheckVFTable, 
                args.CheckCallBoundary);

        public static IntPtr FindStringPtr(this SigScanner scanner, string str)
        {
            Signature s = new Signature(str.ConvertToHex());
            return scanner.Scan(s);
        }

        public static IntPtr FindVarReference(this SigScanner scanner, IntPtr ptr, string prefix = "", string suffix = "")
        {
            Signature s = new Signature($"{prefix} {ptr.GetByteString()} {suffix}");
            return scanner.Scan(s);
        }

        public static IntPtr FindFuncThroughStringRef(
            this SigScanner scanner,
            string targString,
            BackTraceArgs backTraceArgs,
            int strPtrOff = 0,
            int strRefPtrOff = -1,
            Printer pr = null)
        {
            void report(IntPtr a, string name = "", PrintLevel level = PrintLevel.Normal)
            {
                if (pr == null)
                    a.Report(name, level);
                else a.Report(pr, name, level);
            }

            IntPtr ptr = scanner.FindStringPtr(targString) + strPtrOff;
            report(ptr, "string");

            if (ptr == IntPtr.Zero)
                return ptr;

            Signature sig = new Signature(ptr.GetByteString(), strRefPtrOff);
            ptr = scanner.Scan(sig);
            report(ptr, "string ref");

            if (ptr == IntPtr.Zero)
                return ptr;

            ptr = scanner.BackTraceToFuncStart(ptr, backTraceArgs);
            report(ptr, "estimated", PrintLevel.BlueBG);

            return ptr;
        }

        public static IntPtr TraceToFuncEnd(this SigScanner scanner, IntPtr ptr, bool early = false)
        {
            if (ptr == IntPtr.Zero)
                return ptr;

            var tmpScanner = new SigScanner(scanner.Process, ptr, scanner.End);
            var sc = new SigCollection();

            if (early)
            {
                sc.Add("C3");
                sc.Add("C3");
                sc.Add(new Signature("C2 ?? 00", 3));

                return tmpScanner.ScanMinimum(sc);
            }

            sc.Add(new Signature("CC CC CC CC", -1));
            sc.Add(new Signature("C3 CC CC CC", 0));
            sc.Add(new Signature("90 90 90 90", -1));
            sc.Add(new Signature("C3 90 90 90", 0));
            sc.Add(new Signature("C2 90 90 90", 0));

            return tmpScanner.ScanMinimum(sc);

        }

        public static IntPtr FindCVarBase(this SigScanner scanner, string str)
        {
            IntPtr stringPtr = scanner.FindStringPtr(str);
            Signature target = new Signature("68" + stringPtr.GetByteString() + "B9", 6);
            return Program.Game.ReadPointer(scanner.Scan(target));
        }

        public static List<IntPtr> FindMOVReferences(this SigScanner scanner, IntPtr ptr)
        {
            List<IntPtr> output = new List<IntPtr>();

            if (ptr == IntPtr.Zero)
                return output;

            string byteStr = ptr.GetByteString();

            var sc = new SigCollection();
            sc.Add($"8B ?? {byteStr}");
            sc.Add($"8A ?? {byteStr}");
            sc.Add($"A1  {byteStr}");
            sc.Add($"A2  {byteStr}");
            sc.Add($"A3  {byteStr}");
            sc.Add($"B8 ?? {byteStr}");
            sc.Add($"B9 ?? {byteStr}");

            return scanner.ScanAll(sc);
        }

    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static System.Console;
using System.Threading.Tasks;
using System.Diagnostics;
using SE_Finder_Rewrite.Utils.Extensions;

namespace SE_Finder_Rewrite.Utils
{
    class Tests
    {
        public static void TestCollectionScan()
        {
            byte[] bytes = new byte[] { 0x10, 0x31, 0x20, 0x5C, 0x78, 0x01, 0x10, };

            SigCollection sc = new SigCollection("20 5C", "10 31");
            Signature s = new Signature("10 31 47");
            SigScanner scanner = new SigScanner(bytes);

            /*
            Stopwatch sw = new Stopwatch();
            sw.Start();
            for (int i = 0; i <= 0x5000; i++)
            {
                scanner.ScanMinimum(sc);
            }

            WriteLine(sw.ElapsedMilliseconds);
            */

            WriteLine(scanner.Scan(sc));
            ReadLine();
        }

        public static void TestIntAbs()
        {
            WriteLine((-25).Abs());
            ReadLine();
        }
    }
}

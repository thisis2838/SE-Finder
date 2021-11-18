using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SE_Finder_Rewrite.Utils
{
    class FunctionPointer
    {
        private SigScanner _scanner;
        private Process _proc => _scanner.Process;
        public IntPtr Start;
        public FunctionPointer(IntPtr ptr, SigScanner scanner)
        {
            Start = ptr;
            _scanner = scanner;
        }

    }
}

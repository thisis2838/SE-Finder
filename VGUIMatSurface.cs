
using LiveSplit.ComponentUtil;
using System;
using System.Diagnostics;
using System.Threading;

namespace sig
{
    class VGUIMATSURFACE : Run
    {

        private SignatureScanner scanner;
        private const string _moduleName = "VGUIMatSurface";
        public void print(string msg, string tag = _moduleName, int highlight = 0) =>
            prints(tag == "" ? msg : (_context == "" ? "" : $"[{_context}] ") + msg, tag, highlight);
        public void report(IntPtr ptr, string name = "", int highlightLevel = 1) =>
            reports(ptr, _context == "" ? "" : (name == "" ? $"[{_context}]" : $"[{_context}] ") + name, highlightLevel, _moduleName);
        private string _context = "";


        public VGUIMATSURFACE()
        {
            scanner = new SignatureScanner(game, vguim.BaseAddress, vguim.ModuleMemorySize);
            Start();
        }

        public void Start()
        {
            print("", "");
            print("Searching for vguimatsurface.dll functions / vars... \n", _moduleName, 3);
            FIND_StartDrawing();
            FIND_FinishDrawing();
            print("--------", "");
        }

        private IntPtr FindFuncThroughStringRef(string targString, string name = "", string subName = "", bool checkCALL = false)
        {
            _context = name;
            subName = subName == "" ? "" : $"[{subName}] ";
            IntPtr ptr = FindStringAddress(targString, scanner);
            report(ptr, subName + "string");

            if (ptr == IntPtr.Zero)
                return IntPtr.Zero;

            SigScanTarget trg = ConvertPtrToSig(ptr, 0x0, "68");
            ptr = scanner.Scan(trg);
            report(ptr, subName + "string ref");

            ptr = BackTraceToFuncStart(ptr, scanner, checkCALL);
            report(ptr, subName + "(estimated)", 2);
            if (subName == "")
                print("", "");
            return ptr;
        }

        private IntPtr PTR_StartDrawing = IntPtr.Zero;

        void FIND_StartDrawing()
        {
            PTR_StartDrawing = FindFuncThroughStringRef("-pixel_offset_x", "StartDrawing");
        }

        void FIND_FinishDrawing()
        {
            _context = "FinishDrawing";
            var tmpScanner = new SignatureScanner(game, PTR_StartDrawing + 0x50, 0x500);
            var trg = new SigScanTarget(2, "C6 05 ?? ?? ?? ?? 01");
            trg.OnFound = (f_proc, f_scanner, f_ptr) => f_proc.ReadPointer(f_ptr);
            
            IntPtr ptr = tmpScanner.Scan(trg);
            report(ptr, "g_bInDrawing");

            trg = ConvertPtrToSig(ptr, 0, "C6 05", "00");
            ptr = scanner.Scan(trg);
            report(ptr, "g_bInDrawing ref");

            ptr = BackTraceToFuncStart(ptr, scanner, true);
            report(ptr, "", 2);

        }

    }
}

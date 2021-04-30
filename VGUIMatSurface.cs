
using LiveSplit.ComponentUtil;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace sig
{
    class VGUIMATSURFACE : Run
    {

        private SignatureScanner scanner;

        public VGUIMATSURFACE()
        {
            scanner = new SignatureScanner(game, vguim.BaseAddress, vguim.ModuleMemorySize);
            ModuleName = "VGUIMatSurface";
            Context = "";
            CurModule = vguim;
            Start();
        }

        public void Start()
        {
            var watch = new Stopwatch();
            watch.Start();

            print("", "");
            print("Searching for vguimatsurface.dll functions / vars... \n", ModuleName, 3);
            FIND_StartDrawing();
            FIND_FinishDrawing();

            Context = "";
            Console.WriteLine("");
            print($"VGUIMatSurface scanning done after {watch.Elapsed}");
            Console.WriteLine("");
            print("--------", "");
        }

        private IntPtr PTR_StartDrawing = IntPtr.Zero;

        void FIND_StartDrawing()
        {
            PTR_StartDrawing = FindFuncThroughStringRef("-pixel_offset_x", scanner, "StartDrawing");
            print("", "");
        }

        void FIND_FinishDrawing()
        {
            Context = "FinishDrawing";
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

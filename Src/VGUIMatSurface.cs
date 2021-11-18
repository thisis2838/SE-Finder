using SE_Finder_Rewrite.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using LiveSplit.ComponentUtil;
using System.Threading.Tasks;
using SE_Finder_Rewrite.Utils.Extensions;
using static SE_Finder_Rewrite.Utils.Extensions.BackTraceArgs;
using static SE_Finder_Rewrite.Program;
using static SE_Finder_Rewrite.Utils.PrintLevel;

namespace SE_Finder_Rewrite.Src
{
    class VGUIMatSurface : Module
    {
        public VGUIMatSurface() : base()
        {
            Name = "vguimatsurface.dll";
            ModuleTag.Name = ("VGUIMATSURFACE");

            _actions.Add(FIND_StartDrawing);
            _actions.Add(FIND_FinishDrawing);
        }

        IntPtr _ptrStartDrawing = IntPtr.Zero;
        void FIND_StartDrawing()
        {
            _context.Name = "StartDrawing";
            _ptrStartDrawing = _scanner.FindFuncThroughStringRef("-pixel_offset_x", Intermediate, pr:_pr);
        }

        void FIND_FinishDrawing()
        {
            _context.Name = "FinishDrawing";

            var tmpScanner = new SigScanner(Game, _ptrStartDrawing + 0x50, 0x500);
            var sig = new Signature("C6 05 ?? ?? ?? ?? 01", 2);

            _subContext1.Name = "g_bInDrawing";

            IntPtr ptr = Game.ReadPointer(tmpScanner.Scan(sig));
            ptr.Report(_pr);

            sig = new Signature("C6 05 " + ptr.GetByteString() + "00");
            ptr = _scanner.Scan(sig);
            ptr.Report(_pr, "reference");

            _subContext1.Update();

            ptr = _scanner.BackTraceToFuncStart(ptr, Intermediate);
            ptr.Report(_pr, level: BlueBG);
        }
    }
}

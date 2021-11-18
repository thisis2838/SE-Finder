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
    class Client : Module
    {
        public Client() : base()
        {
            Name = "client.dll";
            ModuleTag.Name = ("CLIENT");

            _actions.Add(FIND_DoImageSpaceMotionBlur);
            _actions.Add(FIND_HudUpdate);
            _actions.Add(FIND_GetButtonBits);
            _actions.Add(FIND_ShakeAndFade);
            _actions.Add(FIND_AdjustAngles);
            _actions.Add(FIND_CreateMove);
        }

        void FIND_DoImageSpaceMotionBlur()
        {
            _context.Name = "DoImageSpaceMotionBlur";
            _scanner.FindFuncThroughStringRef("dev/motion_blur", Intermediate.Modify(0x10000), pr: _pr);
        }

        void FIND_HudUpdate()
        {
            _context.Name = "HudUpdate";

            _pr.Print("Running method 1 -- finding \"(time_float)\" reference and backtracing", BlueFG);
            _subContext1.Name = "1";

            IntPtr ptr = _scanner.FindFuncThroughStringRef("(time_float)", Intermediate, pr: _pr);
            if (ptr != IntPtr.Zero)
                return;

            _subContext1.Update();
            _pr.Print("Running method 2 -- finding LevelInitPreEntity to coerce vftable pointer", BlueFG);
            _subContext1.Name = "2";

            _subContext2.Name = "LevelInitPreEntity func";

            ptr = _scanner.FindFuncThroughStringRef("cl_predict 0", Intermediate, pr: _pr);
            ptr = _scanner.FindVFTableEntries(ptr).FirstOrDefault();
            ptr.Report(_pr, "CHLClient vftable pointer");

            _subContext1.Update();
            _subContext2.Update();

            Game.ReadPointer(ptr + 6 * 4).Report(_pr);
        }

        void FIND_GetButtonBits()
        {
            _context.Name = "GetButtonBits";

            SigCollection sig = new SigCollection(
                "81 CE 00 00 20 00",
                "0D 00 00 20 00");

            IntPtr ptr = _scanner.Scan(sig);
            ptr.Report(_pr, "middle of func");

            _scanner.BackTraceToFuncStart(ptr, Slow).Report(_pr, "estimated", BlueBG);
        }

        void FIND_ShakeAndFade()
        {
            _context.Name = "Shake&Fade";

            _subContext1.Name = "Shake";
            _subContext2.Name = "CalcShake";
            IntPtr ptr = _scanner.FindFuncThroughStringRef(
                "%02d: dur(%8.2f) amp(%8.2f) freq(%8.2f)",
                Intermediate,
                pr: _pr);

            ptr = _scanner.FindVFTableEntries(ptr).FirstOrDefault();
            ptr.Report(_pr, "vftable entry");

            _subContext2.Update();
            Game.ReadPointer(ptr - 0x10).Report(_pr, level: BlueBG);

            _subContext1.Name = "Fade";
            Game.ReadPointer(ptr - 0xc).Report(_pr, level: BlueBG);
        }

        void FIND_AdjustAngles()
        {
            _context.Name = "AdjustAngles";

            _pr.Print("Results may be inaccurate especially in old engine!", YellowFG);
            _pr.Print("Function may also be inlined with CreateMove!", YellowFG);

            _subContext1.Name = "DetermineKeySpeed";

            IntPtr tmpPtr = _scanner.FindCVarBase("cl_anglespeedkey");
            tmpPtr.Report(_pr, "cvar base");

            again:
            IntPtr ptr = tmpPtr + GetIntOffset;
            ptr = _scanner.Scan(new Signature(ptr.GetByteString()));
            ptr.Report(_pr, "cvar ref");
            if (ptr == IntPtr.Zero)
            {
                if (GetIntOffset == 0x18)
                    return;

                _pr.Print("GetIntOffset might be wrong, switching and trying again...", YellowFG);
                GetIntOffset = 0x18;
                goto again;
            }

            ptr = _scanner.BackTraceToFuncStart(ptr, Intermediate);
            ptr.Report(_pr, "estimated");

            ptr = _scanner.FindRelativeCalls(ptr, 0x300000).FirstOrDefault();
            ptr.Report(_pr, "reference");

            _subContext1.Update();

            ptr = _scanner.BackTraceToFuncStart(ptr, Slow);
            ptr.Report(_pr, level: BlueBG);
        }

        void FIND_CreateMove()
        {
            _context.Name = "CreateMove";

            IntPtr ptr = _scanner.FindCVarBase("sv_noclipduringpause");
            ptr.Report(_pr, "cvar base");

            if (ptr == IntPtr.Zero)
            {
                _specifics.Add("create-move-in-client", true);
                _pr.Print("might be in server instead, aborting.", YellowFG);
                return;
            }

            Signature sig = new Signature((ptr + GetIntOffset).GetByteString());
            ptr = _scanner.Scan(sig);
            ptr.Report(_pr, "cvar ref");

            ptr = _scanner.BackTraceToFuncStart(ptr, Slow);
            ptr.Report(_pr, level: BlueBG);
        }
    }
}

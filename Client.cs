
using LiveSplit.ComponentUtil;
using System;
using System.Diagnostics;
using System.Threading;

namespace sig
{
    class CLIENT : Run
    {

        private SignatureScanner scanner;

        public CLIENT()
        {
            scanner = new SignatureScanner(game, client.BaseAddress, client.ModuleMemorySize);
            ModuleName = "client";
            Context = "";
            Start();
        }

        public void Start()
        {
            print("", "");
            print("Searching for client.dll functions / vars... \n", "client", 3);
            FIND_DoImageSpaceMotionBlur();
            FIND_HudUpdate();
            FIND_GetButtonBits();
            FIND_ShakeAndFade();
            FIND_AdjustAngles();
            print("--------", "");
        }

        void FIND_DoImageSpaceMotionBlur()
        {
            FindFuncThroughStringRef("dev/motion_blur", scanner, "DoImageSpaceMotionBlur");
        }

        void FIND_HudUpdate()
        {
            Context = "HudUpdate";
            print("Running method 1 -- finding \"(time_float)\" reference and retracing");
            IntPtr ptr = FindFuncThroughStringRef("(time_float)", scanner, "HudUpdate");
            if (ptr == IntPtr.Zero) goto method2;

            goto eof;

        method2:
            SigScanTarget trg = new SigScanTarget();

            print("Running method 2 -- finding LevelInitPreEntity to coerce vftable pointer");
            ptr = FindFuncThroughStringRef("cl_predict 0", scanner, "HudUpdate", "LevelInitPreEntity");
            trg = ConvertPtrToSig(ptr, 0x0);
            ptr = scanner.Scan(trg);
            report(ptr, "LevelInitPreEntity func CHLClient vftable pointer");

            // assume the function is 6 entires away
            ptr = game.ReadPointer(ptr + 6 * 4);
            report(ptr, "", 2);

        eof:
            ;
        }

        void FIND_GetButtonBits()
        {
            Context = "GetButtonBits";
            var target = new SigScanTarget(0, "81 ce 00 00 20 00");
            target.AddSignature(0, "0d 00 00 20 00");
            var ptr = scanner.Scan(target);
            report(ptr, "middle of func");

            ptr = BackTraceToFuncStart(ptr, scanner);
            report(ptr, "(estimated)", 2);
            print("", "");
        }

        void FIND_ShakeAndFade()
        {
            Context = "Shake";
            IntPtr ptr = FindFuncThroughStringRef("%02d: dur(%8.2f) amp(%8.2f) freq(%8.2f)", scanner, "Shake", "CalcShake", false);
            var trg = ConvertPtrToSig(ptr);
            ptr = scanner.Scan(trg);
            report(ptr, "CalcShake vftable entry");

            report(game.ReadPointer(ptr - 0x10), "", 2);
            Context = "Fade";
            report(game.ReadPointer(ptr - 0xc), "", 2);
            print("", "");
        }

        void FIND_AdjustAngles()
        {
            Context = "AdjustAngles";

            IntPtr ptr = IntPtr.Zero;
            IntPtr ptrTmp = FindCVarBase("cl_anglespeedkey", scanner);
            report(ptrTmp, "[DetermineKeySpeed] cvar base");

        again:

            ptr = ptrTmp + GetIntOffset;

            var trg = ConvertPtrToSig(ptr);
            ptr = scanner.Scan(trg);
            if (ptr == IntPtr.Zero)
            {
                GetIntOffset = 0x18;
                print("GetIntOffset might be wrong, setting to 0x18 instead");
                goto again;
            }
            report(ptr, "[DetermineKeySpeed] cvar ref");

            ptr = BackTraceToFuncStart(ptr, scanner, true);
            report(ptr, "[DetermineKeySpeed] (estimate)");

            IntPtr ptr2 = FindRelativeCallReference(ptr, 0x3000);
            report(ptr2, "DetermineKeySpeed ref");

            if (ptr2 == IntPtr.Zero)
            {
                print("retrying to find DetermineKeySpeed ref");
                ptr2 = FindRelativeCallReference(ptr, 0x15000, "", "", null, (int)(ptr - 0x270000));
                report(ptr2, "DetermineKeySpeed thunk fun");
                ptr2 = FindRelativeCallReference(ptr2, 0x15000, "", "", null, (int)(ptr2 + 0x270000));
                report(ptr2, "DetermineKeySpeed ref");
            }

            ptr = BackTraceToFuncStart(ptr2, scanner);
            report(ptr, "(estimate)", 2);
        }
    }
}

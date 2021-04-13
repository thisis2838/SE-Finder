
using LiveSplit.ComponentUtil;
using System;
using System.Diagnostics;
using System.Threading;

namespace sig
{
    class ENGINE : Run
    {

        private SignatureScanner scanner;

        public ENGINE()
        {
            scanner = new SignatureScanner(game, engine.BaseAddress, engine.ModuleMemorySize);
            ModuleName = "engine";
            Context = "";
            Start();
        }

        public void Start()
        {
            print("", "");
            print("Searching for engine.dll functions / vars... \n", ModuleName, 3);
            FIND_FinishRestore();
            FIND_SetPaused();
            FIND_Record();
            FIND_SV_ActivateServer();
            FIND_Host_Runframe();
            print("--------", "");
        }

        void FIND_FinishRestore()
        {
            Context = "FinishRestore";
            IntPtr ptr = FindStringAddress("\0%s%s.HL2", scanner);
            report(ptr, "string");

            if (ptr == IntPtr.Zero)
                return;

            SigScanTarget trg = ConvertPtrToSig(ptr + 0x1, 0x0, "68");
            ptr = scanner.Scan(trg);
            report(ptr, "string ref");

            ptr = BackTraceToFuncStart(ptr, scanner, true);
            report(ptr, "(estimated)", 2);

            print("", "");
            return;
        }

        void FIND_SV_ActivateServer()
        {
            FindFuncThroughStringRef("SV_ActivateServer\0", scanner, "SV_ActivateServer", "");
        }

        void FIND_Record()
        {
            FindFuncThroughStringRef("Can't record on dedicated server.\n", scanner, "Record");
        }
        void FIND_Host_Runframe()
        {
            FindFuncThroughStringRef("_Host_RunFrame (top):", scanner, "Host_Runframe");
        }

        void FIND_SetPaused()
        {
            Context = "SetPaused";
            IntPtr ptr = FindStringAddress("\0paused\0", scanner);
            report(ptr, "[pause CCommand] string");

            if (ptr == IntPtr.Zero)
                return;

            SigScanTarget trg = ConvertPtrToSig(ptr + 0x1, -0x1, "");
            ptr = scanner.Scan(trg);
            report(ptr, "[pause CCommand] string ref");

            ptr = ReadCallRedirect(ptr - 0xC);
            report(ptr, "", 2);
            print("", "");
        }

    }
}

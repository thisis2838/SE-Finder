
using LiveSplit.ComponentUtil;
using System;
using System.Collections.Generic;
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
            CurModule = engine;
            Start();
        }

        public void Start()
        {
            var watch = new Stopwatch();
            watch.Start();

            print("", "");
            print("Searching for engine.dll functions / vars... \n", ModuleName, 3);
            FIND_SpawnPlayer();
            FIND_FinishRestore();
            FIND_SetPaused();
            FIND_Record();
            FIND_SV_ActivateServer();
            FIND_Host_Runframe();
            FIND_Host_AccumulateTime();
            FIND_SV_Frame();

            Context = "";
            Console.WriteLine("");
            print($"Engine scanning done after {watch.Elapsed}");
            Console.WriteLine("");
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
            FindFuncThroughStringRef("record <demoname> [incremental]\n", scanner, "Record");
        }

        private IntPtr PTR_Host_Runframe;

        void FIND_Host_Runframe()
        {
            PTR_Host_Runframe = FindFuncThroughStringRef("_Host_RunFrame (top):", scanner, "Host_Runframe", "", true);
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

        void FIND_Host_AccumulateTime()
        {
            Context = "Host_AccumulateTime";
            print("Running method 1 -- finding \"-tools\" reference and retracing");
            IntPtr ptr = FindStringAddress("-tools", scanner);
            report(ptr, "string");

            if (ptr == IntPtr.Zero || PTR_Host_Runframe == IntPtr.Zero)
                return;

            SigScanTarget trg = ConvertPtrToSig(ptr, 0, "68");
            var tmpScanner = new SignatureScanner(game, engine.BaseAddress, engine.ModuleMemorySize);

            bool found = false;
            int i = 1;
            do
            {
                trg.OnFound = (f_proc, f_scanner, f_ptr) =>
                {
                    report(f_ptr, $"#{i} string ref");
                    IntPtr funcPtr2 = BackTraceToFuncStart(f_ptr, scanner);
                    report(funcPtr2, $"#{i} candidate function");
                    IntPtr funcPtr = FindRelativeCallReference(funcPtr2, 0x4000);
                    report(funcPtr, $"#{i} candidate function reference");
                    funcPtr = BackTraceToFuncStart(funcPtr, scanner, true);
                    report(funcPtr, $"#{i} candidate caller");
                    if (funcPtr == PTR_Host_Runframe)
                    {
                        found = true;
                        return funcPtr2;
                    }

                    f_scanner.Limit(f_ptr);
                    return f_ptr;
                };
                ptr = tmpScanner.Scan(trg);
                i++;
            }
            while (!found && ptr != IntPtr.Zero);

            report(ptr, "", 2);
            if (ptr == IntPtr.Zero)
            {
                print("Running method 2 -- finding TEST insturction and sigscanning");
                ptr = TraceToFuncEnd(PTR_Host_Runframe, true);
                report(ptr, "[Host_Runframe] func end");
                tmpScanner = new SignatureScanner(game, PTR_Host_Runframe, (int)(ptr - (int)PTR_Host_Runframe));

                trg = new SigScanTarget("85 C0");
                ptr = tmpScanner.Scan(trg);
                report(ptr, "[Host_Runframe] target TEST instruction ptr");

                tmpScanner.Limit(ptr);
                trg = new SigScanTarget("E8");
                ptr = ReadCallRedirect(tmpScanner.Scan(trg));
                report(ptr, "", 2);
            }
            print("", "");

        }

        void FIND_SV_Frame()
        {
            IntPtr ptr = FindFuncThroughStringRef("_Host_RunFrame_Server", scanner, "SV_Frame", "_Host_RunFrame_Server", true);
            IntPtr funcEnd = TraceToFuncEnd(ptr, true);
            report(funcEnd, "[_Host_RunFrame_Server] func end");

            var tmpScanner = new SignatureScanner(game, ptr, (int)(funcEnd - (int)ptr));
            var trg = new SigScanTarget(0, "E8 ?? ?? ?? ?? 83 C4 04 FF");

            trg.OnFound = (f_proc, f_scanner, f_ptr) => ReadCallRedirect(f_ptr);
            ptr = tmpScanner.Scan(trg);
            report(ptr, "", 2);
            print("", "");
        }

        void FIND_SpawnPlayer()
        {
            Context = "SpawnPlayer";

            IntPtr spawnPtr = FindFuncThroughStringRef("CBaseClient::SpawnPlayer", scanner, "SpawnPlayer", "CBaseClient::SpawnPlayer", true);
            IntPtr ptr = FindFuncThroughStringRef("serverGameDLL->LevelInit", scanner, "SpawnPlayer", "Host_NewGame", true);
            IntPtr endPtr = TraceToFuncEnd(ptr);
            report(endPtr, "[Host_NewGame] func end");

            if (endPtr == IntPtr.Zero)
                return;

            var tmpScanner = new SignatureScanner(game, ptr, (int)(endPtr - (int)ptr));
            var trg = new SigScanTarget(2, "c6 05 ?? ?? ?? ?? 01");
            trg.OnFound = (f_proc, f_scanner, f_ptr) => f_proc.ReadPointer(f_ptr);

            IntPtr bLoadPtr = tmpScanner.Scan(trg);
            report(bLoadPtr, "m_bLoadgame ptr");

            if (bLoadPtr == IntPtr.Zero)
                return;

            List<IntPtr> ignored = new List<IntPtr>();
            int i = 0;
            trg = ConvertPtrToSig(bLoadPtr, 0, "80 ??", "00");
            do
            {
                i++;
                IntPtr refPtr = FindRelativeCallReference(spawnPtr, 0x200000, "", "", ignored);
                report(refPtr, $"candidate function #{i} CBaseClient::SpawnPlayer ref");
                ptr = BackTraceToFuncStart(refPtr, scanner);
                report(ptr, $"candidate function #{i} start");
                IntPtr end = TraceToFuncEnd(ptr, true);
                report(end, $"candidate function #{i} end");
                if (ptr == IntPtr.Zero)
                    break;
                tmpScanner = new SignatureScanner(game, ptr, (int)(end - (int)ptr));
                if (tmpScanner.Scan(trg) != IntPtr.Zero)
                    break;
                ignored.Add(refPtr + 1);
            }
            while (ptr != IntPtr.Zero);
            report(ptr, "", 2);
            print("", "");
        }

    }
}

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
    class Engine : Module
    {
        public Engine() : base()
        {
            Name = "engine.dll";
            ModuleTag.Name = ("ENGINE");

            _actions.Add(FIND_FinishRestore);
            _actions.Add(FIND_SV_ActivateServer);
            _actions.Add(FIND_Record);
            _actions.Add(FIND_Host_Runframe);
            _actions.Add(FIND_SetPaused);
            _actions.Add(FIND_Host_AccumulateTime);
            _actions.Add(FIND_SpawnPlayer);
            _actions.Add(FIND_SV_Frame);
            _actions.Add(FIND_SleepUntilInput);
        }

        private void FIND_FinishRestore()
        {
            _context.Name = "FinishRestore";
            _scanner.FindFuncThroughStringRef("\0%s%s.HL2", Intermediate, 0x1, pr: _pr);
        }

        private void FIND_SV_ActivateServer()
        {
            _context.Name = "SV_ActivateServer";
            _scanner.FindFuncThroughStringRef("SV_ActivateServer\0", BackTraceArgs.Slow, 0, pr: _pr);
        }

        private void FIND_Record()
        {
            _context.Name = "Record";
            _scanner.FindFuncThroughStringRef("record <demoname> [incremental]\n", Intermediate, 0, pr: _pr);
        }

        private IntPtr _ptrHostRunFrame;

        private void FIND_Host_Runframe()
        {
            _context.Name = "Host_Runframe";
            _ptrHostRunFrame = _scanner.FindFuncThroughStringRef(
                "_Host_RunFrame (top)", 
                Intermediate, 
                0,
                pr: _pr);
        }

        void FIND_SetPaused()
        {
            _context.Name = "SetPaused";

            _subContext1.Name = "pause CCommand";

            IntPtr ptr = _scanner.FindStringPtr("\0paused\0") + 1;
            ptr.Report(_pr, "string");

            if (ptr == IntPtr.Zero)
                return;

            Signature sig = new Signature(ptr.GetByteString(), -1);
            ptr = _scanner.Scan(sig);
            ptr.Report(_pr, "string reference");

            _subContext1.Name = "";
            ptr = _scanner.Process.ReadRelativeReference(ptr - 0xC);
            ptr.Report(_pr, "", PrintLevel.BlueBG);
        }

        void FIND_Host_AccumulateTime()
        {
            _context.Name = "Host_AccumulateTime";
            _pr.Print("Running method 1 -- finding \"-tools\" reference and retracing", PrintLevel.BlueFG);
            _subContext1.Name = "1";

            IntPtr ptr = _scanner.FindStringPtr("-tools");
            ptr.Report(_pr, "string");

            if (ptr == IntPtr.Zero )
                goto method2;

            Signature sig = new Signature("68" + ptr.GetByteString());
            int i = 0;
            sig.EvaluateMatch = (a) =>
            {
                i++;
                _subContext2.Name = $"candidate {i}";

                a.Report(_pr, $"string ref");
                IntPtr fPtr2 = _scanner.BackTraceToFuncStart(a, Intermediate);
                fPtr2.Report(_pr, $"function");
                IntPtr fPtr = _scanner.FindRelativeCalls(fPtr2, 0x4000).FirstOrDefault();
                fPtr.Report(_pr, $"function reference");
                fPtr = _scanner.BackTraceToFuncStart(fPtr, Intermediate);
                fPtr.Report(_pr, $"caller");

                if (fPtr == _ptrHostRunFrame)
                {
                    ptr = fPtr2;
                    return true;
                }

                ptr = IntPtr.Zero;
                return false;
            };

            _scanner.Scan(sig);
            _subContext2.Update();
            ptr.Report(_pr, level: PrintLevel.BlueBG);

            method2:

            if (ptr == IntPtr.Zero && _ptrHostRunFrame != IntPtr.Zero)
            {
                _subContext1.Update();

                _pr.Print("Running method 2 -- finding TEST insturction and sigscanning", PrintLevel.BlueFG);
                _subContext2.Name = "Host_Runframe";

                _subContext1.Name = "2";

                var tmpScanner = new SigScanner(Game, _ptrHostRunFrame, _scanner.TraceToFuncEnd(_ptrHostRunFrame));
                sig = new Signature("85 C0");

                sig.EvaluateMatch = (a) =>
                {
                    a.Report(_pr, "target TEST instruction ptr");
                    var newSig = new Signature("E8");
                    tmpScanner.Limit(a);
                    ptr = Game.ReadRelativeReference(tmpScanner.Scan(newSig));
                    ptr.Report(_pr, "", PrintLevel.BlueBG);
                    
                    return true;
                };

                tmpScanner.Scan(sig);
            }
        }

        void FIND_SpawnPlayer()
        {
            _context.Name = "SpawnPlayer";

            _subContext1.Name = "CBaseClient::SpawnPlayer";
            IntPtr spawnPtr = _scanner.FindFuncThroughStringRef(
                "CBaseClient::SpawnPlayer",
                Slow,
                0,
                pr: _pr);

            _subContext1.Name = "Host_NewGame";
            IntPtr ptr = _scanner.FindFuncThroughStringRef(
                "serverGameDLL->LevelInit",
                Slow,
                0,
                pr: _pr);
            IntPtr newGameFuncEnd = _scanner.TraceToFuncEnd(ptr);
            newGameFuncEnd.Report(_pr, "func end");
            _subContext1.Update();

            var tmpScanner = new SigScanner(Game, ptr, newGameFuncEnd);
            ptr = Game.ReadPointer(tmpScanner.Scan(new Signature("C6 05 ?? ?? ?? ?? 01", 2)));
            ptr.Report(_pr, "m_bLoadgame");

            if (ptr == IntPtr.Zero)
                return;

            List<IntPtr> references = _scanner.FindRelativeCalls(spawnPtr, 0x200000);
            var sig = new Signature($"80 ?? {ptr.GetByteString()} 00");
            int i = 0;

            foreach (IntPtr candidatePtr in references)
            {
                i++;
                _subContext1.Name = $"candidate {i}";

                IntPtr funcBegin = _scanner.BackTraceToFuncStart(candidatePtr, Intermediate);
                IntPtr funcEnd = _scanner.TraceToFuncEnd(candidatePtr, true);
                _pr.Print($"func from 0x{funcBegin.ToString("X")} to 0x{funcEnd.ToString("X")}");
                tmpScanner = new SigScanner(Game, funcBegin, funcEnd);

                if (tmpScanner.Scan(sig) != IntPtr.Zero)
                {
                    funcBegin.Report(_pr, "estimate", PrintLevel.BlueBG);
                    break;
                }
            }

        }

        void FIND_SV_Frame()
        {
            _context.Name = "SV_Frame";

            _subContext1.Name = "_Host_RunFrame_Server";
            IntPtr ptr = _scanner.FindFuncThroughStringRef("_Host_RunFrame_Server", Intermediate, pr: _pr);
            IntPtr funcEnd = _scanner.TraceToFuncEnd(ptr);
            funcEnd.Report(_pr, "func end");

            _subContext1.Update();
            var tmpScanner = new SigScanner(Game, ptr, funcEnd);
            var sig = new Signature("E8 ?? ?? ?? ?? 83 C4 04");
            ptr = Game.ReadRelativeReference(tmpScanner.Scan(sig));
            ptr.Report(_pr, level: PrintLevel.BlueBG);
        }

        void FIND_SleepUntilInput()
        {
            _context.Name = "SleepUntilInput";

            _subContext1.Name = "CEngine::Frame";

            IntPtr ptr = _scanner.FindStringPtr("fs_report_sync_opens");
            ptr.Report(_pr, "string");
            if (ptr == IntPtr.Zero)
                return;

            ptr = _scanner.Scan(new Signature("68" + ptr.GetByteString()));
            ptr = _scanner.BackTraceToFuncStart(ptr, Intermediate.Modify(vftable: 1));
            ptr.Report(_pr, level: BlueFG);

            if (ptr == IntPtr.Zero)
                return;

            SigScanner tmpScanner = new SigScanner(Game, ptr, _scanner.TraceToFuncEnd(ptr));
            SigCollection sc = new SigCollection(
                new Signature("75 ?? ?? ?? ?? ?? ?? ?? 75", 9),
                new Signature("0F 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F 85", 0xE));
            ptr = tmpScanner.Scan(sc);
            ptr.Report(_pr, "Target instructions");

            if (ptr == IntPtr.Zero)
                return;

            tmpScanner = new SigScanner(Game, ptr, Game.ReadValue<byte>(ptr) + 1);
            Signature sig = new Signature("8B 0D", 2);
            ptr = tmpScanner.Scan(sig);
            IntPtr inputDLLBase = Game.ReadPointer(ptr);
            inputDLLBase.Report(_pr, "Input DLL base", BlueFG);
            tmpScanner.Limit(ptr + 4);

            sig = new Signature("FF");
            sig.EvaluateMatch = (a) =>
            {
                for (int i = 0; i < 4; i++)
                    if (_scanner.IsWithin(Game.ReadRelativeReference(a - i)))
                        return false;
                return true;
            };
            ptr = tmpScanner.Scan(sig);
            ptr.Report(_pr, "Scan region end");

            if (ptr == IntPtr.Zero)
                return;

            _subContext1.Name = "";

            int[] possibleOffsets = new int[2];
            possibleOffsets[0] = Game.ReadValue<byte>(ptr + 0x2);
            byte[] bytes = Game.ReadBytes(tmpScanner.Start, ptr.SubtractI(tmpScanner.Start) + 2);
            for (int i = bytes.Count() - 1; i >= 0; i--)
            {
                if (bytes[i] == 0x8B)
                {
                    possibleOffsets[1] = bytes[i + 2];
                    break;
                }
            }

            _pr.Print($"Possible offsets include 0x{possibleOffsets[0]:X} and 0x{possibleOffsets[1]:X}, testing both...", BlueFG);
            ProcessModuleWow64Safe inputDLL = Game.GetModuleWow64Safe("inputsystem.dll");
            SigScanner inputDLLScanner = inputDLL == null ? null : new SigScanner(Game, inputDLL.BaseAddress, inputDLL.ModuleMemorySize);
            foreach (int off in possibleOffsets)
            {
                new DeepPointer(inputDLLBase, 0x0, off, 0x0).DerefOffsets(Game, out ptr);
                _pr.Print($"Offset 0x{off:X} leads to 0x{ptr.ToString("X8")}");
                if (ptr != IntPtr.Zero)
                {
                    if (!_scanner.IsWithin(ptr))
                        if (inputDLLScanner != null)
                        {
                            if (!inputDLLScanner.IsWithin(ptr))
                                continue;
                        }
                        else continue;

                    ptr.Report(_pr, "candidate", BlueBG);
                    break;
                }

            }
        }
    }
}

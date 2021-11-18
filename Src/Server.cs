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
    class Server : Module
    {
        public Server() : base()
        {
            Name = "server.dll";
            ModuleTag.Name = "SERVER";

            _actions.Add(FIND_CheckVelocity);
            _actions.Add(FIND_CheckJumpButton);
            _actions.Add(FIND_FinishGravity);
            _actions.Add(FIND_CheckStuck);
            _actions.Add(FIND_ReadAll);
            _actions.Add(FIND_DoReadAll);
            _actions.Add(FIND_CreateEntityByName);
            _actions.Add(FIND_DispatchSpawn);
            _actions.Add(FIND_CreateMove);
        }

        private IntPtr _ptrCheckVelocity;

        void FIND_CheckVelocity()
        {
            _context.Name = "CheckVelocity";
            _ptrCheckVelocity = _scanner.FindFuncThroughStringRef("PM  Got a NaN velocity", Intermediate, pr: _pr);
        }

        private List<IntPtr> _listCheckJumpButtonMatches = new List<IntPtr>();
        void FIND_CheckJumpButton()
        {
            _context.Name = "CheckJumpButton";

            _pr.Print("Running method 1 -- finding \"xc_uncrouch_on_jump\" string ref and retracing", BlueFG);
            _subContext1.Name = "1";

            IntPtr ptr = _scanner.FindCVarBase("xc_uncrouch_on_jump");
            IntPtr ptr2 = ptr;
            ptr.Report(_pr, "cvar base");
            if (ptr == IntPtr.Zero)
                goto method2;

            Signature sig = new Signature((ptr + GetIntOffset).GetByteString());
            ptr = _scanner.Scan(sig);
            if (ptr == IntPtr.Zero)
                ptr = _scanner.FindMOVReferences(ptr2).FirstOrDefault();
            ptr.Report(_pr, "string ref");

            ptr = _scanner.BackTraceToFuncStart(ptr, Extreme);
            ptr.Report(_pr, "estimated hl2 base", BlueBG);
            _listCheckJumpButtonMatches.Add(ptr);

            //-------------------

            method2:
            _subContext1.Name = "";
            _pr.Print("Running method 2 -- finding float ref and retracing", BlueFG);
            _subContext1.Name = "2";
            _pr.Print("There may be more than than one match", YellowFG);

            int i = 0;
            StationaryPrint sp = new StationaryPrint(_pr);
            Action<IntPtr, List<IntPtr>> commonCallback = (f, rl) =>
            {
                float d = Game.ReadValue<float>(f);

                foreach (IntPtr r in rl)
                {
                    _pr.Print($"Float {d} at 0x{f.ToString("X")} referenced at 0x{r.ToString("X")}");
                    IntPtr r2 = _scanner.BackTraceToFuncStart(r, Extreme);
                    r2.Report(_pr, $"Estimate #{++i}", BlueBG);
                    _listCheckJumpButtonMatches.Add(r2);
                    sp.Update();
                }
            };
            SigCollection sc = new SigCollection(
                "00 00 20 43",
                "01 2A 86 43");
            sc.EvaluateMatch = (a) =>
            {
                sp.Print($"Float found at 0x{a.ToString("X")}");
                Signature f_sig = new Signature(a.GetByteString() + "EB");
                var f_tmp = _scanner.ScanAll(f_sig);

                if (f_tmp.Count != 0)
                    commonCallback(a, f_tmp);

                return true;

            };
            var tmpSig = new Signature("00 00 34 42");
            tmpSig.EvaluateMatch = (a) =>
            {
                sp.Print($"Float found at 0x{a.ToString("X")}");
                Signature f_sig = new Signature("8B ?? ?? F3 0F ?? ??" + a.GetByteString() + "8B");
                var f_tmp = _scanner.ScanAll(f_sig);

                if (f_tmp.Count != 0)
                    commonCallback(a, f_tmp);

                return true;
            };

            _scanner.ScanAll(sc);
            _scanner.Scan(tmpSig);
            sp.Return();

            _listCheckJumpButtonMatches = _listCheckJumpButtonMatches.Where(x => x != IntPtr.Zero).ToList();

            //-------------------

            _subContext1.Name = "";
            _pr.Print("Final step -- coercing remaning matches through TryPlayerMove VFTable entries", BlueFG);
            _subContext1.Name = "final";
            _listCheckJumpButtonMatches = _listCheckJumpButtonMatches.Distinct().ToList();
            List<IntPtr> listTryPlayerMoveMatches = new List<IntPtr>();

            i = 0;
            foreach (IntPtr cjbPtr in _listCheckJumpButtonMatches)
            {
                ptr = _scanner.FindVFTableEntries(cjbPtr).FirstOrDefault();

                if (ptr == IntPtr.Zero || !_scanner.IsWithin(ptr = Game.ReadPointer(ptr + 0xc)))
                    continue;

                ptr.Report(_pr, $"TryPlayerMove ptr candidate " + ++i);
                listTryPlayerMoveMatches.Add(ptr);
            }

            foreach (IntPtr tpmPtr in listTryPlayerMoveMatches)
            {
                sig = new Signature(tpmPtr.GetByteString());
                var tpmMatches = _scanner.FindVFTableEntries(tpmPtr);

                foreach (IntPtr tpmVFT in tpmMatches)
                {
                    ptr = Game.ReadPointer(tpmVFT - 0xC);
                    if (_scanner.IsWithin(ptr) && !_listCheckJumpButtonMatches.Contains(ptr))
                    {
                        _listCheckJumpButtonMatches.Add(ptr);
                        ptr.Report(_pr, $"New potential CheckJumpButton match", BlueBG);
                    }
                }
            }
        }

        void FIND_FinishGravity()
        {
            IntPtr ptr;
            Signature sig;
            int matchCount = 0, i = 0;

            _context.Name = "FinishGravity";

            _pr.Print("Running method 1 -- looking 1 above CheckJumpButton in CGameMovement vftable", BlueFG);
            _subContext1.Name = "1";

            foreach (IntPtr cjbMatch in _listCheckJumpButtonMatches)
            {
                var matches = _scanner.FindVFTableEntries(cjbMatch);
                foreach (var match in matches)
                {
                    ptr = Game.ReadPointer(match - 0x8);
                    byte[] bytes = Game.ReadBytes(ptr, 10);
                    if (bytes[5] != 0xCC && bytes[5] != 0x90)
                        ptr.Report(_pr, $"candidate #{++matchCount}", BlueBG);
                }
            }

            //-------------------

            _subContext1.Name = "";
            _pr.Print("Running method 2 -- looking for references to CheckVelocity and comparing results to calls found in CheckJumpButton", BlueFG);
            _subContext1.Name = "2";
            _subContext2.Name = "CheckVelocity";

            List<IntPtr> tmp = _scanner.FindRelativeCalls(_ptrCheckVelocity, 0x100000);
            List<IntPtr> checkVelRefs = new List<IntPtr>();
            foreach (IntPtr checkVelRef in tmp)
            {
                ptr = _scanner.BackTraceToFuncStart(checkVelRef, Intermediate.Modify(vftable: 1));
                if (!checkVelRefs.Contains(ptr))
                {
                    checkVelRefs.Add(ptr);
                    ptr.Report(_pr, $"called from 0x{checkVelRef.ToString("X")} under function");
                }
            }

            _subContext2.Name = "branching";
            _pr.Print("Comparing calls to those found in CheckJumpButtons");

            i = 0;
            foreach (IntPtr cjbMatch in _listCheckJumpButtonMatches)
            {
                IntPtr end = _scanner.TraceToFuncEnd(cjbMatch);

                _subContext3.Name = $"CJB at 0x{cjbMatch.ToString("X")}";
                _pr.Print($"Searching through candidate #{++i} to 0x{end.ToString("X")}", BlueFG);


                foreach (IntPtr checkVelRef in checkVelRefs)
                {
                    List<IntPtr> calls = _scanner.FindRelativeCalls(checkVelRef, cjbMatch, end);
                    if (calls.Count() > 0)
                    {
                        calls.ForEach(x => x.Report(_pr, "caller"));
                        checkVelRef.Report(_pr, level: BlueBG);
                    }
                }
            }
        }

        void FIND_CheckStuck()
        {
            _context.Name = "CheckStuck";
            _scanner.FindFuncThroughStringRef("%s stuck on object %i/%s", Intermediate, pr: _pr);
        }


        private IntPtr _ptrReadAll;

        void FIND_ReadAll()
        {
            _context.Name = "ReadAll";

            _subContext1.Name = "ReadFields";

            IntPtr ptr = _scanner.FindFuncThroughStringRef("Expected %s found %s ( raw '%s' )", Slow, pr: _pr);

            _subContext1.Name = "";

            Signature sig = new Signature(ptr.GetByteString(), -0x4);
            ptr = Game.ReadPointer(_scanner.Scan(sig));
            ptr.Report(_pr, level: BlueBG);
            _ptrReadAll = ptr;
        }

        void FIND_DoReadAll()
        {
            if (_ptrReadAll == IntPtr.Zero)
                return;

            _context.Name = "DoReadAll";

            SigScanner tmpScanner = new SigScanner(Game, _ptrReadAll, _scanner.TraceToFuncEnd(_ptrReadAll));
            Signature sig = new Signature("E8", -1);
            IntPtr ptr = Game.ReadRelativeReference(_scanner.Scan(sig));

            if (_scanner.IsWithin(ptr))
                ptr.Report(_pr, level: BlueBG);
        }

        void FIND_CreateEntityByName()
        {
            _context.Name = "CreateEntityByName";
            _scanner.FindFuncThroughStringRef("CreateEntityByName( %s, %d )", Intermediate, pr: _pr);
        }

        void FIND_DispatchSpawn()
        {
            _context.Name = "DispatchSpawn";

            _pr.Print("Running method 1-- finding \"Entity %s not found, and couldn\'t create!\" string ref and retracing", BlueFG);
            _subContext1.Name = "1";

            IntPtr ptr = _scanner.FindStringPtr("Entity %s not found, and couldn\'t create!\n");
            ptr.Report(_pr, "string");

            if (ptr == IntPtr.Zero)
                goto method2;

            Signature sig = new Signature("68" + ptr.GetByteString());
            ptr = _scanner.Scan(sig);
            ptr.Report(_pr, "string ref");

            var tmpScanner = new SigScanner(Game, ptr, 0x100);
            sig = new Signature("B? 01 E8 ?? ?? ?? ??", 2);
            ptr = Game.ReadRelativeReference(_scanner.Scan(sig));
            ptr.Report(_pr, level: BlueBG);
            return;

            method2:
            _subContext1.Name = "";
            _pr.Print("Running method 2 -- finding \"ai_ally_speech_manager\" string ref and retracing", level:BlueFG);
            _subContext1.Name = "2";

            ptr = _scanner.FindStringPtr("ai_ally_speech_manager");
            ptr.Report(_pr, "string");

            if (ptr == IntPtr.Zero)
                return;

            SigCollection sc = new SigCollection();
            sc.Add(new Signature("6A FF 68" + ptr.GetByteString()));
            sc.Add(new Signature("68" + ptr.GetByteString() + "6A FF"));
            ptr = _scanner.Scan(sc);
            ptr.Report(_pr, "string ref");

            sig = new Signature("74 ?? ?? E8", 3);
            tmpScanner = new SigScanner(Game, ptr, 0x40);
            ptr = Game.ReadRelativeReference(tmpScanner.Scan(sig));
            ptr.Report(_pr, level: BlueBG);
        }

        void FIND_CreateMove()
        {
            if (!_specifics.TryGetValue("create-move-in-client", out _))
                return;

            _context.Name = "CreateMove";

            IntPtr ptr = _scanner.FindCVarBase("sv_noclipduringpause");
            ptr.Report(_pr, "cvar base");

            Signature sig = new Signature((ptr + GetIntOffset).GetByteString());
            ptr = _scanner.Scan(sig);
            ptr.Report(_pr, "cvar ref");

            ptr = _scanner.BackTraceToFuncStart(ptr, Slow);
            ptr.Report(_pr, level: BlueBG);
        }
    }
}

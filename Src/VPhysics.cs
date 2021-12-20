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
    class VPhysics : Module
    {
        public VPhysics() : base()
        {
            Name = "vphysics.dll";
            ModuleTag.Name = ("VPHYSICS");

            _actions.Add(FIND_ISGFlag);
        }

        void FIND_ISGFlag()
        {
            _context.Name = "ISGFlag";

            _subContext1.Name = "ivp_mindist_recursive function";

            IntPtr tmp = _scanner.FindStringPtr("IVP Failed at %s %d");
            Signature sig = new Signature($"68 ?? ?? ?? ?? 68 {tmp.GetByteString()}", 1);
            sig.EvaluateMatch = (f_ptr) =>
            {
                IntPtr ptr2 = Game.ReadPointer(f_ptr);
                if (_scanner.IsWithin(ptr2))
                    return Game.ReadString(ptr2, 256).Contains("ivp_collision\\ivp_mindist_recursive.cxx");
                return false;
            };

            tmp = _scanner.Scan(sig);
            tmp = _scanner.BackTraceToFuncStart(tmp, Intermediate.Modify(vftable: 1));

            tmp.Report(_pr, level:BlueFG);

            _subContext1.Name = "Recheck_ov_element";

            SigScanner scanner = new SigScanner(Game, tmp, 0x700);
            SigCollection sc1 = new SigCollection(
                new Signature("E? ?? ?? ?? 00", 0),
                new Signature("E? ?? ?? ?? FF", 0));

            SigCollection sc2 = new SigCollection(
                new Signature("E8 ?? ?? ?? ?? ?? ?? ?? ?? E8", 0),
                new Signature("E8 ?? ?? ?? ?? ?? ?? ?? E8", 0));

            sc1.EvaluateMatch = (f_ptr) =>
            {
                IntPtr ptr2 = Game.ReadRelativeReference(f_ptr);
                if (_scanner.IsWithin(ptr2))
                {
                    ptr2 = _scanner.FindVFTableEntries(ptr2, true).FirstOrDefault();
                    if (ptr2 != IntPtr.Zero)
                    {
                        ptr2.Report(_pr, "Candidate");
                        ptr2 = Game.ReadPointer(ptr2 - 4);
                        SigScanner tmpScanner = new SigScanner(Game,ptr2, 0x20);
                        if (tmpScanner.Scan(sc2) != IntPtr.Zero)
                            return true;
                    }
                }
                return false;
            };

            tmp = Game.ReadRelativeReference(scanner.Scan(sc1));
            _subContext1.Name = "";
            tmp.Report(_pr, level:BlueBG);
        }
    }
}

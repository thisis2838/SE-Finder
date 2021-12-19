using LiveSplit.ComponentUtil;
using SE_Finder_Rewrite.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static SE_Finder_Rewrite.Program;
using static SE_Finder_Rewrite.Utils.PrintHelper;

namespace SE_Finder_Rewrite.Src
{
    abstract class Module
    {
        public string Name = "";
        internal SigScanner _scanner;

        internal Tag ModuleTag = new Tag("", ConsoleColor.White);
        internal Tag _context = new Tag("");
        internal Tag _subContext1 = new Tag("");
        internal Tag _subContext2 = new Tag("");
        internal Tag _subContext3 = new Tag("");
        internal Printer _pr;

        internal List<Action> _actions = new List<Action>();

        internal static Dictionary<string, bool> _specifics = new Dictionary<string, bool>();

        public Module()
        {
            Console.WriteLine();
            _pr = new Printer(ModuleTag, _context, _subContext1, _subContext2, _subContext3);
        }

        internal ProcessModuleWow64Safe TryGetProcess()
        {
            StationaryPrint sp = new StationaryPrint(_pr);

            again:
            ProcessModuleWow64Safe proc = Game.GetModuleWow64Safe(Name);

            if (proc == null)
            {
                sp.Print($"Couldn't find {Name}, retrying in 1s", PrintLevel.Warning);
                Thread.Sleep(1000);
                goto again;
            }

            sp.Return();
            return proc;
        }

        public void Begin()
        {
            Stopwatch sw = new Stopwatch();

            PrintSeparator();
            _pr.Print($"Begin scanning {Name}", PrintLevel.YellowBG);
            sw.Start();

            var mod = TryGetProcess();
            _scanner = new SigScanner(Game, mod.BaseAddress, mod.ModuleMemorySize);

            PrintSeparator();

            _actions.ForEach(x => 
            {
                x();
                _context.Update();
                _subContext1.Update();
                _subContext2.Update();
                _subContext3.Update();

                PrintSeparator();
            });

            sw.Stop();

            _context.Name = "";
            _subContext1.Name = "";
            _pr.Print($"Finished scanning {Name} after {sw.ElapsedMilliseconds} ms", PrintLevel.YellowBG);

            PrintSeparator();
        }
    }
}

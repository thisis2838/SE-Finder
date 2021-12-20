using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using SE_Finder_Rewrite.Utils;
using static System.Console;
using static SE_Finder_Rewrite.Utils.ByteExtensions;
using static SE_Finder_Rewrite.Utils.StringExtensions;
using static SE_Finder_Rewrite.Utils.PrintHelper;
using LiveSplit.ComponentUtil;
using System.Threading;
using SE_Finder_Rewrite.Src;
using static LiveSplit.ComponentUtil.WinAPI;

namespace SE_Finder_Rewrite
{
    class Program
    {
        static public Process Game;
        static public int GetIntOffset = 0x1C;

        private static List<string> _processes = new List<string>(new string[]
        {
            "bms",
            "hl2",
            "portal2",
            "hdtf",
            "stanley",
            "hl1",
            "beginnersguide",
        });

        static void Main(string[] args)
        {
            while (true)
            {
                Clear();
                try
                {
                    _pr.Print($"Trying to get process");
                    Game = Process.GetProcesses().Where(x => _processes.Contains(x.ProcessName)).FirstOrDefault();

                    if (Game != null)
                        Init();
                }
                catch
                {
                    Console.Clear();
                    continue;
                }
                finally { Thread.Sleep(1000); }
            }
        }

        static void Init()
        {
            Clear();

            List<Module> modules = new List<Module>()
            {
                new VGUIMatSurface(),
                new Engine(),
                new Client(),
                new Server(),
                new VPhysics(),
            };

            try
            {
                modules.ForEach(x => x.Begin());
            }
            catch (Exception e)
            {
                ForegroundColor = ConsoleColor.Red;
                WriteLine();
                WriteLine(e);
                WriteLine(e.InnerException?.Message ?? "");
                ReadLine();
            }

            ReadLine();
        }

        static private Tag _tInit = new Tag("INIT", ConsoleColor.White, ConsoleColor.DarkGray);
        static private Printer _pr = new Printer(_tInit);
    }
}

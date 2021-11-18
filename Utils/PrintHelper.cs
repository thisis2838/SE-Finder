using System;
using System.Collections.Generic;
using static SE_Finder_Rewrite.Utils.PrintHelper;
using static SE_Finder_Rewrite.Program;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Console;

namespace SE_Finder_Rewrite.Utils
{
    class Tag
    {
        ConsoleColor ForegroundColor;
        ConsoleColor BackgroundColor;

        public string Name = "";

        public Tag(string name, ConsoleColor fore, ConsoleColor back = ConsoleColor.Black)
        {
            ForegroundColor = fore;
            BackgroundColor = back;
            Name = name;
        }

        public Tag(string name)
        {
            ForegroundColor = ConsoleColor.Gray;
            BackgroundColor = ConsoleColor.Black;

            Name = name;
        }

        public void Update(string name = "", ConsoleColor fore = ConsoleColor.Gray, ConsoleColor back = ConsoleColor.Black)
        {
            Name = name;
            ForegroundColor = fore;
            BackgroundColor = back;
        }


        public void Print()
        {
            if (string.IsNullOrWhiteSpace(Name))
                return;

            ChangeConsoleColor(ForegroundColor, BackgroundColor);
            Write($"[{Name}] ");
            ChangeConsoleColor();
        }
    }
    
    enum PrintLevel
    {
        Normal,
        YellowBG,
        YellowFG,
        BlueBG,
        BlueFG,
        Warning
    }

    class Printer
    {
        public List<Tag> Tags;
        public Printer()
        {
            Tags = new List<Tag>();
        }

        public Printer(params Tag[] tags)
        {
            Tags = new List<Tag>();
            tags.ToList().ForEach(x => Tags.Add(x));
        }

        public void Print(string msg)
        {
            Tags.ForEach(x => x.Print());
            CursorLeft--;
            Write(' ');
            WriteLine(msg);
        }

        public void Print(string msg, PrintLevel level)
        {
            Tags.ForEach(x => x.Print());
            ChangeConsoleColor(level);
            WriteLine(msg);
            ChangeConsoleColor();
        }
                
    }

    class StationaryPrint
    {
        private int _line;
        private Printer _pr;
        public StationaryPrint(Printer pr, int line = -1)
        {
            _pr = pr;
            _line = line == -1 ? CursorTop : line;
        }

        public void ClearLine()
        {
            CursorLeft = 0;
            Write(new string(' ', WindowWidth - CursorLeft));
            CursorLeft = 0;
            CursorTop = _line;
        }

        public void Print(string msg)
        {
            ClearLine();
            _pr.Print(msg);
        }

        public void Print(string msg, PrintLevel level)
        {
            ClearLine();
            PrintHelper.ChangeConsoleColor(level);
            _pr.Print(msg);
            PrintHelper.ChangeConsoleColor();
        }

        public void Return()
        {
            CursorTop = _line;
            ClearLine();
        }

        public void Update()
        {
            _line = CursorTop;
        }
    }

    static class PrintHelper
    {
        static public void PrintSeparator()
        {
            WriteLine("");
        }

        static public void ChangeConsoleColor(ConsoleColor fore, ConsoleColor back)
        {
            ForegroundColor = fore;
            BackgroundColor = back;
        }

        static public void ChangeConsoleColor(PrintLevel level = PrintLevel.Normal)
        {
            switch (level)
            {
                case PrintLevel.Normal:
                    ChangeConsoleColor(ConsoleColor.Gray, ConsoleColor.Black);
                    break;
                case PrintLevel.YellowBG:
                    ChangeConsoleColor(ConsoleColor.Black, ConsoleColor.DarkYellow);
                    break;
                case PrintLevel.YellowFG:
                    ChangeConsoleColor(ConsoleColor.DarkYellow, ConsoleColor.Black);
                    break;
                case PrintLevel.BlueBG:
                    ChangeConsoleColor(ConsoleColor.White, ConsoleColor.DarkBlue);
                    break;
                case PrintLevel.BlueFG:
                    ChangeConsoleColor(ConsoleColor.Blue, ConsoleColor.Black);
                    break;
                case PrintLevel.Warning:
                    ChangeConsoleColor(ConsoleColor.Yellow, ConsoleColor.DarkRed);
                    break;
            }
        }
        static public void PrintC(string msg, PrintLevel level, params string[] context)
        {
            string print = "";
            context.ToList().ForEach(x => print += $"[{x}] ");
            Write(print);

            print = msg;
            ChangeConsoleColor(level);
            WriteLine(print);
            ChangeConsoleColor();
        }

        static public void Print(string msg, PrintLevel level = PrintLevel.Normal) => PrintC(msg, level);
        
        /*
        static public void PrintT(string msg, PrintLevel level, params Tag[] tags)
        {
            tags.ToList().ForEach(x => x.Print());
            ChangeConsoleColor(level);
            WriteLine(msg);
            ChangeConsoleColor();
        }

        static public void PrintT(string msg, params Tag[] tags) => PrintT(msg, PrintLevel.Normal, tags);
        */
    }
}

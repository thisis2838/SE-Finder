
using LiveSplit.ComponentUtil;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace sig
{
    class Run
    {
        public static Process game;

        public static int GetIntOffset = 0x1C;

        public static bool SPECIFICS_CreateMoveInServer = false;

        private static List<string> _processes = new List<string>( new string[]
        {
            "bms",
            "hl2",
            "portal2",
            "hdtf",
            "stanley",
            "hl1",
        });

        private static bool init = true;
        private static int i = 0;

        public static ProcessModuleWow64Safe client;
        public static ProcessModuleWow64Safe server;
        public static ProcessModuleWow64Safe engine;
        public static ProcessModuleWow64Safe vguim;

        public static ProcessModuleWow64Safe CurModule;

        public static void prints(string msg, string tag = "", int highlight = 0, bool inPlace = false)
        {
            Console.Write(tag != "" ? $"[{tag.ToUpper()}] " : "");
            switch (highlight)
            {
                case 0:
                    Console.BackgroundColor = ConsoleColor.Black;
                    break;
                case 1:
                    Console.BackgroundColor = ConsoleColor.DarkBlue;
                    break;
                case 2:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.BackgroundColor = ConsoleColor.DarkRed;
                    break;
                case 3:
                    Console.ForegroundColor = ConsoleColor.Black;
                    Console.BackgroundColor = ConsoleColor.DarkYellow;
                    break;
                case 4:
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                case 5:
                    Console.ForegroundColor = ConsoleColor.Blue;
                    break;
                case 6:
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    break;
                case 7:
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    break;
            }
            if (inPlace)
                Console.Write(msg);
            else 
                Console.WriteLine(msg);
            Console.ForegroundColor = ConsoleColor.White;
            Console.BackgroundColor = ConsoleColor.Black;
        }

        public static void reports(IntPtr ptr, string name = "", int highlightLevel = 0, string tag = "")
        {
            int fail = 0;
            int success = 0;

            switch (highlightLevel)
            {
                case 1:
                    fail = 4;
                    success = 5;
                    break;
                case 2:
                    fail = 2;
                    success = 1;
                    break;
            }

            if (ptr == IntPtr.Zero)
                prints(name == "" ? "ptr wasn't found" : name + " wasn't found", tag, fail);
            else
                prints(name + " found at 0x" + ptr.ToString("X"), tag, success);
        }

        public static string Context = "";
        public static string ModuleName = "";

        public static void print(string msg, string tag = " ", int highlight = 0)
        {
            tag = tag == " " ? ModuleName : tag;
            prints(tag == "" ? msg : (Context == "" ? "" : $"[{Context}] ") + msg, tag, highlight);
        }

        public static void report(IntPtr ptr, string name = "", int highlightLevel = 1)
        {
            reports(ptr, Context == "" ? "" : (name == "" ? $"[{Context}]" : $"[{Context}] ") + name, highlightLevel, ModuleName);
        }

        private static void clearUpTo(int line)
        {
            int curline = Console.CursorTop;
            for (int i = line; i < curline; i++)
            {
                Console.SetCursorPosition(0, i);
                Console.Write(new string(' ', Console.WindowWidth));
            }
            Console.SetCursorPosition(0, line);
        }
        public static void Cap(ref uint target, uint min, uint max)
        {
            target = (target < min) ? min : ((target > max) ? max : target);
        }

        private static void Main(string[] args)
        {
            bool isGameRunning = false;
            while (true)
            {
                isGameRunning = GetProcess();
                if (!isGameRunning)
                {
                    init = true;
                    Console.Clear();
                    prints($"Trying to find process {_processes[i]}", "INIT");
                    Thread.Sleep(1000);
                }
                else if (init) Init();
            }
        }

        private static void Init()
        {
            Console.Clear();
            prints($"Found process {_processes[i]}", "INIT");

            client = game.ModulesWow64Safe().FirstOrDefault(x => x.ModuleName.ToLower() == "client.dll");
            server = game.ModulesWow64Safe().FirstOrDefault(x => x.ModuleName.ToLower() == "server.dll");
            engine = game.ModulesWow64Safe().FirstOrDefault(x => x.ModuleName.ToLower() == "engine.dll");
            vguim = game.ModulesWow64Safe().FirstOrDefault(x => x.ModuleName.ToLower() == "vguimatsurface.dll");

            if (client == null || server == null || engine == null || vguim == null)
            {
                prints("All modules haven't been found!", "INIT");
                Thread.Sleep(1000);
                return;
            }

            prints("--------", "");
            new VGUIMATSURFACE();
            new ENGINE();
            new CLIENT();
            new SERVER();
            init = false;
        }

        private static bool GetProcess()
        {
            try
            {
                game = Process.GetProcessesByName(_processes[i])[0];
                return true;
            }
            catch (IndexOutOfRangeException)
            {
                game = null;
                client = null;
                server = null;
                engine = null;
                i++;
                if (i >= _processes.Count()) 
                    i = 0;
                return false;
            }
        }


        public static string ConvertPtrToSigRaw(IntPtr ptr)
        {
            byte[] bytes = BitConverter.GetBytes((uint)ptr);
            return BitConverter.ToString(bytes).Replace("-", " ");
        }

        public static SigScanTarget ConvertPtrToSig(IntPtr ptr, int offset = 0, string prefix = "", string suffix = "")
        {
            if (ptr == IntPtr.Zero)
                return new SigScanTarget();
            byte[] bytes = BitConverter.GetBytes((uint)ptr);
            //prints(prefix + " " + BitConverter.ToString(bytes).Replace("-", " ") + " " + suffix);
            return new SigScanTarget(offset, prefix + " " + BitConverter.ToString(bytes).Replace("-", " ") + " " + suffix);
        }

        public static IntPtr FindStringAddress(string str, SignatureScanner scanner)
        {
            var target = new SigScanTarget(0, BitConverter.ToString(Encoding.Default.GetBytes(str)).Replace("-", ""));
            return scanner.Scan(target);
        }

        public static IntPtr FindCVarBase(string str, SignatureScanner scanner) 
        {
            IntPtr stringPtr = FindStringAddress(str, scanner);
            SigScanTarget target = ConvertPtrToSig(stringPtr, 6, "68", "B9 ?? ?? ?? ??");
            target.OnFound = (proc, scanner2, ptr) => proc.ReadPointer(ptr);
            return scanner.Scan(target);
        }

        public static IntPtr FindMOVReference(IntPtr ptr, SignatureScanner scanner){
            if (ptr == IntPtr.Zero) return ptr;

            byte[] bytes = BitConverter.GetBytes((uint)ptr);
            string sig1 = BitConverter.ToString(bytes).Replace("-", " ");

            SigScanTarget target = new SigScanTarget();
            target.AddSignature(1, "8B ?? " + sig1);
            target.AddSignature(1, "8A ?? " + sig1);
            target.AddSignature(1, "A1 " + sig1);
            target.AddSignature(1, "A2 " + sig1);
            target.AddSignature(1, "A3 " + sig1);
            target.AddSignature(1, "B8 ?? " + sig1);
            target.AddSignature(1, "B9 ?? " + sig1);

            return scanner.Scan(target);

        }

        public static IntPtr ReadCallRedirect(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return ptr;

            byte[] acceptable = new byte[] { 0xE8, 0xE9 };
            if (!acceptable.Contains(game.ReadValue<byte>(ptr)))
                return ptr;

            return (IntPtr)(game.ReadValue<int>(ptr + 0x1) + (uint)(ptr) + 0x5);
        }

        public static IntPtr FindRelativeCallReference(IntPtr ptr, uint bound, string prefix = "", string suffix = "", List<IntPtr> ignored = null, int startHere = 0x0)
        {
            int pos = Console.CursorTop;
            try
            {
                prints($"Finding relative call reference to 0x{ptr.ToString("X")}", "util", 6);
                prints("");
                if (ptr == IntPtr.Zero)
                    return ptr;

                IntPtr startPtr = (IntPtr)startHere;

                int offset = 1;
                if (prefix != "")
                {
                    int l = 0;
                    while (l <= prefix.Length - 1)
                    {
                        if (prefix[l] == ' ')
                            offset++;
                        l++;
                    }
                    offset++;
                }

                bool found = false;
                IntPtr ptr3 = IntPtr.Zero;
                uint bound2 = bound;
                SigScanTarget targ = new SigScanTarget(offset, prefix + " E8 ?? ?? ?? FF " + suffix);
                for (int j = 1; j <= 4; j++)
                {
                    uint end = (uint)(startPtr == IntPtr.Zero ? ptr : startPtr) + bound2;
                    uint start = (uint)(startPtr == IntPtr.Zero ? ptr : startPtr) - bound2;
                    Cap(ref start, (uint)CurModule.BaseAddress, (uint)(CurModule.BaseAddress + CurModule.ModuleMemorySize));
                    Cap(ref end, (uint)CurModule.BaseAddress, (uint)(CurModule.BaseAddress + CurModule.ModuleMemorySize));
                    bound = end - start;

                    if (bound <= 0)
                        break;

                    SignatureScanner scanner = new SignatureScanner(game, (IntPtr)(start), (int)(bound));
                    found = false;
                    do
                    {
                        targ.OnFound = (proc2, scanner2, ptr2) =>
                        {
                            uint target = (uint)(proc2.ReadValue<int>(ptr2) + (uint)ptr2 + 0x4);

                            //Console.SetCursorPosition(0, Console.CursorTop - 1);
                            //prints($"Call at 0x{ptr2.ToString("X")} to 0x{target:X}, left {scanner2.Size:X}              ", "util", 6);

                            if (target == (uint)ptr)
                            {
                                if (ignored != null)
                                {
                                    if (!ignored.Contains(ptr2))
                                        found = true;
                                }
                                else found = true;
                            }
                            scanner.Limit(ptr2);
                            return ptr2;
                        };
                        ptr3 = scanner.Scan(targ);
                    }
                    while (!found && ptr3 != IntPtr.Zero && scanner.Size > targ.Signatures[0].Pattern.Length);

                    if (ptr3 == IntPtr.Zero || !found)
                    {
                        switch (j)
                        {
                            case 1:
                                targ = new SigScanTarget(offset, prefix + " E8 ?? ?? ?? 00 " + suffix);
                                break;
                            case 2:
                                targ = new SigScanTarget(offset, prefix + " E9 ?? ?? ?? FF " + suffix);
                                break;
                            case 3:
                                targ = new SigScanTarget(offset, prefix + " E9 ?? ?? ?? 00 " + suffix);
                                break;
                        }
                    }
                    else break;
                }
                return (ptr3 != IntPtr.Zero) ? ptr3 - 0x1 : IntPtr.Zero;
            }
            finally
            {
                clearUpTo(pos);
            }
        }

        public static bool IsInVFTable(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return false;

            bool isInside(uint test)
            {
                return test >= (uint)CurModule.BaseAddress && test <= (uint)(CurModule.BaseAddress + CurModule.ModuleMemorySize);
            }

            /*
            if (isInside(game.ReadValue<uint>(ptr - 0x4)) || isInside(game.ReadValue<uint>(ptr + 0x4)))
            {
                return game.ReadBytes(game.ReadPointer(ptr - 0x4), 3).Any(x => isFuncStartByte(x)) || 
                    game.ReadBytes(game.ReadPointer(ptr + 0x4), 3).Any(x => isFuncStartByte(x));    
            }
            */

            // for now go lenient
            return (isInside(game.ReadValue<uint>(ptr - 0x4)) || isInside(game.ReadValue<uint>(ptr + 0x4)));
        }

        private static bool isFuncStartByte(byte a)
        {
            List<byte> start = new List<byte>(new byte[] { 0x6A, 0x68, 0xA1, 0xFF, 0x83, 0x81 });
            return (a >= 0x50 && a <= 0x5F) || start.Contains(a);
        }

        public static IntPtr BackTraceToFuncStart(IntPtr ptr, SignatureScanner scanner, bool checkCALL = false)
        {
            int pos = Console.CursorTop;
            try
            {
                prints($"Backtracing from 0x{ptr.ToString("X")}...", "util", 6);

                if (ptr == IntPtr.Zero)
                {
                    Console.SetCursorPosition(0, Console.CursorTop - 1);
                    return ptr;
                }

                List<byte> nop = new List<byte>(new byte[] { 0xCC, 0x90 });

                byte curbyte = 0x0;
                byte oldbyte = 0x0;

                prints("");
                for (int i = 0x0; i < 0x5000; i++)
                {
                    IntPtr found = IntPtr.Zero;
                    oldbyte = curbyte;
                    game.ReadValue<byte>(ptr - i, out curbyte);

                    Console.SetCursorPosition(0, Console.CursorTop - 1);
                    prints($"Try #{i}, current byte {curbyte:X02}", "util", 6);

                    if (nop.Contains(curbyte) && !nop.Contains(oldbyte))
                    {
                        found = scanner.Scan(ConvertPtrToSig(ptr - i + 1));
                        if (IsInVFTable(found))
                            return ptr - i + 1;
                        else if (game.ReadBytes(ptr - i - 4, 4).SequenceEqual(new byte[] { 0xCC, 0xCC, 0xCC, 0xCC }) ||
                            game.ReadBytes(ptr - i - 4, 4).SequenceEqual(new byte[] { 0x90, 0x90, 0x90, 0x90 }))
                            return ptr - i + 1;
                        else if (checkCALL && FindRelativeCallReference(ptr - i + 1, 0x10000) != IntPtr.Zero)
                            return ptr - i + 1;
                    }
                    else if (curbyte != oldbyte && isFuncStartByte(oldbyte))
                        if (IsInVFTable(scanner.Scan(ConvertPtrToSig(ptr - i + 1))) || 
                            (checkCALL && FindRelativeCallReference(ptr - i + 1, 0x10000) != IntPtr.Zero))
                            return ptr - i + 1;
                }

                return IntPtr.Zero;
            }
            finally
            {
                clearUpTo(pos);
            }

        }

        public static IntPtr TraceToFuncEnd(IntPtr ptr, bool early = false)
        {
            if (ptr == IntPtr.Zero)
                return ptr;

            List<byte> nop = new List<byte>(new byte[] { 0xCC, 0x90 });

            var scanner = new SignatureScanner(game, ptr, 0x5000);
            if (early)
            {
                var trg1 = new SigScanTarget();
                trg1.AddSignature(0, "C3");
                trg1.AddSignature(3, "C2 ?? 00");

                return scanner.Scan(trg1);
            }

            var trg2 = new SigScanTarget();
            trg2.AddSignature(-1, "CC CC CC CC");
            trg2.AddSignature(0, "C3 CC CC CC");
            trg2.AddSignature(-1, "90 90 90 90");
            trg2.AddSignature(0, "C3 90 90 90");
            trg2.AddSignature(0, "C2 90 90 90");

            return scanner.Scan(trg2);

        }

        public static IntPtr FindFuncThroughStringRef(string targString, SignatureScanner scanner, 
            string name = "", string subName = "", bool checkCall = false)
        {
            Context = name;
            subName = subName == "" ? "" : $"[{subName}] ";
            IntPtr ptr = FindStringAddress(targString, scanner);
            report(ptr, subName + "string");

            if (ptr == IntPtr.Zero)
                return IntPtr.Zero;

            SigScanTarget trg = ConvertPtrToSig(ptr, 0x0, "68");
            ptr = scanner.Scan(trg);
            report(ptr, subName + "string ref");

            ptr = BackTraceToFuncStart(ptr, scanner, checkCall);
            report(ptr, subName + "(estimated)", 2);
            if (subName == "")
                print("", "");
            return ptr;
        }

    }
}

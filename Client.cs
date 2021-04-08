
using LiveSplit.ComponentUtil;
using System;
using System.Diagnostics;
using System.Threading;

namespace sig
{
    class CLIENT : Run
    {

        private SignatureScanner scanner;
        private const string _moduleName = "client";
        public void print(string msg, string tag = _moduleName, int highlight = 0) =>
            prints(tag == "" ? msg : (_context == "" ? "" : $"[{_context}] ") + msg, tag, highlight);
        public void report(IntPtr ptr, string name = "", int highlightLevel = 1) =>
            reports(ptr, _context == "" ? "" : (name == "" ? $"[{_context}]" : $"[{_context}] ") + name, highlightLevel, _moduleName);
        private string _context = "";


        public CLIENT()
        {
            scanner = new SignatureScanner(game, client.BaseAddress, client.ModuleMemorySize);
            Start();
        }

        public void Start()
        {
            print("", "");
            print("Searching for client.dll functions / vars... \n", "client", 3);
            FIND_DoImageSpaceMotionBlur();
            FIND_HudUpdate();
            FIND_GetButtonBits();
            FIND_Shake();
            FIND_Fade();
            print("--------", "");
        }
        private IntPtr FindFuncThroughStringRef(string targString, string name = "", string subName = "", bool checkMOV = false)
        {
            _context = name;
            subName = subName == "" ? "" : $"[{subName}] ";
            IntPtr ptr = FindStringAddress(targString, scanner);
            report(ptr, subName + "string");

            if (ptr == IntPtr.Zero)
                return IntPtr.Zero;

            SigScanTarget trg = ConvertPtrToSig(ptr, 0x0, "68");
            ptr = scanner.Scan(trg);
            report(ptr, subName + "string ref");

            ptr = BackTraceToFuncStart(ptr, scanner, checkMOV);
            report(ptr, subName + "(estimated)", 2);
            if (subName == "")
                print("", "");
            return ptr;
        }

        void FIND_DoImageSpaceMotionBlur()
        {
            FindFuncThroughStringRef("dev/motion_blur", "DoImageSpaceMotionBlur");
        }

        void FIND_HudUpdate()
        {
            _context = "HudUpdate";
            print("Running method 1 -- finding \"(time_float)\" reference and retracing");
            IntPtr ptr = FindStringAddress("(time_float)", scanner);
            report(ptr, "string");
            if (ptr == IntPtr.Zero) goto method2;
            SigScanTarget trg = ConvertPtrToSig(ptr, 0x0, "68");

            ptr = scanner.Scan(trg);
            report(ptr, "string ref");

            ptr = BackTraceToFuncStart(ptr, scanner);
            report(ptr, "(estimated)", 2);

            goto eof;

        method2:
            print("Running method 2 -- finding LevelInitPreEntity to coerce vftable pointer");
            ptr = FindStringAddress("cl_predict 0", scanner);
            report(ptr, "LevelInitPreEntity string");

            trg = ConvertPtrToSig(ptr, 0x0, "68");
            ptr = scanner.Scan(trg);
            report(ptr, "LevelInitPreEntity string ref");

            ptr = BackTraceToFuncStart(ptr, scanner);
            report(ptr, "LevelInitPreEntity func start (estimated)");

            trg = ConvertPtrToSig(ptr, 0x0);
            ptr = scanner.Scan(trg);
            report(ptr, "LevelInitPreEntity func CHLClient vftable pointer");

            // assume the function is 6 entires away
            ptr = game.ReadPointer(ptr + 6 * 4);
            report(ptr, "", 2);
        eof:

            print("", "");
        }

        void FIND_GetButtonBits()
        {
            _context = "GetButtonBits";
            var target = new SigScanTarget(0, "81 ce 00 00 20 00");
            target.AddSignature(0, "0d 00 00 20 00");
            var ptr = scanner.Scan(target);
            report(ptr, "middle of func");

            ptr = BackTraceToFuncStart(ptr, scanner);
            report(ptr, "(estimated)", 2);
            print("", "");
        }

        void FIND_Shake()
        {
            _context = "Shake";
            SigScanTarget trg = new SigScanTarget(0, "53 68 61 6B 65");
            SignatureScanner tmpScanner = new SignatureScanner(game, client.BaseAddress, client.ModuleMemorySize);
            bool found = false;
            IntPtr ptr = server.BaseAddress;

            while (ptr != IntPtr.Zero && !found)
            {
                trg.OnFound = (f_proc, f_scanner, f_ptr) => {
                    var trg2 = ConvertPtrToSig(f_ptr, 0x0, "68");
                    if (scanner.Scan(trg2) != IntPtr.Zero)
                    {
                        if (f_proc.ReadString(f_ptr, 20) == "Shake")
                        {
                            found = true;
                        }
                    }
                    tmpScanner.Limit(f_ptr);
                    return f_ptr;
                };
                ptr = tmpScanner.Scan(trg);
            }

            report(ptr, "string");

            trg = ConvertPtrToSig(ptr, 1, "68 ?? ?? ?? ?? 68");
            ptr = game.ReadPointer(scanner.Scan(trg));
            report(ptr, "host func");
            IntPtr funcStart = ptr;

            ptr = TraceToFuncEnd(ptr, true);
            report(ptr, "host func end (estimate)");
            IntPtr funcEnd = ptr;

            byte oldByte = 0x0;
            byte curByte = 0x0;

            for (int i = 0; (int)funcEnd - i > (int)funcStart; i++)
            {
                oldByte = curByte;
                game.ReadValue<byte>(funcEnd - i, out curByte);

                if (curByte == 0xE8 && oldByte != 0xE8)
                {
                    ptr = (IntPtr)(game.ReadValue<int>(funcEnd - i + 1) + (uint)(funcEnd - i + 1) + 0x4);
                    break;
                }
            }
            report(ptr, "", 2);
            print("", "");
        }

        void FIND_Fade()
        {
            _context = "Fade";
            SigScanTarget trg = new SigScanTarget(0, "46 61 64 65");
            SignatureScanner tmpScanner = new SignatureScanner(game, client.BaseAddress, client.ModuleMemorySize);
            bool found = false;
            IntPtr ptr = server.BaseAddress;

            while (ptr != IntPtr.Zero && !found)
            {
                trg.OnFound = (f_proc, f_scanner, f_ptr) => {
                    var trg2 = ConvertPtrToSig(f_ptr, 0x0, "68");
                    if (scanner.Scan(trg2) != IntPtr.Zero)
                    {
                        if (f_proc.ReadString(f_ptr, 20) == "Fade")
                        {
                            found = true;
                        }
                    }
                    tmpScanner.Limit(f_ptr);
                    return f_ptr;
                };
                ptr = tmpScanner.Scan(trg);
            }

            report(ptr, "string");

            trg = ConvertPtrToSig(ptr, 1, "68 ?? ?? ?? ?? 68");
            ptr = game.ReadPointer(scanner.Scan(trg));
            report(ptr, "host func");
            IntPtr funcStart = ptr;

            ptr = TraceToFuncEnd(ptr, true);
            report(ptr, "host func end (estimate)");
            IntPtr funcEnd = ptr;

            byte oldByte = 0x0;
            byte curByte = 0x0;

            for (int i = 0; (int)funcEnd - i > (int)funcStart; i++)
            {
                oldByte = curByte;
                game.ReadValue<byte>(funcEnd - i, out curByte);

                if (curByte == 0xE8 && oldByte != 0xE8)
                {
                    ptr = (IntPtr)(game.ReadValue<int>(funcEnd - i + 1) + (uint)(funcEnd - i + 1) + 0x4);
                    break;
                }
            }
            report(ptr, "", 2);
            print("", "");
        }
    }
}


using LiveSplit.ComponentUtil;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace sig
{
    class SERVER : Run
    {
        private SignatureScanner scanner;

        public SERVER()
        {
            scanner = new SignatureScanner(game, server.BaseAddress, server.ModuleMemorySize);
            ModuleName = "server";
            CurModule = server;
            Context = "";
            Start();
        }

        public void Start()
        {
            var watch = new Stopwatch();
            watch.Start();

            print("", "");
            print("Searching for server.dll functions / vars... \n", "server", 3);
            Context = "";
            FIND_CheckVelocity();
            FIND_CheckJumpButton();
            FIND_FinishGravity();
            FIND_CheckStuck();
            FIND_ReadAll();
            FIND_CreateEntityByName();
            FIND_DispatchSpawn();

            Context = "";
            Console.WriteLine("");
            print($"Server scanning done after {watch.Elapsed}");
            Console.WriteLine("");
            print("--------", "");
        }

        private IntPtr PTR_CheckVelocity;

        private void FIND_CheckVelocity()
        {
            PTR_CheckVelocity = FindFuncThroughStringRef("PM  Got a NaN velocity", scanner, "CheckVelocity", "", true);
        }

        private List<IntPtr> _checkJumpButtonMatches = new List<IntPtr>();

        private void FIND_CheckJumpButton()
        {
            void addPtr(IntPtr inPtr)
            {
                if (inPtr != IntPtr.Zero && !_checkJumpButtonMatches.Contains(inPtr))
                    _checkJumpButtonMatches.Add(inPtr);
            }

            Context = "CheckJumpButton";

            #region method1
            print("Running method 1 -- finding \"xc_uncrouch_on_jump\" string ref and retracing");
            IntPtr ptr = FindCVarBase("xc_uncrouch_on_jump", scanner);
            report(ptr, "string");
            if (ptr == IntPtr.Zero)
                goto method2;
            var target = ConvertPtrToSig(ptr + GetIntOffset, 0, "", "");
            ptr = scanner.Scan(target);

            if (ptr == IntPtr.Zero)
                ptr = FindMOVReference(FindCVarBase("xc_uncrouch_on_jump", scanner), scanner);

            report(ptr, "string ref");

            ptr = BackTraceToFuncStart(ptr, scanner);
            report(ptr, "(estimated, HL2 / base)", 2);
            addPtr(ptr);
            #endregion

            #region method2
            method2:
            print("Running method 2 -- finding float ref and retracing");
            print("NOTE!! There could be multiple results if the game uses its own CheckJumpButton!!");
            var targ = new SigScanTarget();

            Func<IntPtr, SigScanTarget> getSig = (pointer) => {
                return ConvertPtrToSig(pointer, 0x0, "", "EB");
            };

            int tryNum = 0;

            method2back:
            switch (tryNum)
            {
                case 0:
                    {
                        targ = new SigScanTarget(0, "00 00 20 43");
                        goto check;
                    }
                case 1:
                    {
                        targ = new SigScanTarget(0, "01 2a 86 43");
                        goto check;
                    }
                case 2:
                    {
                        targ = new SigScanTarget(0, "00 00 34 42");
                        getSig = (pointer) => {
                            return ConvertPtrToSig(pointer, 0x0, "8B ?? ?? F3 0F ?? ??", "8B");
                        };
                        goto check;
                    }
                default:
                    goto finalstep;
            }

            check:
            tryNum++;
            var tmpScanner = new SignatureScanner(game, server.BaseAddress, server.ModuleMemorySize);
            bool found = false;
            ptr = server.BaseAddress;
            while (!found && ptr != IntPtr.Zero)
            {
                targ.OnFound = (f_proc, f_scanner, f_ptr) => {
                    var f_targ = getSig(f_ptr);
                    var f_ptr2 = scanner.Scan(f_targ);
                    if (f_ptr2 != IntPtr.Zero)
                    {
                        report(f_ptr, "Float " + BitConverter.ToSingle(targ.Signatures[0].Pattern, 0).ToString("0.0f"));
                        report(f_ptr2, "Float reference");
                        found = true;
                        return f_ptr2;
                    }
                    f_scanner.Limit(f_ptr);
                    return f_ptr;
                };
                ptr = tmpScanner.Scan(targ);
            }

            ptr = BackTraceToFuncStart(ptr, scanner);
            report(ptr, $"estimate #{tryNum} ", 2);
            addPtr(ptr);
            goto method2back;
            #endregion

            finalstep:
            target = new SigScanTarget();

            List<IntPtr> additionalCJBMatches = new List<IntPtr>();

            foreach (IntPtr _ptr in _checkJumpButtonMatches)
            {
                target = ConvertPtrToSig(_ptr, 0, "", "");
                IntPtr tmpPtr = game.ReadPointer(scanner.Scan(target) + 0xC);
                report(tmpPtr, $"[TryPlayerMove] #{_checkJumpButtonMatches.IndexOf(_ptr) + 1}", 2);
                target = ConvertPtrToSig(tmpPtr, 0, "", "");
                tmpScanner = new SignatureScanner(game, server.BaseAddress, server.ModuleMemorySize);

                do
                {
                    target.OnFound = (d_proc, d_scanner, d_ptr) => {
                        IntPtr f_ptr = d_proc.ReadPointer(d_ptr - 0xC);
                        if (f_ptr != _ptr)
                        {
                            report(f_ptr, "game-specific", 2);
                            additionalCJBMatches.Add(f_ptr);
                            return f_ptr;
                        }
                        tmpScanner.Limit(d_ptr);
                        return f_ptr;
                    };
                    tmpPtr = tmpScanner.Scan(target);
                }
                while (tmpPtr != IntPtr.Zero && tmpPtr == _ptr);
            }

            _checkJumpButtonMatches.AddRange(additionalCJBMatches);

            print("", "");
        }

        private void FIND_FinishGravity()
        {
            Context = "FinishGravity";

            print("Running method 1 -- looking 1 above CheckJumpButton in CGameMovement vftable");
            IntPtr ptr;
            SigScanTarget trg = new SigScanTarget();
            bool skip = false;
            foreach (IntPtr _ptr in _checkJumpButtonMatches)
            {
                trg = ConvertPtrToSig(_ptr);
                trg.OnFound = (f_proc, f_scanner, f_ptr) => {
                    f_ptr -= 0x8;
                    IntPtr funcPtr = f_proc.ReadPointer(f_ptr);
                    if (f_proc.ReadValue<byte>(funcPtr + 0x5) == 0xCC ||
                    f_proc.ReadValue<byte>(funcPtr + 0x5) == 0x90)
                        return IntPtr.Zero;
                    return funcPtr;
                };

                ptr = scanner.Scan(trg);
                if (ptr != IntPtr.Zero && !skip)
                    skip = true;
                report(ptr, $"candidate #{_checkJumpButtonMatches.IndexOf(_ptr) + 1}", 2);
            }

            if (skip)
                goto eof;

            print("Running method 2 -- looking for references to CheckVelocity and comparing results to calls found in CheckJumpButton");
            List<IntPtr> checkVelRefs = new List<IntPtr>();
            List<IntPtr> checkVelRefSources = new List<IntPtr>();
            IntPtr candidate;
            do
            {
                candidate = FindRelativeCallReference(PTR_CheckVelocity, 0x2000, "", "", checkVelRefSources);
                if (candidate != IntPtr.Zero)
                {
                    checkVelRefSources.Add(candidate + 1);
                    IntPtr candidate2 = BackTraceToFuncStart(candidate, scanner, true);
                    checkVelRefs.Add(candidate2);
                    report(candidate2, $"candidate from call at 0x{candidate.ToString("X")}");
                }
            }
            while (candidate != IntPtr.Zero);

            List<IntPtr> CJBcalls = new List<IntPtr>();
            foreach (IntPtr _ptr in _checkJumpButtonMatches)
            {
                int i = _checkJumpButtonMatches.IndexOf(_ptr) + 1;
                IntPtr funcEnd = TraceToFuncEnd(_ptr);
                report(funcEnd, $"[CheckJumpButton] estimate {i} function end");
                var tmpScanner = new SignatureScanner(game, _ptr, (int)(funcEnd - (int)_ptr));
                trg = new SigScanTarget(1, "E8 ?? ?? ?? 00");
                IntPtr ptr3 = IntPtr.Zero;
                bool found = false;
                for (int j = 0; j < 4; j++)
                {
                    do
                    {
                        trg.OnFound = (proc2, scanner2, ptr2) =>
                        {
                            IntPtr call = (IntPtr)(proc2.ReadValue<int>(ptr2) + (uint)ptr2 + 0x4);
                            if (!CJBcalls.Contains(call))
                                CJBcalls.Add(call);
                            report(ptr2 - 1, $"[CheckJumpButton] estimate {i} call to 0x{call.ToString("X")}");
                            if (checkVelRefs.Contains(call))
                            {
                                report(call, "", 2);
                                found = true;
                            }

                            tmpScanner.Limit(ptr2);
                            return ptr2;
                        };
                        ptr3 = tmpScanner.Scan(trg);

                        if (found)
                            goto eof;
                    }
                    while (ptr3 != IntPtr.Zero);

                    tmpScanner = new SignatureScanner(game, _ptr, (int)(funcEnd - (int)_ptr));
                    switch (j)
                    {
                        case 1:
                            {
                                trg = new SigScanTarget(1, "E8 ?? ?? ?? FF");
                                break;
                            }
                        case 2:
                            {
                                trg = new SigScanTarget(1, "E9 ?? ?? ?? 00");
                                break;
                            }
                        case 3:
                            {
                                trg = new SigScanTarget(1, "E9 ?? ?? ?? FF");
                                break;
                            }
                    }
                }
                foreach ( IntPtr member in checkVelRefs )
                {
                    if (CJBcalls.Contains(member))
                    {
                        report(member, "", 2);
                        goto eof;
                    }
                }
            }
            eof:
            print("", "");
        }

        private void FIND_CheckStuck()
        {
            FindFuncThroughStringRef("%s stuck on object %i/%s", scanner, "CheckStuck");
        }

        private void FIND_ReadAll()
        {
            IntPtr ptr = FindFuncThroughStringRef("Expected %s found %s ( raw '%s' )", scanner, "ReadAll", "ReadFields");
            var trg = ConvertPtrToSig(ptr, -0x4);
            ptr = game.ReadPointer(scanner.Scan(trg));
            report(ptr, "", 2);

            if (ptr == IntPtr.Zero)
                return;

            Context = "DoReadAll";
            var tmpScanner = new SignatureScanner(game, ptr, 0x200);
            trg = new SigScanTarget(1, "e8 ?? ?? ?? ??");
            trg.OnFound = (f_proc, f_scanner, f_ptr) => {
                return (IntPtr)((int)f_proc.ReadValue<int>(f_ptr) + 0x4 + (int)f_ptr);
            };
            ptr = tmpScanner.Scan(trg);
            report(ptr, "", 2);
            print("", "");
        }

        private void FIND_CreateEntityByName()
        {
            FindFuncThroughStringRef("CreateEntityByName( %s, %d )", scanner, "CreateEntityByName");
        }

        private void FIND_DispatchSpawn()
        {
            Context = "DispatchSpawn";
            print("Running method 1 -- finding \"Entity %s not found, and couldn\'t create!\" string ref and retracing");
            IntPtr ptr = FindStringAddress("Entity %s not found, and couldn\'t create!\n", scanner);
            report(ptr, "string");

            if (ptr == IntPtr.Zero)
                goto method2;

            SigScanTarget trg = ConvertPtrToSig(ptr, 0x0, "68");
            ptr = scanner.Scan(trg);
            report(ptr, "string ref");

            var tmpScanner = new SignatureScanner(game, ptr, 0x40);
            trg = new SigScanTarget(3, "B? 01 E8 ?? ?? ?? ??");

            method2jmp:
            trg.OnFound = (f_proc, f_scanner, f_ptr) => {
                return (IntPtr)((int)f_proc.ReadValue<int>(f_ptr) + 0x4 + (int)f_ptr);
            };

            ptr = tmpScanner.Scan(trg);
            report(ptr, "", 2);
            goto eof;

            method2:
            print("Running method 2 -- finding \"ai_ally_speech_manager\" string ref and retracing");
            ptr = FindStringAddress("ai_ally_speech_manager", scanner);
            report(ptr, "string");

            if (ptr == IntPtr.Zero)
                goto eof;

            trg = new SigScanTarget();
            trg.AddSignature(ConvertPtrToSig(ptr, 0x0, "6A FF 68"));
            trg.AddSignature(ConvertPtrToSig(ptr, 0x0, "68", "6A FF"));
            ptr = scanner.Scan(trg);
            report(ptr, "string ref");

            trg = new SigScanTarget(4, "74 0E 50 E8");
            tmpScanner = new SignatureScanner(game, ptr, 0x40);
            goto method2jmp;

            eof:
            print("", "");
        }
    }
}

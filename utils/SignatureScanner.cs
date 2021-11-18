using LiveSplit.ComponentUtil;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SE_Finder_Rewrite.Utils.StringExtensions;

namespace SE_Finder_Rewrite.Utils
{
    class Signature
    {
        public byte[] Bytes;
        public ByteCompareType[] Masks;
        public int Offset;
        public Func<IntPtr, bool> EvaluateMatch
        {
            get
            {
                if (_evaluateMatch == null)
                    return new Func<IntPtr, bool>((a) => { return true; });
                return _evaluateMatch;
            }
            set
            {
                if (value == null)
                    _evaluateMatch = new Func<IntPtr, bool>((a) => { return true; });
                else _evaluateMatch = value;
            }
        }

        private Func<IntPtr, bool> _evaluateMatch = null;

        public string Name;
        public int Length => Bytes?.Count() ?? 0;

        public Signature(string mask, int offset = 0, Func<IntPtr, bool> match = null, string name = "")
        {
            mask = mask.Replace(" ", "");

            if (mask.Length < 2)
                throw new Exception("Signature length can't be less than 2!");

            Name = name;
            Offset = offset;
            EvaluateMatch = match;

            string[] bytes = mask.SplitInParts(2).ToArray();
            Bytes = new byte[bytes.Count()];
            Masks = new ByteCompareType[bytes.Count()];

            for (int i = 0; i < bytes.Count(); i++)
            {
                string part = bytes[i].Trim();
                byte.TryParse(part.Trim('?'), System.Globalization.NumberStyles.HexNumber , null, out Bytes[i]);

                int j = part.IndexOf('?');
                if (j != -1)
                {
                    if (part.All(x => x == '?'))
                    {
                        Bytes[i] = 0;
                        Masks[i] = ByteCompareType.Any;
                        continue;
                    }

                    switch (j)
                    {
                        case 0:
                            Masks[i] = ByteCompareType.UpperNibble;
                            continue;
                        case 1:
                            Masks[i] = ByteCompareType.LowerNibble;
                            continue;
                    }
                }
            }

        }

        public string PrintByte(int i)
        {
            if (Bytes.Count() <= i)
                throw new Exception("Index beyond array bounds!");

            switch (Masks[i])
            {
                case ByteCompareType.Full:
                    return Bytes[i].ToString("x2");
                case ByteCompareType.Any:
                    return "??";
                case ByteCompareType.UpperNibble:
                    return "?" + Bytes[i].ToString("x2").Trim('0');
                case ByteCompareType.LowerNibble:
                    return Bytes[i].ToString("x2").Trim('0') + "?";
            }

            return "";
        }

        public override string ToString()
        {
            string output =  $"Sig [{Name}] Bytes [";
            for (int i = 0; i < Bytes.Count(); i++)
                output += $"{PrintByte(i)} ";
            output = output.TrimEnd(' ');
            output += "]";

            return output;
        }
    }


    class SigCollection
    {
        public List<Signature> Signatures = new List<Signature>();
        public Func<IntPtr, bool> EvaluateMatch
        {
            get
            {
                if (_evaluateMatch == null)
                    return new Func<IntPtr, bool>((a) => { return true; });
                return _evaluateMatch;
            }
            set
            {
                if (value == null)
                    _evaluateMatch = new Func<IntPtr, bool>((a) => { return true; });
                else _evaluateMatch = value;
            }
        }

        private Func<IntPtr, bool> _evaluateMatch = null;
        public string Name = "";

        public SigCollection(params Signature[] sigs)
        {
            foreach (Signature sig in sigs)
                Signatures.Add(sig);
        }

        public SigCollection()
        {

        }

        public SigCollection(string name, Func<IntPtr, bool> match, params Signature[] sigs)
        {
            Name = name;
            EvaluateMatch = match;

            foreach (Signature sig in sigs)
                Signatures.Add(sig);
        }

        public SigCollection(params string[] sigs)
        {
            foreach (string sig in sigs)
                Signatures.Add(new Signature(sig));
        }

        public void Add(params Signature[] sigs)
        {
            foreach (Signature sig in sigs)
                Signatures.Add(sig);
        }

        public void Add(params string[] sigs)
        {
            foreach (string sig in sigs)
                Signatures.Add(new Signature(sig));
        }

        public override string ToString()
        {
            StringBuilder output = new StringBuilder();
            output.AppendLine($"Sig Collection [{Name}] Count [{Signatures.Count}]");

            Signatures.ForEach(x => output.AppendLine(x.ToString()));

            return output.ToString();
        }
    }

    class SigScanner
    {
        private Process _process;
        private byte[] _memory;
        private IntPtr _start;
        private int _size;
        public IntPtr End => _start + _size;
        public Func<IntPtr, bool> EvaluateMatch
        {
            get
            {
                if (_evaluateMatch == null)
                    return new Func<IntPtr, bool>((a) => { return true; });
                return _evaluateMatch;
            }
            set
            {
                if (value == null)
                    _evaluateMatch = new Func<IntPtr, bool>((a) => { return true; });
                else _evaluateMatch = value;
            }
        }

        private Func<IntPtr, bool> _evaluateMatch = null;

        public IntPtr Start
        {
            get { return _start; }
            set
            {
                _memory = null;
                _start = value;
            }
        }

        public int Size
        {
            get { return _size; }
            set
            {
                _memory = null;
                _size = value;
            }
        }

        public Process Process
        {
            get { return _process; }
            set
            {
                _memory = null;
                _process = value;
            }
        }

        public byte[] Memory
        {
            get { return _memory; }
            set
            {
                _memory = value;
                _size = value.Length;
            }
        }

        public SigScanner(Process proc, IntPtr start, int size)
        {
            Process = proc;
            Start = start;
            Size = size;

            _memory = new byte[1];
        }

        public SigScanner(Process proc, IntPtr start, IntPtr end)
        {
            if (!start.IsSmaller(end))
                throw new Exception("Start pointer can't be bigger than end pointer!");
            
            Process = proc;
            Start = start;
            Size = end.SubtractI(start);

            _memory = new byte[1];
        }

        public SigScanner(byte[] mem)
        {
            Size = mem.Length;
            _start = (IntPtr.Zero);
            _memory = mem;
        }

        private void UpdateMemory()
        {
            if (_memory == null || _memory.Length != _size)
                Memory = _process.ReadBytes(_start, _size);
        }

        public unsafe IntPtr Scan(Signature sig)
        {
            int size = _size;
            int lengthMask = sig.Length;

            if (size < lengthMask)
                return IntPtr.Zero;

            UpdateMemory();

            fixed (byte* mem = _memory)
            fixed (byte* bytes = sig.Bytes)
            fixed (ByteCompareType* masks = sig.Masks)
            {
                for (int i = 0, j = 0; i <= _size - lengthMask; i++)
                {
                    for (j = 0; j < lengthMask; j++)
                    {
                        if (!bytes[j].CompareByte(mem[i + j], masks[j]))
                            goto next;
                    }

                    IntPtr ptr = (_start + i + sig.Offset);
                    if (sig.EvaluateMatch(ptr) && EvaluateMatch(ptr))
                        return ptr;

                    next:
                    ;
                }
            }

            return IntPtr.Zero;
        }

        public unsafe List<IntPtr> ScanAll(Signature sig)
        {
            List<IntPtr> output = new List<IntPtr>();

            int size = _size;
            int lengthMask = sig.Length;

            if (size < lengthMask)
                return output;

            UpdateMemory();

            fixed (byte* mem = _memory)
            fixed (byte* bytes = sig.Bytes)
            fixed (ByteCompareType* masks = sig.Masks)
            {
                for (int i = 0; i <= _size - lengthMask; i++)
                {
                    for (int j = 0; j < lengthMask; j++)
                    {
                        if (!bytes[j].CompareByte(mem[i + j], masks[j]))
                            goto next;
                    }

                    IntPtr ptr = (_start + i + sig.Offset);
                    if (sig.EvaluateMatch(ptr) && EvaluateMatch(ptr))
                    {
                        output.Add(ptr);
                        continue;
                    }

                    next:
                    ;
                }
            }

            return output;
        }

        public IntPtr Scan(SigCollection collection)
        {
            foreach (Signature sig in collection.Signatures)
            {
                IntPtr output = Scan(sig);
                if (output == IntPtr.Zero)
                    continue;

                if (collection.EvaluateMatch(output))
                    return output;
            }

            return IntPtr.Zero;
        }

        public List<IntPtr> ScanAll(SigCollection collection)
        {
            List<IntPtr> output = new List<IntPtr>();

            foreach (Signature sig in collection.Signatures)
            {
                var list = ScanAll(sig);

                if (list.Count() == 0)
                    continue;

                foreach (IntPtr match in list)
                    if (collection.EvaluateMatch(match))
                        output.Add(match);
            }
            return output;
        }

        public IntPtr ScanMinimum(SigCollection collection)
        {
            var results = ScanAll(collection);

            if (results.Count() == 0)
                return IntPtr.Zero;

            return (IntPtr)results.ConvertAll<long>(x => x.ToInt64()).Min();
        }

        public bool IsWithin(IntPtr ptr)
        {
            long delta = (long)ptr - (long)_start;
            return delta > 0 && delta < _size;
        }

        public void Limit(IntPtr newStart)
        {
            if (!newStart.IsSmaller(End))
                throw new Exception("Start pointer can't be further than end pointer!");

            IntPtr end = End;
            Start = newStart;
            _size = end.SubtractI(Start);
        }

        public override string ToString()
        {
            return $"Sig Scanner Start [{Start}] End [{End}] Size [{Size}]";
        }
    }
}

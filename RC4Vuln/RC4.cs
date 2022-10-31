using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RC4Vuln
{
    // RC4 implementation and "simulator"
    // Acts like a normal implementation of RC4, but also supports stepping through the initialization of S
    // one permutation (for each value of i) at a time, so long as that information would be knowable
    // under the assumptions of the Fluhrer et al attack.
    public class RC4
    {
        // Key (IV, SK)
        private byte[] K;

        // State variables
        public byte[] S;
        public byte i;
        public byte j;

        // Initialization step, equal to i during initialization
        private int k;

        // Number of known key bytes, if zero, this implementation acts as a black box.
        // In the case of WEP, nk starts at 3 and increases until it equals the full 8 or 16 byte key length.
        private int nk;

        // Initialize RC4 using the regular KSA and n = 8 / N = 256
        // nk is the number of known secret bytes.
        public RC4(byte[] K, int nk)
        {
            this.K = K;
            this.nk = nk;

            S = new byte[256];
            i = 0;
            j = 0;

            k = 0;

            // Initial permutation (0, 1, 2, ... N - 1)
            for (int x = 0; x < S.Length; x++)
                S[x] = (byte)x;
        }

        // Initialize a black box RC4 implementation
        // SimulateInitStep cannot be called when RC4 is constructed as a black box.
        public RC4(byte[] K) : this(K, 0) { }

        // Finish initializing S, once this is called, PRGA can be called to generate the output keystream.
        public void FinishInit()
        {
            while (!InitStep());
        }

        // Take one step (incrementing i by 1) in initializing the permutation S.
        // Disallows stepping if doing so would require a byte from K that the user does not have, as set by nk.
        public void SimulateInitStep()
        {
            if (!(k < nk))
                throw new InvalidOperationException("Not allowed to observe this state!");

            InitStep();
        }

        // One initialization scrambling step, returns true when initialization is finished.
        private bool InitStep()
        {
            // i, j = 0

            if (k != S.Length)
            {
                j = (byte)(j + S[i] + K[i % K.Length]);
                Swap(i, j);

                k++;
                i = (byte)k;

                return false;
            }

            i = 0;
            j = 0;
            return true;
        }

        // Swap values at indexes i and j in S.
        private void Swap(byte i, byte j)
        {
            byte temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        // Generate one byte of PRGA keystream output.
        public byte PRGA()
        {
            if (k != S.Length)
                throw new Exception("RC4 is not fully initialized, Not valid to output PRGA word.");

            i = (byte)(i + 1);
            j = (byte)(j + S[i]);
            Swap(i, j);

            return S[(S[i] + S[j]) % S.Length];
        }
    }
}

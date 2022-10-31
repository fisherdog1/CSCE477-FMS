using Decipher;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace RC4Vuln
{
    internal class Program
    {
        static void TestEncipher(byte[] WEPK)
        {
            byte[] testmsg = new byte[] { 0x54, 0x68, 0x65, 0xC0, 0x71, 0x75, 0x69, 0xF3 };

            Console.WriteLine($"WEPK: {Convert.ToHexString(WEPK)}");
            Console.WriteLine($"Test Plaintext: {Convert.ToHexString(testmsg)}");

            RC4 rc4 = new RC4(WEPK);
            rc4.FinishInit();

            // Encipher
            Console.Write("Test Ciphertext: ");

            foreach (byte p in testmsg)
            {
                byte key = rc4.PRGA();
                byte ciphertext = (byte)(p ^ key);
                

                Console.Write("{0:X2}", ciphertext);
            }

            Console.WriteLine();
        }

        static void BExact(byte[] K, int b)
        {
            // Check if K is b-exact
            bool bexact = true;

            for (int t = 0; t < 256; t++)
            {
                byte kl = (byte)(K[t % K.Length] % b);
                byte kr = (byte)((1 - t + (b * 256)) % b);

                if (kl != kr)
                    bexact = false;
            }

            // Print key
            if (bexact)
                Console.WriteLine($"Key {Convert.ToHexString(K)} is {b}-exact");
            else
                Console.WriteLine($"Key {Convert.ToHexString(K)} is not {b}-exact");
        }

        static void Main(string[] args)
        {
            // 64 bit WEP consists of a 3 byte IV and 5 byte Secret
            int nSK = 5;

            // Create a random 5 byte secret
            byte[] K = new byte[nSK];
            new Random().NextBytes(K);

            TestEncipher(K);

            // Number of known SK bytes
            byte A = 0;

            byte[] knownSecretKeys = new byte[nSK];

            while (A < nSK)
            {
                // First word statistics
                Statistics.DictionaryCounter<byte> fwstats = new Statistics.DictionaryCounter<byte>();

                for (int X = 0; X < 250; X++)
                {
                    // Create a weak WEPK key by using the special form IV
                    byte[] IV = new byte[3];
                    IV[0] = (byte)(A + 3);
                    IV[1] = 0xFF; // N - 1
                    IV[2] = (byte)X;

                    // Concatenate to create target WEP key
                    byte[] WEPK = new byte[8];
                    Buffer.BlockCopy(IV, 0, WEPK, 0, 3);
                    Buffer.BlockCopy(K, 0, WEPK, 3, 5);

                    // Create RC4 to use as a simulator, not fully initialized yet
                    // We know the 3 IV bytes plus A secret key bytes
                    var rc4 = new RC4(WEPK, 3 + A);

                    // S0, key looks like:
                    // [A+3][N-1][ X ][SK0][...][SK4]
                    // S permutation looks like:
                    // [ 0 ][ 1 ][ 2 ][ 3 ][...][255]

                    rc4.SimulateInitStep();
                    // First step, j is advanced to A+3 (3 when A = 0), then swaps with i (which is 0)
                    // [ 3 ][ 1 ][ 2 ][ 0 ][...][255]

                    rc4.SimulateInitStep();
                    // Second step, i advances, j must advance by 0 (S[1] + K[1] = 1 + 255 mod 256 = 0), another swap occurs
                    // [ 3 ][ 0 ][ 2 ][ 1 ][...][255]

                    // If at this point S[0] or S[1] has changed again we cannot use this IV (continue)
                    // I think this is only the case for high X?

                    rc4.SimulateInitStep();
                    // Third step (last step we can exactly simulate), j advances by X + 2 (S[2] + K[2])
                    // We now know exactly j_A+2 = A + X + 5 (j = 5 first)
                    // S_A+2 also exactly known
                    // [ 3 ][ 0 ][ 5 ][ 1 ][ 4 ][ 2 ][255]

                    // Exactly and always known j from above 3 procedure steps
                    byte j_2 = (byte)(A + X + 5);

                    // Save known S_2 and j_2 (this isn't cheating since we can exactly simulate up to here)
                    byte[] S_2 = new byte[A + 6];
                    Buffer.BlockCopy(rc4.S, 0, S_2, 0, A + 6);

                    // Repeat steps until i = A + 2 to successively find next secret key byte
                    while (rc4.i < A + 3)
                    {
                        j_2 += (byte)(rc4.S[rc4.i] + knownSecretKeys[(rc4.i - 3) % knownSecretKeys.Length]);
                        rc4.SimulateInitStep();
                    }

                    // Not allowed to know the state of RC4 after this point!
                    // This commented line would cause an exception:
                    
                    // rc4.SimulateInitStep();

                    // Finish initializing RC4
                    rc4.FinishInit();

                    // With about 5% chance, the output will be related to K[0] as follows
                    // K[0] = (S_2)^-1[first] - j_2 - S_2[3]
                    // We must use the values we predicted for these S

                    // Invert S_2 for the later key prediction formula
                    byte[] S_2_inv = new byte[S_2.Length];

                    for (int i = 0; i < S_2.Length; i++)
                        for (int j = 0; j < S_2.Length; j++)
                            if (S_2[j] == i)
                            {
                                S_2_inv[i] = (byte)j;
                                break;
                            }


                    // First keystream output word
                    byte first = rc4.PRGA();

                    // Find first word's index in S_2
                    byte S_2_inv_first = first;
                    if (first < A + 6)
                        // One of the S_2 whose inverse (index) is known exactly, otherwise, it is part of the remaining identity permutation
                        S_2_inv_first = S_2_inv[first];

                    // Calculate the most likely key
                    byte likelyKey = (byte)((S_2_inv_first - j_2 - S_2[3 + A] + 512) % 256);

                    // Record likely key for statistical analysis, expected to take 60 samples to reach a correct key guess
                    fwstats.CountItems(likelyKey);
                }

                // Store and print known secret key for later iterations
                knownSecretKeys[A] = fwstats.SortedList().First().Key;
                Console.WriteLine($"Likely value of SK[{A}]: {knownSecretKeys[A]:X2}");

                // Next unknown key index
                A++;
            }
        }
    }
}
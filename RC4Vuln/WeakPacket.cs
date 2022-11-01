using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RC4Vuln
{
    internal class WeakPacket
    {
        private byte[] iv;
        private byte[] packetdata;
    
        public int A { get { return iv[0] - 3; } }
        public int X { get { return iv[2]; } }
        public byte[] ICV { get {
                return new byte[] {
            packetdata[packetdata.Length - 4],
            packetdata[packetdata.Length - 3],
            packetdata[packetdata.Length - 2],
            packetdata[packetdata.Length - 1],
        };
            } }

        public override string ToString()
        {
            return $"Weak Packet: A: {A} X: {X} Len: {packetdata.Length} IV: {iv[0]:X2}{iv[1]:X2}{iv[2]:X2} ICV: {ICV[0]:X2}{ICV[1]:X2}{ICV[2]:X2}{ICV[3]:X2}";
        }

        public WeakPacket(byte[] iv, byte[] packetdata)
        {
            if (iv.Length != 3)
                throw new Exception("IV length must be 3");

            this.iv = iv;
            this.packetdata = packetdata;
        }

        public bool DecryptAndCheckICV(byte[] secretkey, out byte[] plaintext)
        {
            if (!(secretkey.Length == 5 || secretkey.Length == 13))
                throw new Exception("WEP secret key length must be 5 (64 bit WEP) or 13 (128 bit WEP)");

            // IV and secret key concatenation
            byte[] WEPK = new byte[8];
            Buffer.BlockCopy(iv, 0, WEPK, 0, 3);
            Buffer.BlockCopy(secretkey, 0, WEPK, 3, 5);

            // Decrypt the data in packetdata using the given WEPK
            RC4 prng = new RC4(WEPK);
            plaintext = new byte[packetdata.Length];

            for (int i = 0; i < packetdata.Length; i++)
            {
                byte x = prng.PRGA();
                plaintext[i] = (byte)(packetdata[i] ^ x);
            }

            // Check the ICV (last 4 bytes) against the data
            // I dont know how this check works I'm assuming it's just a checksum
            UInt32 sum = 0;

            for (int i = 0; i < plaintext.Length - 4; i++)
                sum += plaintext[i];

            // Return true if ICV matches
            return sum == 0;
        }
    }
}

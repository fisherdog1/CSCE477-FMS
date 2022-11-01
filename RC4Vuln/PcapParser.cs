using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RC4Vuln
{
    // Thing that opens libpcap .cap files (Not pcapng)
    internal class PcapParser
    {

        public PcapParser(Stream instream)
        {
            BinaryReader r = new BinaryReader(instream);

            UInt32 magic = r.ReadUInt32();

            // Either a1b2c3d4 or the same thing reversed, used to determine byte order.
            // If reversed, need to flip byte order of all reads?
            bool isForwardByteOrder;

            if (magic == 0xA1B2C3D4)
                isForwardByteOrder = true;
            else if (magic == 0xD4C3B2A1)
                isForwardByteOrder = false;
            else
                throw new Exception("Pcap file not valid, does not begin with pcap magic number!");

            // Global Header
            UInt16 vmajor = r.ReadUInt16();
            UInt16 vminor = r.ReadUInt16();
            Int32 thiszone = r.ReadInt32();
            UInt32 sigfigs = r.ReadUInt32();
            UInt32 snaplen = r.ReadUInt32();
            UInt32 network = r.ReadUInt32();

            Console.WriteLine($"Loading pcap file with following Global Header:\nVer: {vmajor}.{vminor}\nSnaplen: {snaplen}\nNetwork Type: {network:X}");

            // Read packets
            while (r.BaseStream.Position < r.BaseStream.Length)
            {
                UInt32 ts_sec = r.ReadUInt32();
                UInt32 ts_usec = r.ReadUInt32();
                UInt32 incl_len = r.ReadUInt32();
                UInt32 orig_len = r.ReadUInt32();

                long startOfPacket = r.BaseStream.Position;

                UInt16 fc = r.ReadUInt16();

                int ftype = (fc >> 2) & 0x3;
                int subtype = (fc >> 4) & 0xF;

                // IV is at bytes 24,25,26 from start of packet
                r.BaseStream.Seek(startOfPacket + 24, SeekOrigin.Begin);
                byte[] iv = r.ReadBytes(3);

                // WEP ICV is the last 4 bytes
                r.BaseStream.Seek(startOfPacket + incl_len - 4, SeekOrigin.Begin);
                byte[] icv = r.ReadBytes(4);

                // Consume rest of packet bytes
                r.BaseStream.Seek(startOfPacket + incl_len, SeekOrigin.Begin);

                // Data packet
                // https://en.wikipedia.org/wiki/802.11_Frame_Types
                if (ftype == 2 && subtype == 0)
                {
                    Console.WriteLine($"Data pkt len: {incl_len} IV: {iv[0]:X2}{iv[1]:X2}{iv[2]:X2} ICV: {icv[0]:X2}{icv[1]:X2}{icv[2]:X2}{icv[3]:X2}");

                    // Check for weak IVs ()
                    int iva = iv[0] - 3;

                    if (iv[1] == 0xFF && iva >= 0 && iva <= 13)
                        Console.WriteLine($" (Weak A = {iva} X = {iv[2]})!");
                }
            }
        }
    }
}

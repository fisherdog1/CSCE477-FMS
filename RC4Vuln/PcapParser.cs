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

                // Consume packet bytes
                for (long i = 0; i < incl_len; i++)
                {
                    _ = r.ReadByte(); // Do nothing with bytes for now
                }

                Console.WriteLine($"Pkt len: {incl_len}");
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RC4Vuln
{
    // Thing that opens libpcap .cap files (Not pcapng)
    internal class PcapParser
    {
        List<WeakPacket> packets;
        byte[] targetBssid;

        public static bool MacMatch(byte[] a, byte[] b)
        {
            bool match = true;

            for (int i = 0; i < 6; i++)
                if (!(a[i] == b[i]))
                {
                    match = false;
                    break;
                }

            return match;
        }

        public PcapParser(Stream instream)
        {
            packets = new List<WeakPacket>();
            targetBssid = new byte[] { 0x00, 0x14, 0x6C, 0x7D, 0x91, 0x2E };

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

                // Data packet
                // https://en.wikipedia.org/wiki/802.11_Frame_Types
                if (ftype == 2 && subtype == 0)
                {
                    // Double check BSSID
                    r.BaseStream.Seek(startOfPacket + 4, SeekOrigin.Begin);
                    byte[] mac1 = r.ReadBytes(6);
                    byte[] mac2 = r.ReadBytes(6);

                    if (!(MacMatch(mac1, targetBssid) || MacMatch(mac2, targetBssid)))
                    {
                        // Skip to end of this packet and continue
                        r.BaseStream.Seek(startOfPacket + incl_len, SeekOrigin.Begin);
                        continue;
                    }

                    // Console.WriteLine($"BSSID: {bssid[0]:X2}:{bssid[1]:X2}:{bssid[2]:X2}:{bssid[3]:X2}:{bssid[4]:X2}:{bssid[5]:X2}");

                    // IV is at bytes 24,25,26 from start of packet
                    r.BaseStream.Seek(startOfPacket + 24, SeekOrigin.Begin);
                    byte[] iv = r.ReadBytes(3);

                    // Consume packet bytes
                    byte[] packetdata = r.ReadBytes((int)(startOfPacket + incl_len - r.BaseStream.Position - 4));

                    // WEP ICV is the last 4 bytes
                    byte[] icv = r.ReadBytes(4);

                    // Check for weak IVs ()
                    int iva = iv[0] - 3;

                    if (iv[1] == 0xFF && iva >= 0 && iva < 5)
                    {
                        WeakPacket weak = new WeakPacket(iv, packetdata);
                        Console.WriteLine(weak);

                        packets.Add(weak);
                    }
                }
                else
                {
                    r.BaseStream.Seek((int)(startOfPacket + incl_len), SeekOrigin.Begin);
                }
            }
        }

        // Get weak packets that have the given A value
        public List<WeakPacket> GetWeakPackets(int A)
        {
            List<WeakPacket> output = new List<WeakPacket>();

            foreach (WeakPacket packet in packets)
                if (packet.A == A)
                    output.Add(packet);

            return output;
        }

        public List<WeakPacket> GetWeakPackets()
        {
            return packets;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{
    public class MD5
    {
        private uint[] T;
        private uint[] S;
        private byte[] buffer;
        private uint[] state;

        public MD5()
        {
            T = new uint[64];
            S = new uint[] { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
            buffer = new byte[64];
            state = new uint[] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
            InitT();
        }

        private void InitT()
        {
            for (int i = 0; i < 64; i++)
            {
                T[i] = (uint)(4294967296 * Math.Abs(Math.Sin(i + 1)));
            }
        }

        private void Transform(byte[] input)
        {
            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];

            uint[] x = new uint[16];
            for (int i = 0; i < 16; i++)
            {
                x[i] = (uint)(input[i * 4] + (input[i * 4 + 1] << 8) + (input[i * 4 + 2] << 16) + (input[i * 4 + 3] << 24));
            }

            for (int i = 0; i < 64; i++)
            {
                uint f, g;
                if (i < 16)
                {
                    f = (b & c) | ((~b) & d);
                    g = (uint)i;
                }
                else if (i < 32)
                {
                    f = (d & b) | ((~d) & c);
                    g = (5 * (uint)i + 1) % 16;
                }
                else if (i < 48)
                {
                    f = b ^ c ^ d;
                    g = (3 * (uint)i + 5) % 16;
                }
                else
                {
                    f = c ^ (b | (~d));
                    g = (7 * (uint)i) % 16;
                }

                f = f + a + T[i] + x[g];
                a = d;
                d = c;
                c = b;
                b = b + LeftRotate(f, S[i]);
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }
        private uint LeftRotate(uint x, uint n)
        {
            return (x << (int)n) | (x >> (int)(32 - n));
        }

        public string GetHash(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            int offset = 0;
            int length = bytes.Length;

            // pad the message with a single 1-bit followed by zeros until the length is congruent to 448 modulo 512
            buffer = new byte[64];
            int bufferIndex = 0;
            while (offset < length)
            {
                buffer[bufferIndex++] = bytes[offset++];
                if (bufferIndex == 64)
                {
                    Transform(buffer);
                    bufferIndex = 0;
                }
            }
            buffer[bufferIndex++] = 0x80;
            if (bufferIndex > 56)
            {
                while (bufferIndex < 64)
                {
                    buffer[bufferIndex++] = 0;
                }
                Transform(buffer);
                bufferIndex = 0;
            }
            while (bufferIndex < 56)
            {
                buffer[bufferIndex++] = 0;
            }
            ulong bitLength = (ulong)length * 8;
            buffer[56] = (byte)(bitLength & 0xFF);
            buffer[57] = (byte)((bitLength >> 8) & 0xFF);
            buffer[58] = (byte)((bitLength >> 16) & 0xFF);
            buffer[59] = (byte)((bitLength >> 24) & 0xFF);
            buffer[60] = (byte)((bitLength >> 32) & 0xFF);
            buffer[61] = (byte)((bitLength >> 40) & 0xFF);
            buffer[62] = (byte)((bitLength >> 48) & 0xFF);
            buffer[63] = (byte)((bitLength >> 56) & 0xFF);
            Transform(buffer);

            // convert the state to a 32-byte hash value
            byte[] hashBytes = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                hashBytes[i * 4] = (byte)(state[i] & 0xFF);
                hashBytes[i * 4 + 1] = (byte)((state[i] >> 8) & 0xFF);
                hashBytes[i * 4 + 2] = (byte)((state[i] >> 16) & 0xFF);
                hashBytes[i * 4 + 3] = (byte)((state[i] >> 24) & 0xFF);
            }
            string hash = BitConverter.ToString(hashBytes).Replace("-", "");
            return hash;
        }

    }
}

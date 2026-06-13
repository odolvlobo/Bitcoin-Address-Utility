// Bitcoin Address Utility
// Copyright (C) 2012 Mike Caldwell
// Copyright (C) 2026 odolvlobo
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.Text;
using Casascius.Bitcoin;
using Xunit;

namespace BtcAddress.UnitTests
{
    // Proves the Convert-based refactors of ByteArrayToString / HexStringToBytes produce
    // byte-for-byte identical output to the original hand-rolled implementations, which are
    // embedded below as the reference oracle and fuzzed against the live Util methods.
    public class RefactorEquivalenceTests
    {
        // ---- original implementations (pre-refactor), kept verbatim as the oracle ----

        private static string OldByteArrayToString(byte[] ba, int offset, int count)
        {
            string rv = "";
            int usedcount = 0;
            for (int i = offset; usedcount < count; i++, usedcount++)
            {
                rv += String.Format("{0:X2}", ba[i]) + " ";
            }
            return rv;
        }

        private static byte[] OldHexStringToBytes(string source, bool testingForValidHex = false)
        {
            List<byte> bytes = new List<byte>();
            bool gotFirstChar = false;
            byte accum = 0;

            foreach (char c in source.ToCharArray())
            {
                if (c == ' ' || c == '-' || c == ':')
                {
                    if (gotFirstChar)
                    {
                        bytes.Add(accum);
                        accum = 0;
                        gotFirstChar = false;
                    }
                }
                else if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
                {
                    byte v = (byte)(c - 0x30);
                    if (c >= 'A' && c <= 'F') v = (byte)(c + 0x0a - 'A');
                    if (c >= 'a' && c <= 'f') v = (byte)(c + 0x0a - 'a');

                    if (gotFirstChar == false)
                    {
                        gotFirstChar = true;
                        accum = v;
                    }
                    else
                    {
                        accum <<= 4;
                        accum += v;
                        bytes.Add(accum);
                        accum = 0;
                        gotFirstChar = false;
                    }
                }
                else
                {
                    if (testingForValidHex) return null;
                }
            }
            if (gotFirstChar) bytes.Add(accum);
            return bytes.ToArray();
        }

        // ---- ByteArrayToString ----

        [Fact]
        public void ByteArrayToString_Empty_ReturnsEmpty()
        {
            Assert.Equal("", Util.ByteArrayToString(Array.Empty<byte>()));
        }

        [Fact]
        public void ByteArrayToString_AllByteValues_MatchOracle()
        {
            byte[] all = new byte[256];
            for (int i = 0; i < 256; i++) all[i] = (byte)i;
            Assert.Equal(OldByteArrayToString(all, 0, all.Length), Util.ByteArrayToString(all));
        }

        [Fact]
        public void ByteArrayToString_Fuzz_MatchesOracle()
        {
            Random rng = new Random(1234567);
            for (int iter = 0; iter < 20000; iter++)
            {
                byte[] ba = new byte[rng.Next(0, 41)];
                rng.NextBytes(ba);
                int offset = ba.Length == 0 ? 0 : rng.Next(0, ba.Length);
                int count = ba.Length == 0 ? 0 : rng.Next(0, ba.Length - offset + 1);

                Assert.Equal(OldByteArrayToString(ba, offset, count), Util.ByteArrayToString(ba, offset, count));
            }
        }

        // ---- HexStringToBytes ----

        [Theory]
        [InlineData("ABC", new byte[] { 0xAB, 0x0C })]          // trailing lone nibble -> low byte
        [InlineData("1-A2", new byte[] { 0x01, 0xA2 })]         // delimiter forces a byte boundary mid-pair
        [InlineData("1 2 3", new byte[] { 0x01, 0x02, 0x03 })]  // single nibbles between spaces
        [InlineData("", new byte[] { })]
        [InlineData("   ", new byte[] { })]
        [InlineData("de:ad:be:ef", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })]
        public void HexStringToBytes_KnownCases(string src, byte[] expected)
        {
            Assert.Equal(expected, Util.HexStringToBytes(src));
        }

        [Fact]
        public void HexStringToBytes_InvalidCharNotTesting_SkipsButKeepsPairing()
        {
            // '.' is ignored and does NOT break a nibble pair when not validating.
            Assert.Equal(new byte[] { 0xAB }, Util.HexStringToBytes("A.B"));
        }

        [Fact]
        public void HexStringToBytes_InvalidCharTesting_ReturnsNull()
        {
            Assert.Null(Util.HexStringToBytes("A.B", testingForValidHex: true));
        }

        [Fact]
        public void HexStringToBytes_Fuzz_MatchesOracle()
        {
            // Alphabet biased toward hex digits, delimiters, and a few invalid chars.
            char[] alphabet = "0123456789abcdefABCDEF -:gGzZ.\t\n".ToCharArray();
            Random rng = new Random(7654321);

            for (int iter = 0; iter < 50000; iter++)
            {
                int len = rng.Next(0, 25);
                StringBuilder sb = new StringBuilder(len);
                for (int i = 0; i < len; i++) sb.Append(alphabet[rng.Next(alphabet.Length)]);
                string src = sb.ToString();

                foreach (bool testing in new[] { false, true })
                {
                    byte[] expected = OldHexStringToBytes(src, testing);
                    byte[] actual = Util.HexStringToBytes(src, testing);
                    Assert.Equal(expected, actual); // Assert.Equal handles null == null
                }
            }
        }

        // ---- round trip across both refactored functions ----

        [Fact]
        public void HexRoundTrip_Fuzz()
        {
            Random rng = new Random(424242);
            for (int iter = 0; iter < 5000; iter++)
            {
                byte[] ba = new byte[rng.Next(0, 41)];
                rng.NextBytes(ba);
                string hex = Util.ByteArrayToString(ba);
                Assert.Equal(ba, Util.HexStringToBytes(hex));
            }
        }
    }
}

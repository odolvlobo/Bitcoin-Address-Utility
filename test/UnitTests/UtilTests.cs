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

using Casascius.Bitcoin;
using Xunit;

namespace BtcAddress.UnitTests
{

    // Base58Check, hex conversion, and hashing helpers in Util.
    public class UtilTests
    {

        static string NoSpace(string s) => s?.Replace(" ", "");

        [Fact]
        public void Base58Check_AllZero_WellKnownAddress()
        {
            Assert.Equal("1111111111111111111114oLvT2", Util.ByteArrayToBase58Check(new byte[21]));
        }

        [Fact]
        public void Base58Check_LeadingZeros_RoundTrip()
        {
            byte[] lead = { 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a };
            string enc = Util.ByteArrayToBase58Check(lead);
            byte[] dec = Util.Base58CheckToByteArray(enc);
            Assert.Equal(lead, dec);
        }

        [Fact]
        public void Base58Check_InvalidChecksum_ReturnsNull()
        {
            // flip the last char of a valid address to corrupt the checksum
            Assert.Null(Util.Base58CheckToByteArray("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZX"));
        }

        [Theory]
        [InlineData("00", new byte[] { 0x00 })]
        [InlineData("FF", new byte[] { 0xFF })]
        [InlineData("0123456789abcdef", new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })]
        public void HexStringToBytes_Parses(string hex, byte[] expected)
        {
            Assert.Equal(expected, Util.HexStringToBytes(hex));
        }

        [Theory]
        [InlineData("xyz")]
        [InlineData("0g")]
        public void HexStringToBytes_Invalid_ReturnsNull_WhenTesting(string hex)
        {
            Assert.Null(Util.HexStringToBytes(hex, testingForValidHex: true));
        }

        [Fact]
        public void ByteArrayToString_SpaceSeparatedUppercaseHex()
        {
            // Util formats bytes as space-separated uppercase hex.
            Assert.Equal("01 23 AB CD EF ", Util.ByteArrayToString(new byte[] { 0x01, 0x23, 0xab, 0xcd, 0xef }));
        }

        [Fact]
        public void HexRoundTrip()
        {
            byte[] original = { 0xde, 0xad, 0xbe, 0xef };
            string hex = NoSpace(Util.ByteArrayToString(original));
            Assert.Equal(original, Util.HexStringToBytes(hex));
        }

        [Fact]
        public void Sha256_EmptyString_KnownDigest()
        {
            // SHA-256("") = e3b0c442...
            Assert.Equal(
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                NoSpace(Util.ByteArrayToString(Util.ComputeSha256(""))));
        }

        [Fact]
        public void DoubleSha256_EmptyString_KnownDigest()
        {
            // SHA-256(SHA-256("")) = 5df6e0e2...
            Assert.Equal(
                "5DF6E0E2761359D30A8275058E299FCC0381534545F55CF43E41983F5D4C9456",
                NoSpace(Util.ByteArrayToString(Util.ComputeDoubleSha256(""))));
        }

        [Fact]
        public void Force32Bytes_PadsShort()
        {
            byte[] result = Util.Force32Bytes(new byte[] { 0x01 });
            Assert.Equal(32, result.Length);
            Assert.Equal(0x01, result[31]);
            Assert.Equal(0x00, result[0]);
        }
    }
}

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

    // Known-answer vectors for the priv-key -> address/WIF/pubkey path.
    // Ported from test/GoldenVectors so the same anchors run under `dotnet test`.
    public class KeyPairTests
    {

        static byte[] PrivKey(byte low)
        {
            byte[] b = new byte[32];
            b[31] = low;
            return b;
        }

        static string NoSpace(string s) => s?.Replace(" ", "");

        [Fact]
        public void Priv0x01_Uncompressed_Address()
        {
            var kp = new KeyPair(PrivKey(0x01), compressed: false);
            Assert.Equal("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", kp.AddressBase58);
        }

        [Fact]
        public void Priv0x01_Uncompressed_Wif()
        {
            var kp = new KeyPair(PrivKey(0x01), compressed: false);
            Assert.Equal("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", kp.PrivateKeyBase58);
        }

        [Fact]
        public void Priv0x01_Uncompressed_PubKey()
        {
            var kp = new KeyPair(PrivKey(0x01), compressed: false);
            Assert.Equal(
                "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                NoSpace(kp.PublicKeyHex));
        }

        [Fact]
        public void Priv0x01_Compressed_Address()
        {
            var kp = new KeyPair(PrivKey(0x01), compressed: true);
            Assert.Equal("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", kp.AddressBase58);
        }

        [Fact]
        public void Priv0x01_Compressed_Wif()
        {
            var kp = new KeyPair(PrivKey(0x01), compressed: true);
            Assert.Equal("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", kp.PrivateKeyBase58);
        }

        [Fact]
        public void Priv0x01_Compressed_PubKey()
        {
            var kp = new KeyPair(PrivKey(0x01), compressed: true);
            Assert.Equal(
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                NoSpace(kp.PublicKeyHex));
        }

        [Fact]
        public void Mini_KnownVector_ToPrivHex()
        {
            var mini = new MiniKeyPair("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy");
            Assert.Equal(
                "4C7A9640C72DC2099F23715D0C8A0D8A35F8906E3CAB61DD3F78B67BF887C9AB",
                NoSpace(Util.ByteArrayToString(mini.PrivateKeyBytes)));
        }

        [Theory]
        [InlineData("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")]
        [InlineData("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")]
        public void Wif_RoundTrips_To_Address(string wif, string expectedAddress)
        {
            var kp = new KeyPair(wif);
            Assert.Equal(expectedAddress, kp.AddressBase58);
        }
    }
}

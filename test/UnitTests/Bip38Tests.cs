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

namespace BtcAddress.UnitTests {

    // BIP38 encrypted keys. The no-EC-multiply path is deterministic, so it
    // matches the spec vector byte-for-byte; the EC-multiply path is checked
    // for round-trip self-consistency.
    public class Bip38Tests {

        const string SpecWif = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";
        const string SpecEnc = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
        const string SpecPass = "TestingOneTwoThree";

        [Fact]
        public void NoEcMultiply_Encrypt_MatchesSpecVector() {
            var known = new KeyPair(SpecWif);
            var enc = new Bip38KeyPair(known, SpecPass);
            Assert.Equal(SpecEnc, enc.EncryptedPrivateKey);
        }

        [Fact]
        public void NoEcMultiply_Decrypt_RecoversWif() {
            var dec = new Bip38KeyPair(SpecEnc);
            Assert.True(dec.DecryptWithPassphrase(SpecPass));
            Assert.Equal(SpecWif, dec.GetUnencryptedPrivateKey().PrivateKeyBase58);
        }

        [Fact]
        public void NoEcMultiply_WrongPassphrase_Fails() {
            var dec = new Bip38KeyPair(SpecEnc);
            Assert.False(dec.DecryptWithPassphrase("wrong passphrase"));
        }

        [Fact]
        public void EcMultiply_RoundTrip_AddressMatches() {
            byte[] ownerentropy = new byte[8];
            new Org.BouncyCastle.Security.SecureRandom().NextBytes(ownerentropy);

            var intermediate = new Bip38Intermediate("Satoshi", ownerentropy, true);
            var enc = new Bip38KeyPair(intermediate);
            string conf = enc.GetConfirmationCode();
            Assert.False(string.IsNullOrEmpty(conf));

            var dec = new Bip38KeyPair(enc.EncryptedPrivateKey);
            Assert.True(dec.DecryptWithPassphrase("Satoshi"));
            Assert.Equal(enc.GetAddress().AddressBase58, dec.GetAddress().AddressBase58);
        }
    }
}

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
using Casascius.Bitcoin;
using Xunit;

namespace BtcAddress.GoldenVectors {

    // Crypto-validation harness for the .NET 10 migration (plan Step 7).
    //
    // The original .NET 4.0 binary cannot be built on a modern toolchain, so instead
    // of a byte-for-byte diff against it we anchor to PUBLIC known-answer vectors
    // (objective truth, independent of this codebase) for the standardized paths, and
    // round-trip self-consistency for the Casascius-custom paths (MofN, escrow).
    //
    // Any failure means a BouncyCastle v1->v2 migration regression. Originally a
    // standalone console harness; migrated to xUnit so `dotnet test` runs it alongside
    // the unit suite. Still a separate assembly, so it remains the dedicated release gate.
    public class GoldenVectorTests {

        static string NoSpace(string s) => s == null ? null : s.Replace(" ", "");

        // priv key = 0x01 (32 bytes, big-endian).
        static byte[] PrivOne() { byte[] one = new byte[32]; one[31] = 0x01; return one; }

        // --- Known-answer: private key = 0x01, uncompressed -----------------
        [Fact]
        public void Priv0x01_Uncompressed() {
            var kp = new KeyPair(PrivOne(), compressed: false);
            Assert.Equal("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", kp.AddressBase58);
            Assert.Equal("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", kp.PrivateKeyBase58);
            Assert.Equal(
                "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                NoSpace(kp.PublicKeyHex));
        }

        // --- Known-answer: private key = 0x01, compressed -------------------
        [Fact]
        public void Priv0x01_Compressed() {
            var kp = new KeyPair(PrivOne(), compressed: true);
            Assert.Equal("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", kp.AddressBase58);
            Assert.Equal("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", kp.PrivateKeyBase58);
            Assert.Equal(
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                NoSpace(kp.PublicKeyHex));
        }

        // --- Base58Check leading-zero handling ------------------------------
        [Fact]
        public void Base58Check_AllZero_WellKnownAddress() {
            // version 0x00 + 20 zero bytes -> well-known all-zero address.
            Assert.Equal("1111111111111111111114oLvT2", Util.ByteArrayToBase58Check(new byte[21]));
        }

        [Fact]
        public void Base58Check_LeadingZeros_RoundTrip() {
            byte[] lead = new byte[] { 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a };
            byte[] dec = Util.Base58CheckToByteArray(Util.ByteArrayToBase58Check(lead));
            Assert.Equal(lead, dec);
        }

        // --- Casascius mini private key (known vector) ----------------------
        [Fact]
        public void MiniKey_KnownVector_ToPrivHex() {
            var mini = new MiniKeyPair("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy");
            Assert.Equal("4C7A9640C72DC2099F23715D0C8A0D8A35F8906E3CAB61DD3F78B67BF887C9AB",
                NoSpace(Util.ByteArrayToString(mini.PrivateKeyBytes)));
        }

        // --- BIP38 no-EC-multiply (spec vector 1, encrypt + decrypt) --------
        // Encryption here is deterministic (passphrase + key only), so we match
        // the published encrypted key byte-for-byte.
        [Fact]
        public void Bip38_NoEcMultiply_SpecVector_RoundTrip() {
            const string specWif = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";
            const string specEnc = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
            KeyPair known = new KeyPair(specWif);
            var encbip = new Bip38KeyPair(known, "TestingOneTwoThree");
            Assert.Equal(specEnc, encbip.EncryptedPrivateKey);

            var decbip = new Bip38KeyPair(encbip.EncryptedPrivateKey);
            Assert.True(decbip.DecryptWithPassphrase("TestingOneTwoThree"));
            Assert.Equal(specWif, decbip.GetUnencryptedPrivateKey().PrivateKeyBase58);
        }

        // --- BIP38 EC-multiply round-trip (encrypt/confirm/decrypt) ---------
        [Fact]
        public void Bip38_EcMultiply_RoundTrip() {
            byte[] ownerentropy = new byte[8];
            new Org.BouncyCastle.Security.SecureRandom().NextBytes(ownerentropy);
            var intermediate = new Bip38Intermediate("Satoshi", ownerentropy, true);
            var enckp = new Bip38KeyPair(intermediate);
            string encstr = enckp.EncryptedPrivateKey;
            Assert.False(string.IsNullOrEmpty(enckp.GetConfirmationCode()));

            var deckp = new Bip38KeyPair(encstr);
            Assert.True(deckp.DecryptWithPassphrase("Satoshi"));
            Assert.Equal(enckp.GetAddress().AddressBase58, deckp.GetAddress().AddressBase58);
        }

        // --- M-of-N split/combine self-consistency --------------------------
        [Fact]
        public void MofN_2of3_AnySubset_RecombinesToSameAddress() {
            var gen = new MofN();
            gen.Generate(2, 3); // 2-of-3, random key
            List<string> parts = gen.GetKeyParts();
            Assert.Equal(3, parts.Count);

            string a = CombineMofN(parts[0], parts[1]);
            string b = CombineMofN(parts[1], parts[2]);
            string c = CombineMofN(parts[0], parts[2]);
            Assert.NotNull(a);
            Assert.Equal(a, b);
            Assert.Equal(b, c);
            Assert.Equal(gen.BitcoinAddress, a);
        }

        // --- Escrow code round-trip -----------------------------------------
        [Fact]
        public void Escrow_RoundTrip_RecoversPaymentAddress() {
            var escrow = new EscrowCodeSet();
            var pay = new EscrowCodeSet(escrow.EscrowInvitationCodeA);
            string payAddr = pay.BitcoinAddress;
            Assert.False(string.IsNullOrEmpty(payAddr));

            string recovered = null;
            foreach (string firstcode in new[] { escrow.EscrowInvitationCodeB, escrow.EscrowInvitationCodeA }) {
                try {
                    var rec = new EscrowCodeSet(firstcode, pay.PaymentInvitationCode);
                    if (rec.BitcoinAddress == payAddr) { recovered = rec.BitcoinAddress; break; }
                } catch { /* try the other code ordering */ }
            }
            Assert.Equal(payAddr, recovered);
        }

        // --- QR encode: must size the version to the payload, not throw --------
        // Regression guard: a fixed QR version made boundary-length payloads
        // (34-char address, 58-char BIP38 key, ~65-char confirmation code) throw
        // DataTooLongException. Each must now produce a bitmap.
        [Theory]
        [InlineData("1BitcoinEaterAddressDontSendf59kuE")]                                    // address (34)
        [InlineData("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg")]            // BIP38 key (58)
        [InlineData("cfrm38V8a9b2c3d4e5f6g7h8j9k1m2n3p4q5r6s7t8u9v1w2x3y4z5A6B7C8D9E1F2")]     // confirmation-length
        public void Qr_BoundaryLengthPayloads_Encode(string payload) {
            using var bmp = global::BtcAddress.QR.EncodeQRCode(payload);
            Assert.NotNull(bmp);
        }

        [Fact]
        public void Qr_PubKeyHex_BothForms_Encode() {
            var kpU = new KeyPair(PrivOne(), compressed: false);
            var kpC = new KeyPair(PrivOne(), compressed: true);
            using (var u = global::BtcAddress.QR.EncodeQRCode(NoSpace(kpU.PublicKeyHex))) Assert.NotNull(u);
            using (var c = global::BtcAddress.QR.EncodeQRCode(NoSpace(kpC.PublicKeyHex))) Assert.NotNull(c);
        }

        static string CombineMofN(string p1, string p2) {
            var m = new MofN();
            m.AddKeyPart(p1);
            m.AddKeyPart(p2);
            m.Decode();
            return m.Decoded ? m.BitcoinAddress : null;
        }
    }
}

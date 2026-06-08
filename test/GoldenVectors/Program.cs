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

// Crypto-validation harness for the .NET 10 migration (plan Step 7).
//
// The original .NET 4.0 binary cannot be built on a modern toolchain, so instead
// of a byte-for-byte diff against it we anchor to PUBLIC known-answer vectors
// (objective truth, independent of this codebase) for the standardized paths, and
// round-trip self-consistency for the Casascius-custom paths (MofN, escrow).
//
// Any FAIL means a BouncyCastle v1->v2 migration regression. Exit code != 0 on fail.

static class Program {
    static int failures = 0;

    static void Check(string name, string expected, string actual) {
        bool ok = string.Equals(expected, actual, StringComparison.Ordinal);
        if (!ok) failures++;
        Console.WriteLine((ok ? "PASS " : "FAIL ") + name);
        if (!ok) {
            Console.WriteLine("       expected: " + expected);
            Console.WriteLine("       actual:   " + actual);
        }
    }

    static void CheckTrue(string name, bool ok) {
        if (!ok) failures++;
        Console.WriteLine((ok ? "PASS " : "FAIL ") + name);
    }

    static string NoSpace(string s) { return s == null ? null : s.Replace(" ", ""); }

    static int Main() {
        Console.WriteLine("=== Bitcoin Address Utility crypto validation ===");

        // --- Known-answer: private key = 0x01 -------------------------------
        byte[] one = new byte[32];
        one[31] = 0x01;

        var kpU = new KeyPair(one, compressed: false);
        Check("priv0x01 address (uncompressed)", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", kpU.AddressBase58);
        Check("priv0x01 WIF (uncompressed)", "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", kpU.PrivateKeyBase58);
        Check("priv0x01 pubkey (uncompressed)",
            "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            NoSpace(kpU.PublicKeyHex));

        var kpC = new KeyPair(one, compressed: true);
        Check("priv0x01 address (compressed)", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", kpC.AddressBase58);
        Check("priv0x01 WIF (compressed)", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", kpC.PrivateKeyBase58);
        Check("priv0x01 pubkey (compressed)",
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            NoSpace(kpC.PublicKeyHex));

        // --- Base58Check leading-zero handling ------------------------------
        // version 0x00 + 20 zero bytes -> well-known all-zero address.
        Check("Base58Check 21 zero bytes", "1111111111111111111114oLvT2", Util.ByteArrayToBase58Check(new byte[21]));
        // round-trip a value with leading zero bytes through decode/encode.
        byte[] lead = new byte[] { 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a };
        string enc = Util.ByteArrayToBase58Check(lead);
        byte[] dec = Util.Base58CheckToByteArray(enc);
        CheckTrue("Base58Check leading-zero round-trip", ByteEq(lead, dec));

        // --- Casascius mini private key (known vector) ----------------------
        var mini = new MiniKeyPair("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy");
        Check("mini key -> priv hex", "4C7A9640C72DC2099F23715D0C8A0D8A35F8906E3CAB61DD3F78B67BF887C9AB",
            NoSpace(Util.ByteArrayToString(mini.PrivateKeyBytes)));

        // --- BIP38 no-EC-multiply (spec vector 1, encrypt + decrypt) --------
        // Encryption here is deterministic (passphrase + key only), so we can match
        // the published encrypted key byte-for-byte.
        try {
            const string specWif = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";
            const string specEnc = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
            KeyPair known = new KeyPair(specWif);
            var encbip = new Bip38KeyPair(known, "TestingOneTwoThree");
            Check("BIP38 no-EC-multiply encrypt", specEnc, encbip.EncryptedPrivateKey);

            var decbip = new Bip38KeyPair(encbip.EncryptedPrivateKey);
            bool dok = decbip.DecryptWithPassphrase("TestingOneTwoThree");
            CheckTrue("BIP38 no-EC-multiply decrypt succeeded", dok);
            if (dok) {
                Check("BIP38 no-EC-multiply -> WIF", specWif,
                    decbip.GetUnencryptedPrivateKey().PrivateKeyBase58);
            }
        } catch (Exception ex) {
            CheckTrue("BIP38 no-EC-multiply (threw: " + ex.Message + ")", false);
        }

        // --- BIP38 EC-multiply round-trip (encrypt/confirm/decrypt) ---------
        try {
            byte[] ownerentropy = new byte[8];
            new Org.BouncyCastle.Security.SecureRandom().NextBytes(ownerentropy);
            var intermediate = new Bip38Intermediate("Satoshi", ownerentropy, true);
            var enckp = new Bip38KeyPair(intermediate);
            string encstr = enckp.EncryptedPrivateKey;
            string conf = enckp.GetConfirmationCode();
            CheckTrue("BIP38 EC-multiply confirmation code generated", !string.IsNullOrEmpty(conf));

            var deckp = new Bip38KeyPair(encstr);
            bool ecdok = deckp.DecryptWithPassphrase("Satoshi");
            CheckTrue("BIP38 EC-multiply decrypt succeeded", ecdok);
            Check("BIP38 EC-multiply round-trip address",
                enckp.GetAddress().AddressBase58, deckp.GetAddress().AddressBase58);
        } catch (Exception ex) {
            CheckTrue("BIP38 EC-multiply round-trip (threw: " + ex.Message + ")", false);
        }

        // --- M-of-N split/combine self-consistency --------------------------
        try {
            var gen = new MofN();
            gen.Generate(2, 3); // 2-of-3, random key
            List<string> parts = gen.GetKeyParts();
            CheckTrue("MofN generated 3 parts", parts.Count == 3);

            string a = CombineMofN(parts[0], parts[1]);
            string b = CombineMofN(parts[1], parts[2]);
            string c = CombineMofN(parts[0], parts[2]);
            CheckTrue("MofN combine {0,1} valid", a != null);
            CheckTrue("MofN combine subsets agree", a != null && a == b && b == c);
            CheckTrue("MofN combine matches generated address", a == gen.BitcoinAddress);
        } catch (Exception ex) {
            CheckTrue("MofN round-trip (threw: " + ex.Message + ")", false);
        }

        // --- Escrow code round-trip -----------------------------------------
        try {
            var escrow = new EscrowCodeSet();
            var pay = new EscrowCodeSet(escrow.EscrowInvitationCodeA);
            string payAddr = pay.BitcoinAddress;
            CheckTrue("Escrow payment address derived", !string.IsNullOrEmpty(payAddr));

            string recovered = null;
            foreach (string firstcode in new[] { escrow.EscrowInvitationCodeB, escrow.EscrowInvitationCodeA }) {
                try {
                    var rec = new EscrowCodeSet(firstcode, pay.PaymentInvitationCode);
                    if (rec.BitcoinAddress == payAddr) { recovered = rec.BitcoinAddress; break; }
                } catch { /* try the other code ordering */ }
            }
            CheckTrue("Escrow round-trip recovers payment address", recovered == payAddr);
        } catch (Exception ex) {
            CheckTrue("Escrow round-trip (threw: " + ex.Message + ")", false);
        }

        // --- QR encode: must size the version to the payload, not throw --------
        // Regression guard: a fixed QR version made boundary-length payloads
        // (34-char address, 58-char BIP38 key, ~75-char confirmation code) throw
        // DataTooLongException. Each must now produce a bitmap.
        try {
            CheckTrue("QR address (34-char)", QrOk("1BitcoinEaterAddressDontSendf59kuE"));
            CheckTrue("QR pubkey hex uncompressed (130)", QrOk(NoSpace(kpU.PublicKeyHex)));
            CheckTrue("QR pubkey hex compressed (66)", QrOk(NoSpace(kpC.PublicKeyHex)));
            CheckTrue("QR BIP38 key (58)", QrOk("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"));
            // Long mixed-case Base58 (byte mode), confirmation-code shaped.
            CheckTrue("QR confirmation-length", QrOk("cfrm38V8a9b2c3d4e5f6g7h8j9k1m2n3p4q5r6s7t8u9v1w2x3y4z5A6B7C8D9E1F2"));
        } catch (Exception ex) {
            CheckTrue("QR encode (threw: " + ex.Message + ")", false);
        }

        Console.WriteLine();
        Console.WriteLine(failures == 0 ? "ALL VECTORS PASSED" : (failures + " FAILURE(S)"));
        return failures == 0 ? 0 : 1;
    }

    static string CombineMofN(string p1, string p2) {
        var m = new MofN();
        m.AddKeyPart(p1);
        m.AddKeyPart(p2);
        m.Decode();
        return m.Decoded ? m.BitcoinAddress : null;
    }

    static bool QrOk(string s) {
        using (var bmp = BtcAddress.QR.EncodeQRCode(s)) return bmp != null;
    }

    static bool ByteEq(byte[] x, byte[] y) {
        if (x == null || y == null || x.Length != y.Length) return false;
        for (int i = 0; i < x.Length; i++) if (x[i] != y[i]) return false;
        return true;
    }
}

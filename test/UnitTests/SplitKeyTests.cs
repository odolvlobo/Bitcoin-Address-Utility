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

using System.Collections.Generic;
using Casascius.Bitcoin;
using Xunit;

namespace BtcAddress.UnitTests
{

    // M-of-N split-key and escrow-code self-consistency. No public KAT exists for
    // these Casascius-custom paths, so the invariant is: any valid subset of parts
    // recombines to the same address.
    public class SplitKeyTests
    {

        static string Combine(string p1, string p2)
        {
            var m = new MofN();
            m.AddKeyPart(p1);
            m.AddKeyPart(p2);
            m.Decode();
            return m.Decoded ? m.BitcoinAddress : null;
        }

        [Fact]
        public void MofN_2of3_AnySubset_RecombinesToSameAddress()
        {
            var gen = new MofN();
            gen.Generate(2, 3);
            List<string> parts = gen.GetKeyParts();
            Assert.Equal(3, parts.Count);

            string ab = Combine(parts[0], parts[1]);
            string bc = Combine(parts[1], parts[2]);
            string ac = Combine(parts[0], parts[2]);

            Assert.NotNull(ab);
            Assert.Equal(gen.BitcoinAddress, ab);
            Assert.Equal(ab, bc);
            Assert.Equal(bc, ac);
        }

        [Fact]
        public void Escrow_RoundTrip_RecoversPaymentAddress()
        {
            var escrow = new EscrowCodeSet();
            var pay = new EscrowCodeSet(escrow.EscrowInvitationCodeA);
            string payAddr = pay.BitcoinAddress;
            Assert.False(string.IsNullOrEmpty(payAddr));

            string recovered = null;
            foreach (string firstcode in new[] { escrow.EscrowInvitationCodeB, escrow.EscrowInvitationCodeA })
            {
                try
                {
                    var rec = new EscrowCodeSet(firstcode, pay.PaymentInvitationCode);
                    if (rec.BitcoinAddress == payAddr) { recovered = rec.BitcoinAddress; break; }
                }
                catch { /* try the other code ordering */ }
            }
            Assert.Equal(payAddr, recovered);
        }
    }
}

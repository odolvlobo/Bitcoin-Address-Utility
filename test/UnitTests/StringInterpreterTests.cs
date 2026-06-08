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

    // StringInterpreter routes arbitrary user text to the right model type.
    // Guards the UI text-field -> model glue against type-detection regressions.
    public class StringInterpreterTests
    {

        [Fact]
        public void Interpret_Wif_ReturnsKeyPair()
        {
            var result = StringInterpreter.Interpret("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
            var kp = Assert.IsAssignableFrom<KeyPair>(result);
            Assert.Equal("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", kp.AddressBase58);
        }

        [Fact]
        public void Interpret_Address_ReturnsAddressBase()
        {
            var result = StringInterpreter.Interpret("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
            var addr = Assert.IsAssignableFrom<AddressBase>(result);
            Assert.Equal("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", addr.AddressBase58);
        }

        [Fact]
        public void Interpret_MiniKey_ReturnsMiniKeyPair()
        {
            var result = StringInterpreter.Interpret("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy");
            Assert.IsAssignableFrom<MiniKeyPair>(result);
        }

        [Fact]
        public void Interpret_Bip38Key_ReturnsBip38KeyPair()
        {
            var result = StringInterpreter.Interpret("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg");
            Assert.IsAssignableFrom<Bip38KeyPair>(result);
        }

        [Theory]
        [InlineData("")]
        [InlineData("not a key")]
        [InlineData("1234")]
        public void Interpret_Garbage_ReturnsNull(string input)
        {
            Assert.Null(StringInterpreter.Interpret(input));
        }

        [Fact]
        public void Interpret_Null_ReturnsNull()
        {
            Assert.Null(StringInterpreter.Interpret(null));
        }
    }
}

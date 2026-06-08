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
using System.Drawing;
using System.Text.RegularExpressions;
using QRCoder;

namespace BtcAddress {
    public class QR {

        /// <summary>
        /// Encodes a QR code, making the best choice based on string length.
        /// Version/ECC selection and null-on-overlength behavior are preserved
        /// from the original ThoughtWorks.QRCode implementation; only the
        /// underlying encoder changed (QRCoder). QRCoder auto-selects
        /// alphanumeric vs byte mode based on the payload, so a [0-9A-F] hex
        /// string still encodes in alphanumeric mode.
        /// </summary>
        public static Bitmap EncodeQRCode(string what) {
            if (what == null || what == "") return null;

            // Determine if we can use alphanumeric encoding (e.g. public key hex)
            Regex r = new Regex("^[0-9A-F]{63,154}$");
            bool IsAlphanumeric = r.IsMatch(what);

            int version;
            QRCodeGenerator.ECCLevel ecc;

            if (IsAlphanumeric) {
                if (what.Length > 154) {
                    return null;
                } else if (what.Length > 67) {
                    // 5L is good to 154 alphanumeric characters
                    version = 5;
                    ecc = QRCodeGenerator.ECCLevel.L;
                } else {
                    // 4Q is good to 67 alphanumeric characters
                    version = 4;
                    ecc = QRCodeGenerator.ECCLevel.Q;
                }
            } else {
                if (what.Length > 84) {
                    // We don't intend to encode any alphanumeric strings longer than confirmation codes at 75 characters
                    return null;
                } else if (what.Length > 62) {
                    // 5M is good to 84 characters
                    version = 5;
                    ecc = QRCodeGenerator.ECCLevel.M;
                } else if (what.Length > 34) {
                    // 4M is good to 62 characters
                    version = 4;
                    ecc = QRCodeGenerator.ECCLevel.M;
                } else if (what.Length > 32) {
                    // 4H is good to 34 characters
                    version = 4;
                    ecc = QRCodeGenerator.ECCLevel.H;
                } else {
                    // 3Q is good to 32 characters
                    version = 3;
                    ecc = QRCodeGenerator.ECCLevel.Q;
                }
            }

            using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
            using (QRCodeData qrCodeData = qrGenerator.CreateQrCode(what, ecc, false, false, QRCodeGenerator.EciMode.Default, version)) {
                QRCode qrCode = new QRCode(qrCodeData);
                return qrCode.GetGraphic(4);
            }
        }

    }
}

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

            // Pick the error-correction level by payload length (denser ECC for
            // short payloads, lighter ECC as they grow), matching the original
            // intent. The QR *version* is left to QRCoder, which auto-selects the
            // smallest version that fits the payload at the chosen ECC level --
            // pinning a fixed version made boundary-length payloads (e.g. a
            // 34-char Bitcoin address) throw DataTooLongException.
            QRCodeGenerator.ECCLevel ecc;

            if (IsAlphanumeric) {
                if (what.Length > 154) return null;
                ecc = what.Length > 67 ? QRCodeGenerator.ECCLevel.L
                                       : QRCodeGenerator.ECCLevel.Q;
            } else {
                // Longest expected payload is a ~75-char confirmation code.
                if (what.Length > 84) return null;
                ecc = what.Length > 34 ? QRCodeGenerator.ECCLevel.M
                                       : QRCodeGenerator.ECCLevel.H;
            }

            try {
                using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
                using (QRCodeData qrCodeData = qrGenerator.CreateQrCode(what, ecc)) {
                    QRCode qrCode = new QRCode(qrCodeData);
                    return qrCode.GetGraphic(4);
                }
            } catch (QRCoder.Exceptions.DataTooLongException) {
                // Preserve the original null-on-overlength contract.
                return null;
            }
        }

    }
}

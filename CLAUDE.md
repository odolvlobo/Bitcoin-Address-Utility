# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Bitcoin Address Utility (Casascius) — a Windows desktop tool for generating and manipulating Bitcoin keys, addresses, paper wallets, BIP38-encrypted keys, mini private keys, M-of-N split keys, and escrow codes. Originally by Mike Caldwell. GPLv3.

**Security-critical:** this app generates and handles private keys. Intended to run offline / air-gapped. Treat any change to the crypto/keygen paths as security-sensitive — do not alter algorithm behavior without validating output against known vectors.

## Build / run

- WinForms app, **.NET Framework 4.0**, `x86`. No cross-platform support.
- Solution: `BtcAddress.sln`. Build in Visual Studio or `msbuild BtcAddress.sln /p:Configuration=Release`.
- **Two required DLLs are NOT in the repo** (referenced via `HintPath=".\"` — repo root):
  - `BouncyCastle.Crypto.dll` — get from <http://www.bouncycastle.org/csharp/>
  - `ThoughtWorks.QRCode.dll`
  Obtain both and place at repo root before building.
- Entry point: `Program.Main` launches `BtcAddress.Forms.KeyCollectionView` (NOT `Form1`).
- **No test project, no lint, no CI.** There is no automated test command. Validation is manual against known crypto vectors.

## Architecture

### Namespace layout (does not match folders)

- `Casascius.Bitcoin` — all of `Model/` (the crypto + domain core).
- `BtcAddress` and `BtcAddress.Forms` — `Forms/` (WinForms UI). Note: forms live in **both** namespaces; check `using` and `Program.cs` references.
- `CryptSharp.Utility` — `CryptSharp/` (SCrypt, Pbkdf2, Salsa20 — used by BIP38).
- `PC` — `Reports/` printing components.

### Core: `Model/Bitcoin.cs`

Contains the static `Util` class — the central helper hub used everywhere: Base58Check encode/decode, hex conversion, validation, and secp256k1 EC point math (`PrivKeyToPubKey`, `PubKeyToByteArray`, etc.) via BouncyCastle. Start here when tracing any address/key computation.

### Key class hierarchy (`Model/`)

Two inheritance chains carry the domain model:

```text
AddressBase            (Hash160 + address-type byte → Base58Check address)
  └─ PublicKey         (adds EC public key)
       └─ KeyPair      (adds private key; WIF; keygen via BouncyCastle SecureRandom)
            └─ MiniKeyPair  (Casascius mini private key format)

EncryptedKeyPair
  └─ PassphraseKeyPair (abstract)
       ├─ ShaPassphraseKeyPair
       └─ Bip38KeyPair      (BIP38 encrypted keys)

Bip38Base
  ├─ Bip38Confirmation
  └─ Bip38Intermediate     (BIP38 EC-multiply intermediate codes)
```

- `Address.cs` / `PublicKey.cs` / `KeyPair.cs` are the spine. Most forms operate on a `KeyPair` or `AddressBase`.
- BIP38 (`Bip38*.cs`) depends on `CryptSharp` SCrypt + AES; the most complex and security-sensitive code path.
- `MofN.cs` and `EscrowCode.cs` do BigInteger-heavy secret splitting/escrow math via BouncyCastle.
- `StringInterpreter.cs` parses arbitrary user input (hex, WIF, Base58, mini key, etc.) into the right model type — the glue between UI text fields and the model.

### Crypto dependencies

- secp256k1 EC math, SHA256, RIPEMD160, `SecureRandom` → BouncyCastle (`Org.BouncyCastle.*`). RNG used in keygen is BouncyCastle's `SecureRandom`, not .NET's.
- scrypt / PBKDF2 / Salsa20 for BIP38 → bundled `CryptSharp/` (uses `unsafe` blocks).
- QR codes → ThoughtWorks.QRCode; Code128 barcodes → `Barcode/Barcode128b.cs`.
- Printing (paper wallets, vouchers, coin inserts) → `Reports/` + `System.Drawing.Printing`; logic currently lives partly in form code-behind (e.g. `Forms/PaperWalletPrinter.cs`).

## Conventions

- Address type is carried as a leading byte on the Hash160 (e.g. 0 = Bitcoin mainnet); `AddressBase` accepts 20 bytes (hash only) or 21 bytes (type + hash).
- When adding key formats or address types, route through `Util` and `StringInterpreter` rather than duplicating Base58/EC logic in forms.

## Planned upgrade

`upgrade-to-dotnet-8-plan.md` is an agent-executable plan to retarget this to .NET 8 (keeping WinForms), swapping the two unmanaged DLLs for NuGet (`BouncyCastle.Cryptography`, `QRCoder`) and `System.Drawing.Common`. Its release gate is **byte-identical crypto output vs the original 4.0 binary** — preserve that invariant in any migration work. This work happens on branch `feature/upgrade-to-dotnet-8`.

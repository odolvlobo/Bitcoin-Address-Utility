# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Bitcoin Address Utility (Casascius) — a Windows desktop tool for generating and manipulating Bitcoin keys, addresses, paper wallets, BIP38-encrypted keys, mini private keys, M-of-N split keys, and escrow codes. Originally by Mike Caldwell. GPLv3.

**Security-critical:** this app generates and handles private keys. Intended to run offline / air-gapped. Treat any change to the crypto/keygen paths as security-sensitive — do not alter algorithm behavior without validating output against known vectors.

## Build / run

- WinForms app, **.NET 10** (`net10.0-windows`), `x64`. No cross-platform support.
- SDK-style project `BtcAddress.csproj` (solution `BtcAddress.sln`). Dependencies restore from NuGet — no manual DLLs.

```powershell
dotnet build BtcAddress.csproj -c Release
```

- Single-file self-contained exe (runs on a clean Windows): `dotnet publish BtcAddress.csproj -r win-x64 -c Release -p:PublishSingleFile=true --self-contained true` → `bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe`.
- Entry point: `Program.Main` launches `BtcAddress.Forms.KeyCollectionView` (NOT `Form1`).
- **No lint, no CI.** The only automated check is the golden-vector crypto harness (see below).

### Crypto validation harness

`test/GoldenVectors/` is a separate console project (excluded from the app's compile glob via `<Compile Remove="test\**" />`). It anchors crypto output to public known-answer vectors (priv key `0x01`, BIP38 spec, mini key, Base58Check) plus round-trip self-consistency (M-of-N, escrow). Run after **any** change to crypto/keygen paths:

```powershell
dotnet run --project test/GoldenVectors/GoldenVectors.csproj -c Release
```

Exit code = number of failing vectors (0 = `ALL VECTORS PASSED`). Details: `test/golden-vectors.md`.

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

- secp256k1 EC math, SHA256, RIPEMD160, `SecureRandom` → BouncyCastle NuGet (`BouncyCastle.Cryptography` v2, namespace `Org.BouncyCastle.*`). RNG used in keygen is BouncyCastle's `SecureRandom`, not .NET's. Migrated from BC v1; `ECPoint.GetEncoded(bool)` compression args were re-derived (BC v1 `Multiply()` returned uncompressed points) — golden vectors guard this.
- scrypt / PBKDF2 / Salsa20 for BIP38 → bundled `CryptSharp/` (uses `unsafe` blocks).
- QR codes → `QRCoder` NuGet, wrapped in `Barcode/QR.cs`; Code128 barcodes → `Barcode/Barcode128b.cs`.
- Printing (paper wallets, vouchers, coin inserts) → `Reports/` + `System.Drawing.Printing`; logic currently lives partly in form code-behind (e.g. `Forms/PaperWalletPrinter.cs`).

## Conventions

- Address type is carried as a leading byte on the Hash160 (e.g. 0 = Bitcoin mainnet); `AddressBase` accepts 20 bytes (hash only) or 21 bytes (type + hash).
- When adding key formats or address types, route through `Util` and `StringInterpreter` rather than duplicating Base58/EC logic in forms.

## Migration status

The .NET Framework 4.0 → .NET 10 retarget is **done** (branch `feature/upgrade-to-dotnet-10`): SDK-style project, NuGet `BouncyCastle.Cryptography` + `QRCoder` replacing the old unmanaged DLLs, WinForms kept. `upgrade-to-dotnet-10-plan.md` is the original plan, retained for context. The original 4.0 binary can't be rebuilt on a modern toolchain, so there is no byte-for-byte golden binary — the release gate is instead **all golden vectors passing** (`test/golden-vectors.md`). Any crypto-path change must keep that green.

## Releases

Releases ship a GnuPG **detached signature** (`BtcAddress.exe.asc`), not Authenticode. Signing key fingerprint `6B6BC26599EC24EF7E29A405EAF050539D0B2925`. Maintainer workflow and verification steps: `SIGNING.md` (user-facing summary in `README.md`).

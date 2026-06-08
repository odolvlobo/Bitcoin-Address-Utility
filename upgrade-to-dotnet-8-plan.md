# AGENT PLAN: .NET 4.0 → .NET 8, keep WinForms

Audience: executing agent. Deterministic steps. Run gates in order. Do not skip Step 0 or Step 7.

## Objective

Retarget `BtcAddress.csproj` to `net8.0-windows`, keep WinForms, swap dead DLL refs for NuGet, emit single-file self-contained x64 `.exe` that runs offline. Release gate = crypto output byte-identical to original 4.0 binary.

## Constraints

- Keep WinForms. No UI redesign. No new features. No WPF.
- Minimal diff. Touch only what upgrade requires.
- No nullable, no implicit usings (legacy code).
- Do not refactor logic out of forms (deferred; out of scope).

## Repo facts (verified — do not re-investigate)

- Old-style `BtcAddress.csproj`: `OutputType=WinExe`, `TargetFrameworkVersion=v4.0`, `PlatformTarget=x86`.
- 14 forms `Forms/*.cs` + `*.Designer.cs`; 15 `.resx`.
- `Model/*` ~4150 LOC; `CryptSharp/*` ~580 LOC (uses `unsafe`); `Barcode/*` ~180; `Reports/*` ~936 (uses `System.Drawing.Printing`).
- DLL refs via `HintPath`, NOT in repo: `BouncyCastle.Crypto.dll`, `ThoughtWorks.QRCode.dll`.
- `SecureRandom` = `Org.BouncyCastle.Security.SecureRandom` (9 model files + `Forms/Form1.cs`, `Forms/PaperWalletPrinter.cs`).
- `Properties/Settings.settings` + `Settings.Designer.cs`: UNUSED (no `Settings.Default`/`ConfigurationManager` refs). Safe delete.
- `app.config`: only `<supportedRuntime version="v4.0">`. Safe delete.
- `Properties/AssemblyInfo.cs`: false attribution `AssemblyCompany("Microsoft")`, `Copyright © Microsoft 2011`. Fix.

## Dependency swaps

| Remove | Add (NuGet) | Action |
| --- | --- | --- |
| `BouncyCastle.Crypto.dll` ref | `BouncyCastle.Cryptography` (2.x) | Compile-fix `Org.BouncyCastle.*` |
| `ThoughtWorks.QRCode.dll` ref | `QRCoder` | Rewrite `Barcode/QR.cs` |
| `System.Drawing` BCL ref | `System.Drawing.Common` | Covers `System.Drawing.Printing` |
| `System.Windows.Forms` BCL ref | `<UseWindowsForms>true` | — |
| `System.Deployment`, `System.Data.DataSetExtensions`, dead BCL refs | — | Drop |

---

## STEP 0 — Baseline (MANDATORY, before any edit)

1. Branch `feature/upgrade-to-dotnet-8` (already created; this plan committed there).
2. Build or locate original 4.0 binary = golden reference.
3. Capture golden vectors from original binary → write `test/golden-vectors.md`. Required inputs (fixed seeds):
   - priv key `0x01` → address + WIF, compressed AND uncompressed.
   - Mini key generate + validate one.
   - BIP38 spec vectors: both no-EC-multiply and EC-multiply paths (encrypt+decrypt).
   - BIP38 intermediate + confirmation code for one passphrase.
   - MofN: split one secret, combine back.
   - Escrow code round-trip.
   - Base58Check: encode/decode a value with leading zero byte.

GATE 0: `test/golden-vectors.md` exists and is committed before Step 1.

## STEP 1 — SDK csproj

Overwrite `BtcAddress.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <RootNamespace>BtcAddress</RootNamespace>
    <AssemblyName>BtcAddress</AssemblyName>
    <Platforms>x64</Platforms>
    <PlatformTarget>x64</PlatformTarget>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <ApplicationIcon>bitcoinlogo.ico</ApplicationIcon>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <Company>Casascius</Company>
    <Product>BtcAddress</Product>
    <Copyright>Copyright Mike Caldwell</Copyright>
    <Version>1.0.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.*" />
    <PackageReference Include="QRCoder" Version="1.*" />
    <PackageReference Include="System.Drawing.Common" Version="8.*" />
  </ItemGroup>
</Project>
```

Notes:
- No `<Compile>`/`<EmbeddedResource>` lists — SDK auto-globs `.cs`, infers `.resx`↔`.Designer.cs`.
- `bitcoinlogo.ico` already `Content` in repo root; `ApplicationIcon` handles it.

## STEP 2 — Delete dead config

- Delete `app.config`.
- Delete `Properties/Settings.settings`, `Properties/Settings.Designer.cs`.
- Keep `Properties/Resources.resx` + `Resources.Designer.cs`.

## STEP 3 — Assembly metadata

- Delete `Properties/AssemblyInfo.cs` (metadata now in csproj from Step 1; `GenerateAssemblyInfo=false` prevents duplicate-attr errors AND stops auto-gen, so no conflict).
- If any attribute still needed (e.g. `[assembly: Guid]`, `ComVisible`), keep a trimmed `AssemblyInfo.cs` with ONLY those; remove all `AssemblyCompany`/`AssemblyCopyright`/`AssemblyVersion`/`AssemblyTitle`/`AssemblyProduct`/`AssemblyDescription`/`AssemblyConfiguration`/`AssemblyTrademark`/`AssemblyCulture`/`AssemblyFileVersion` lines (now in csproj).

## STEP 4 — BouncyCastle compile-fix

`dotnet build`; fix `Org.BouncyCastle.*` v1→v2 errors. Likely-touched symbols:
`SecureRandom`, `Math.EC.ECPoint`/`ECCurve`, `Crypto.Digests.Sha256Digest`/`RipeMD160Digest`, `Crypto.Generators.Pkcs5S2ParametersGenerator`, `Asn1.*`.
Expect mostly source-compatible. Fix only what compiler flags. Do NOT change algorithm logic.

## STEP 5 — QR rewrite

Rewrite `Barcode/QR.cs::EncodeQRCode(string)` for QRCoder. Hold invariant:
- Same alphanumeric-vs-byte selection (regex `^[0-9A-F]{63,154}$`).
- Same version/ECC thresholds: 3Q / 4H / 4M / 4Q / 5M / 5L per existing length branches.
- Same `null` returns for over-length input.
- Return `System.Drawing.Bitmap` (callers depend on it).

## STEP 6 — Build gate

GATE 6: `dotnet build -c Debug` AND `dotnet build -c Release` both 0 errors.
Resolve residual `System.Drawing.Printing`/`Graphics`/`Bitmap` issues (expect none past package ref).

## STEP 7 — Crypto validation (RELEASE GATE)

Run new build vs original binary on identical inputs. Compare to `test/golden-vectors.md`. Must be byte-identical:

- [ ] Address + WIF (compressed + uncompressed) from priv `0x01`.
- [ ] Mini key gen + validate.
- [ ] BIP38 encrypt/decrypt — both spec paths.
- [ ] BIP38 intermediate + confirmation codes.
- [ ] MofN split/combine round-trip.
- [ ] Escrow code round-trip.
- [ ] Base58Check leading-zero edge cases.
- [ ] QR: payload decodes correctly (functional only; pixels may differ — lib changed).

GATE 7: every item matches. ANY mismatch = STOP, do not publish. Highest risk: BouncyCastle `BigInteger` paths (Base58, MofN, EscrowCode) + BIP38 scrypt/AES. Check these first.

## STEP 8 — Publish

```text
dotnet publish -r win-x64 -c Release -p:PublishSingleFile=true --self-contained true
```

GATE 8: produced `.exe` runs on clean Windows (no .NET runtime) with no network. Smoke-test: paper wallet print, vouchers, coin inserts, QR render.

## STEP 9 — Hardening (recommended)

- Authenticode-sign the `.exe`; record thumbprint.
- Grep for `HttpClient`/`WebRequest`/`Socket` — confirm zero network calls in keygen path.

---

## Done criteria

- net8.0-windows SDK project, Debug+Release clean.
- Old DLL refs gone, NuGet in place.
- `app.config`/`Settings.*` deleted, attribution fixed.
- All Step 7 vectors byte-match original.
- Single-file self-contained x64 `.exe` runs offline on clean machine.

## Execution order

```text
0 branch + golden vectors  (GATE 0)
1 SDK csproj + NuGet
2 delete app.config + Settings.*
3 fix assembly metadata
4 BouncyCastle compile-fix
5 rewrite QR.cs
6 build Debug+Release       (GATE 6)
7 validate crypto vs original (GATE 7 = release gate)
8 publish single-file + smoke (GATE 8)
9 sign (recommended)
```

## Out of scope

- Logic extraction from form code-behind (future Phase 1.5).
- WPF migration (future Phase 2; same project via `<UseWPF>true</UseWPF>`).

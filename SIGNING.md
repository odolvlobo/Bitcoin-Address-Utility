# Authenticode signing (plan Step 9)

Sign the published single-file exe so Windows SmartScreen and users can verify
origin and integrity. Re-sign after **every** republish — rebuilding changes the
bytes and voids any prior signature.

Target file:

```text
bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe
```

This is the self-contained bundle; signing this one exe is sufficient (the
bundled runtime/DLLs live inside it).

## Prerequisites

- A code-signing certificate. One of:
  - **OV cert** as a `.pfx` file (+ password), or imported into the Windows
    certificate store.
  - **EV cert** on a hardware token / HSM (USB dongle or cloud KMS). Required for
    immediate SmartScreen reputation. The private key never leaves the token —
    you sign by subject name and enter the token PIN when prompted.
- `signtool.exe` from the Windows SDK (installed with VS 2026). Typical path:

  ```text
  C:\Program Files (x86)\Windows Kits\10\bin\<sdk-version>\x64\signtool.exe
  ```

  Or open **Developer Command Prompt for VS 2026** and `signtool` is on PATH.

## Sign

Always include an RFC 3161 timestamp (`/tr` + `/td`) so the signature stays valid
after the certificate expires. Pick the form matching how your key is stored.

### A. PFX file

```powershell
signtool sign /fd SHA256 `
  /f "C:\path\to\cert.pfx" /p "<pfx-password>" `
  /tr http://timestamp.digicert.com /td SHA256 `
  "bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe"
```

### B. Certificate in the Windows store (by thumbprint)

```powershell
signtool sign /fd SHA256 `
  /sha1 <CERT-THUMBPRINT-NO-SPACES> `
  /tr http://timestamp.digicert.com /td SHA256 `
  "bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe"
```

### C. EV cert on hardware token (by subject name)

```powershell
signtool sign /fd SHA256 `
  /n "Your Cert Subject Name" `
  /tr http://timestamp.digicert.com /td SHA256 `
  "bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe"
```

Token prompts for its PIN during signing.

Alternate timestamp server if DigiCert is unreachable:
`http://timestamp.sectigo.com`.

## Verify

```powershell
signtool verify /pa /v "bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe"
```

Expect `Successfully verified` and a non-empty timestamp line.

## Record the thumbprint

Note the signing cert thumbprint in your release record:

```powershell
(Get-AuthenticodeSignature "bin\Release\net10.0-windows\win-x64\publish\BtcAddress.exe").SignerCertificate.Thumbprint
```

Should also report `Status : Valid`.

## Notes

- **Security:** never commit the `.pfx` or its password to the repo. Keep keys
  off the build machine if possible (token/HSM). This tool handles private keys —
  a compromised signing key lets an attacker ship a trojaned build under your
  identity.
- Order matters: **publish → sign → distribute**. Signing must be the last step;
  any later edit (even re-zipping) requires re-signing.
- SmartScreen reputation builds over download volume for OV certs; EV certs get
  it immediately.

# Crypto golden vectors

Release gate for the .NET Framework 4.0 → .NET 10 migration: crypto output must
stay correct. The original 4.0 binary cannot be built on a modern toolchain, so
there is no byte-for-byte golden binary to diff against. Instead this suite
anchors to **public known-answer vectors** (objective truth, independent of this
codebase) for the standardized paths, and **round-trip self-consistency** for the
Casascius-custom paths (M-of-N split, escrow).

Any failure means a BouncyCastle v1 → v2 migration regression.

## Run

```text
dotnet run --project test/GoldenVectors/GoldenVectors.csproj -c Release
```

Exit code = number of failing vectors (0 = `ALL VECTORS PASSED`). Source:
`test/GoldenVectors/Program.cs`.

## Vectors

### 1. Private key = 0x01 (secp256k1 generator point)

Private key = `0x000…001`. Public point = G. Widely published reference values.

| Check | Expected |
| --- | --- |
| Address (uncompressed) | `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm` |
| WIF (uncompressed) | `5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf` |
| Pubkey (uncompressed) | `0479BE667E…FFB10D4B8` (65 bytes, `04` prefix) |
| Address (compressed) | `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` |
| WIF (compressed) | `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn` |
| Pubkey (compressed) | `0279BE667E…16F81798` (33 bytes, `02` prefix) |

Exercises: EC scalar mult (`G.Multiply`), point compression both ways,
SHA256+RIPEMD160 (Hash160), Base58Check, WIF encoding.

### 2. Base58Check leading-zero handling

- Version `0x00` + 20 zero bytes → `1111111111111111111114oLvT2` (all-zero address).
- `00 00 12 34 56 78 9a` survives encode → decode unchanged.

Exercises: leading-zero (`1`) preservation, checksum round-trip.

### 3. Casascius mini private key

Mini key `S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy` →
priv `4C7A9640C72DC2099F23715D0C8A0D8A35F8906E3CAB61DD3F78B67BF887C9AB`.

Exercises: mini-key SHA256 derivation + `?`-suffix typo check.

### 4. BIP38 no-EC-multiply (BIP-0038 spec vector 1)

Deterministic (passphrase + key only), so the encrypted key is matched
byte-for-byte against the spec.

| Field | Value |
| --- | --- |
| Passphrase | `TestingOneTwoThree` |
| WIF | `5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR` |
| Encrypted | `6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg` |

Checks: encrypt produces the spec string; decrypt of that string recovers the
WIF. Exercises: scrypt (CryptSharp), AES, the most security-sensitive path.

### 5. BIP38 EC-multiply (round-trip)

Owner passphrase `Satoshi`, random owner entropy → intermediate code →
encrypted key + confirmation code → decrypt. Checks confirmation code
generated, decrypt succeeds, and the address from encrypt side == decrypt side.
Random per run (no fixed spec string), so self-consistency only.

### 6. M-of-N split / combine (2-of-3)

Generate random 2-of-3, split into 3 parts. Every 2-part subset `{0,1}`,
`{1,2}`, `{0,2}` recombines to the **same** address, and that address equals the
generated one. Exercises BigInteger secret-splitting math.

### 7. Escrow code round-trip

Generate escrow set → derive payment address from invitation code A → recover
the payment address from an invitation code + payment invitation code. Recovered
address must equal the derived one. Exercises BigInteger escrow math.

## Notes

- RNG remains BouncyCastle `SecureRandom` (unchanged from the 4.0 source).
- Compression args on every `ECPoint.GetEncoded(bool)` were re-derived during the
  BC v2 migration; BC v1 `Multiply()` returned uncompressed points, which the
  uncompressed BIP38/escrow vectors above confirm.

# The `.pcipher` file format, version 1

A `.pcipher` file is one file encrypted on the user's device by Potent Cipher. The format is open so anyone can write a compatible tool. The reference implementation is `crates/core/src/pcipher.rs`, and every build must pass the round-trip and tamper tests in that file.

## Primitives
- **Content encryption:** XChaCha20-Poly1305 in the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár), with a 19-byte nonce prefix, a 32-bit big-endian counter and a one-byte last-block flag. This is RustCrypto's `aead::stream::EncryptorBE32`.
- **Passphrase key (mode 1):** Argon2id (version 0x13, 32-byte output) of the UTF-8 passphrase with the header salt and the header parameters. Then HKDF-SHA256 with the same salt and info `pc/v1/pcipher` derives the file key.
- **Vault key (mode 2):** HKDF-SHA256 of the 32-byte vault key, with the header salt as the HKDF salt. The info is `pc/v1/pcipher-vault` followed by the vault id as a length-prefixed part (u32 little-endian length, then the UTF-8 bytes).

## Header (73 bytes)
| Offset | Size | Field |
|---|---|---|
| 0 | 7 | Magic `PCIPHER` (ASCII) |
| 7 | 1 | Format version, `1` |
| 8 | 1 | Mode: `1` passphrase, `2` vault key |
| 9 | 1 | KDF id: `1` Argon2id in mode 1, `0` in mode 2 |
| 10 | 4 | Argon2id memory in KiB (u32 LE), `0` in mode 2 |
| 14 | 4 | Argon2id iterations (u32 LE), `0` in mode 2 |
| 18 | 4 | Argon2id parallelism (u32 LE), `0` in mode 2 |
| 22 | 16 | Salt |
| 38 | 8 | Key id: in mode 2, the first 8 bytes of SHA-256 of the vault id; zeros in mode 1 |
| 46 | 4 | Chunk size in bytes (u32 LE), 4 KiB to 16 MiB; default 1 MiB |
| 50 | 4 | Metadata length in bytes (u32 LE), at most 64 KiB |
| 54 | 19 | STREAM nonce prefix (random) |

Readers must reject Argon2id parameters below 19 MiB of memory or 2 iterations, and above 1 GiB, 10 iterations or 8 lanes. This stops a crafted file from making the key weak or exhausting the device.

## Body
Every segment is a STREAM message whose associated data is the whole 73-byte header. Each segment is its plaintext plus a 16-byte tag.
1. **Metadata segment** (counter 0, not last): the metadata, `metadata length` bytes. Potent Cipher writes UTF-8 JSON `{"name": "...", "type": "...", "size": n}`, so the original file name is never stored in the clear.
2. **Content segments:** the file in chunks of exactly `chunk size` bytes, each one *not last*.
3. **Final segment:** the remaining 0 to `chunk size` bytes, marked *last*. An empty file still has a final segment holding just the tag.

A decryptor holds back one segment until it knows whether more bytes follow. It fails if the final segment is missing or wrong (truncation), if segments are reordered or changed, or if the header changed.

## Errors a reader reports
- Wrong passphrase or vault key: the metadata segment fails to decrypt.
- Damaged or truncated file: a later segment fails.
- Not a `.pcipher` file, or an unknown version or mode: the header check fails.

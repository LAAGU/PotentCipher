# potent-cipher-core

The cryptography of Potent Cipher: the key hierarchy (passphrase -> Argon2id -> master key -> vault keys -> item keys), item encryption bound to item and vault ids, the streaming `.pcipher` file format, recovery keys, device hand-over and escrow sealing. It runs only on the user's device (WebAssembly in the browser, native in the desktop app).

- Primitives: Argon2id, XChaCha20-Poly1305 (STREAM for files), HKDF-SHA256, X25519 sealed boxes, Ed25519, all from audited RustCrypto crates.
- Keys are zeroized when dropped or locked.
- File format: `spec/pcipher.md`.
- Browse it file by file, see where each piece sits in the key flow, and run it live: https://potentcipher.softwaretrinkets.com/open-source

```
cargo test -p potent-cipher-core
```

# Potent Cipher

**A zero-knowledge vault for passwords, API keys, secrets and files, plus instant account switching.** Everything is encrypted on your own device before it leaves it. Our servers only ever store ciphertext: we can't read your vault, and neither can anyone who breaks into us.

Website: **https://potentcipher.softwaretrinkets.com**

This repository holds:

- **The desktop app releases** for Windows (see [Download](#download)).
- **The cryptography core** (`crates/core`): the one implementation of every cryptographic operation Potent Cipher performs, in the browser (as WebAssembly) and in the desktop app (natively). Open so anyone can check it.
- **The `.pcipher` file format** (`spec/pcipher.md`): an open format, so your encrypted files never depend on us.

## Download

Get the latest Windows installer from the [Releases](https://github.com/LAAGU/PotentCipher/releases/latest) page (`PotentCipher_x64-setup.exe`), or from the [download page](https://potentcipher.softwaretrinkets.com/download) on the website.

- The app updates itself: it checks for a new version shortly after it starts and every few hours, downloads it in the background and asks before installing.
- Every update is signed. The app only installs a file whose signature matches the public key built into it, so a tampered download is refused.
- Windows SmartScreen may warn about an "unknown publisher" the first time. Choose **More info > Run anyway**.

The web app needs no download at all: it works in any modern browser.

## How your data is protected

| Step | What happens |
|---|---|
| Your passphrase | Never leaves your device. **Argon2id** turns it into your master key, slowly and with a lot of memory, so guessing is expensive. |
| Key hierarchy | Master key -> vault keys -> one key per item, each layer wrapped by the one above with **XChaCha20-Poly1305**. |
| Your items | Encrypted with their own key and bound to their item and vault ids, so ciphertext can't be swapped between items. Names, notes and file names are encrypted too, not just the values. |
| Files | Encrypted in chunks (XChaCha20-Poly1305 STREAM), so large files never need to fit in memory and any change, cut or reordering is detected. |
| New devices | Approved from a device you already use: the key is handed over in an **X25519** sealed box that only the new device can open. |
| Recovery | A recovery key you keep, and an optional assisted recovery you switch on yourself. |
| Keys in memory | Zeroized when they are no longer needed and when the vault locks. |

All primitives (Argon2id, XChaCha20-Poly1305, HKDF-SHA256, X25519, Ed25519) come from the audited [RustCrypto](https://github.com/RustCrypto) and dalek crates. Nothing is invented here.

Read the code file by file, see where each piece sits in the key flow and run it live in your browser: **https://potentcipher.softwaretrinkets.com/open-source**

## The `.pcipher` format

Any file can be encrypted with a passphrase in the website's free [Encrypt a file](https://potentcipher.softwaretrinkets.com/encrypt) tool or in the desktop app, without an account. The result is a `.pcipher` file. Its format is fully documented in [`spec/pcipher.md`](spec/pcipher.md), with the reference implementation in [`crates/core/src/pcipher.rs`](crates/core/src/pcipher.rs), so anyone can write a compatible tool.

## Build and test the core

You need [Rust](https://rustup.rs) (stable).

```
cargo test
```

The tests cover the key hierarchy, unlock and recovery, published test vectors (HKDF, TOTP), the file format round trip, and that a wrong passphrase, a changed or cut-off file, an item moved to another id, or a file header asking for weakened key settings is refused.

## Reporting a security issue

Please don't open a public issue. Write to **support@softwaretrinkets.com** with the details and how to reproduce it. We answer every report.

## License

The core and the specification are licensed under the [Apache License 2.0](LICENSE).

Made by [Software Trinkets](https://softwaretrinkets.com).

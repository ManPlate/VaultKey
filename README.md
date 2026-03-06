<div align="center">

<img src="https://raw.githubusercontent.com/ManPlate/Marai/main/marai_logo.svg" alt="Marai Logo" width="120" height="120"/>

# Marai

### Offline Password Manager for Windows

*Marai* (மறை) — an ancient Tamil word from Sangam literature meaning **"that which is hidden"**.
Sacred knowledge concealed from the world, accessible only to those who hold the key.

---

[![Version](https://img.shields.io/badge/version-2.1.0-7c5cfc?style=flat-square)](https://github.com/ManPlate/Marai/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square&logo=windows)](https://github.com/ManPlate/Marai/releases)
[![License](https://img.shields.io/badge/license-MIT-4ecca3?style=flat-square)](LICENSE)
[![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-fc5c7d?style=flat-square)](#security)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-fc5c7d?style=flat-square)](#security)

**[⬇️ Download Latest Release](https://github.com/ManPlate/Marai/releases)** &nbsp;·&nbsp;
**[📋 View Changelog](#version-history)** &nbsp;·&nbsp;
**[🛠️ Build from Source](README_DEV.md)**

</div>

---

## What is Marai?

Marai is a **fully offline**, open source password manager for Windows. Your passwords are encrypted locally on your machine using military-grade encryption — no cloud, no accounts, no subscriptions, no internet connection required. Ever.

> Your data never leaves your computer. Not even once.

---

## Features

### 🔐 Security First
| Feature | Detail |
|---|---|
| **AES-256-GCM Encryption** | Authenticated encryption — detects tampering as well as encrypting |
| **Argon2id Key Derivation** | Memory-hard KDF — resists GPU and specialised hardware brute force attacks |
| **Zero Knowledge** | Master password is never stored — used only to derive the encryption key |
| **Clipboard Protection** | Copied passwords never appear in Windows clipboard history (Win+V) |
| **Auto-Lock** | Vault locks automatically after 5 minutes of inactivity |
| **Login Lockout** | 5 failed attempts triggers a 30-second cooldown |
| **Fully Offline** | No network requests except optional update checks |

### 🗂️ Password Management
- Organise entries by category — **Work, Email, Social, Finance, Dev, Other**
- Instant search across all entries
- Password strength meter — see how strong any password is at a glance
- Built-in password generator with customisable length and character sets
- Show/hide individual passwords
- One-click copy to clipboard
- Edit and delete entries

### 🔑 Vault Management
- Change master password — re-encrypts the entire vault with the new key
- Automatic update checker — notifies you when a new version is available
- Vault stored locally at `C:\Users\YourName\.marai\`

---

## Download

<div align="center">

### **[⬇️ Download Marai.exe](https://github.com/ManPlate/Marai/releases/latest)**

No installation required. Download and double-click to run.

</div>

> **⚠️ Windows SmartScreen Warning**
> Windows may show "Windows protected your PC" when you first run Marai.
> This happens because the app is not yet code-signed.
> Click **More info → Run anyway** to proceed. This is safe.

---

## Security

Marai is built on a foundation of well-established, auditable cryptographic primitives. No custom cryptography — only battle-tested standard libraries.

### Encryption
```
Algorithm:    AES-256-GCM  (authenticated encryption)
IV:           96-bit random, generated fresh per encryption
Library:      Python cryptography (built on OpenSSL)
```

### Key Derivation
```
Algorithm:    Argon2id  (OWASP recommended)
Memory:       64 MB
Iterations:   3
Parallelism:  4 threads
Hash length:  256-bit
Salt:         128-bit random, unique per vault
```

### Vault Storage
```
Location:     ~/.marai/vault.enc
Format:       AES-256-GCM encrypted JSON
Meta:         ~/.marai/meta.json  (salt + verification token — no plaintext)
```

### Threat Model
| Threat | Protection |
|---|---|
| Someone steals your vault file | AES-256-GCM + Argon2id makes brute force impractical |
| Shoulder surfing | Auto-lock after 5 minutes of inactivity |
| Clipboard snooping | Passwords excluded from Windows clipboard history |
| Brute force login | 5-attempt lockout with 30-second cooldown |
| Network interception | Not applicable — fully offline |

### Honest Limitations
- Decrypted passwords exist in RAM while the vault is unlocked. This is a fundamental Python limitation shared by all Python-based password managers. Mitigated by auto-lock.
- The `.exe` is not yet code-signed. Windows SmartScreen will warn on first run.

---

## Version History

<!-- VERSION_TABLE_START -->
| Version | What's New |
|---|---|
| **v2.2.0** ← current | Favourite entries and password age indicator |
| **v2.1.0** | Upgraded to Argon2id key derivation — silent migration on login |
| **v2.0.0** | Rebranded from VaultKey to Marai |
| **v1.7.0** | Passwords never enter Windows clipboard history (Win+V) |
| **v1.6.0** | Added automatic update checker |
| **v1.5.0** | Security hardening: lockout, auto-lock, clipboard clear |
| **v1.4.0** | Added password generator with strength meter |
| **v1.3.0** | Added ability to change master password |
| **v1.2.0** | Fixed card layout and resize behaviour |
| **v1.1.0** | Fixed compatibility with Python 3.14 on Windows |
| **v1.0.0** | Initial release |
<!-- VERSION_TABLE_END -->

---

## How to Update

1. Download the new `Marai.exe` from [Releases](https://github.com/ManPlate/Marai/releases)
2. Replace the old `Marai.exe` with the new one — that is all
3. Your passwords are completely safe — stored separately in `~/.marai/`

> Updating from an older version? Security upgrades (like the Argon2id migration in v2.1.0) happen automatically and silently on your first login after updating. No action needed.

See [HOW_TO_UPDATE.md](HOW_TO_UPDATE.md) for full step-by-step instructions.

---

## Backup & Portability

Your vault is fully portable. It is stored in just two files — no database, no cloud, no account.

```
C:\Users\YourName\.marai\vault.enc   ← encrypted passwords
C:\Users\YourName\.marai\meta.json   ← salt and verification token
```

### How to back up your vault

1. Navigate to `C:\Users\YourName\.marai\`
2. Copy both `vault.enc` and `meta.json` to a safe location — USB drive, external hard drive, or encrypted cloud storage
3. That's it — both files together are your complete backup

### How to move your vault to a new machine

1. Install Marai on the new machine
2. Create the folder `C:\Users\YourName\.marai\` if it doesn't exist
3. Copy `vault.enc` and `meta.json` into that folder
4. Launch Marai and enter your master password as normal — everything will be there

> **Why this works:** Marai's encryption is based entirely on your master password and the salt in `meta.json`. There is nothing machine-specific involved. Your vault will open on any machine running Marai, anywhere in the world, as long as you know your master password.

> **Security note:** Anyone who obtains both files can attempt to brute force your master password offline. This is why a strong master password matters — and why Marai uses Argon2id to make brute force attacks as slow and expensive as possible.

---

## For Developers

Want to audit the code, build from source, or contribute?

See **[README_DEV.md](README_DEV.md)** for full setup and build instructions.

The entire cryptographic implementation is contained in four functions at the top of `marai.py` — fully readable and auditable in under 5 minutes.

---

<div align="center">

Built with Python + tkinter &nbsp;·&nbsp; Encryption by [cryptography](https://cryptography.io) (OpenSSL) &nbsp;·&nbsp; KDF by [argon2-cffi](https://argon2-cffi.readthedocs.io)

*Marai — hidden by design.*

</div>

# 🔐 VaultKey — Offline Password Manager

A standalone desktop password manager. No browser needed. No internet. No accounts.
All data is encrypted with AES-256-GCM and stored only on your machine.

Download VaultKey [here](https://github.com/ManPlate/VaultKey/raw/49221719933d8e75e7b63a3988152dd75d2f14ce/dist/VaultKey.exe)
---

## 🔒 First Launch

On first run, you'll be asked to create a **Master Password**.
This password encrypts everything — **there is no recovery option if you forget it.**

---

## 📁 Where is my data stored?

All encrypted vault data is stored in:
- **Windows:** `C:\Users\<YourName>\.vaultkey\`
- **Mac/Linux:** `~/.vaultkey/`

The files are encrypted — they cannot be read without your master password.

---

## 📦 Package as a Standalone App (Optional)

To create a double-clickable `.exe` (Windows) or `.app` (Mac):

```
pip install pyinstaller
pyinstaller --onefile --windowed --name VaultKey vaultkey.py
```

The standalone file will appear in the `dist/` folder.

---

## 🔐 Security

- **Encryption:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 390,000 iterations
- **Salt:** 16-byte random salt per vault
- **No telemetry. No network calls. Fully offline.**

---

## 📦 Version History

| Version | Notes |
|---|---|
| **v1.3.0** | Added ability to change master password |
| **v1.2.0** | Fixed card layout and resize behaviour |
| **v1.1.0** | Fixed compatibility with Python 3.14 on Windows |
| **v1.0.0** | Initial release |

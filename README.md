# 🔐 VaultKey — Offline Password Manager

A standalone desktop password manager. No browser needed. No internet. No accounts.
All data is encrypted with AES-256-GCM and stored only on your machine.

---

## 📋 Requirements

- Python 3.8 or higher (free download: https://www.python.org/downloads/)
- Windows, macOS, or Linux

---

## 🚀 Quick Start (3 steps)

**Step 1 — Install Python** (if you don't have it)
Download from https://www.python.org/downloads/ and install.
➡ On Windows: check "Add Python to PATH" during install.

**Step 2 — Install dependencies**
Open Terminal (Mac/Linux) or Command Prompt (Windows), navigate to this folder, and run:

```
pip install -r requirements.txt
```

**Step 3 — Launch the app**
```
python vaultkey.py
```

Or on Windows, double-click `run_windows.bat`
Or on Mac/Linux, double-click `run_mac_linux.sh` (may need to chmod +x it first)

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
| **v1.2.0** | Fixed card layout and resize behaviour |
| **v1.1.0** | Fixed compatibility with Python 3.14 on Windows |
| **v1.0.0** | Initial release |

# 🛡️ SecureVault - Portable Password Manager

SecureVault is a secure, single-file, offline-first password manager designed for portability. It runs entirely in your web browser with zero external dependencies, no internet required, and zero tracking.

## ✨ Key Features
- **Military-Grade Encryption:** Uses AES-256-GCM authenticated encryption for all data.
- **Hardened Key Derivation:** PBKDF2 with 600,000 iterations (OWASP recommended) to protect against brute-force.
- **Zero-Trace Architecture:** No sensitive data is stored in the browser's persistent storage (LocalStorage/IndexedDB). Everything stays in volatile memory until you save it to a file.
- **Privacy First:** Completely offline. No telemetry, no cloud sync, no "calling home."
- **Portable:** A single HTML file that works on any modern desktop or mobile browser.

## 🚀 Quick Start Guide
1. **Open the App:** Open the `index.html` file in any modern web browser.
2. **Create Vault:** On your first run, enter a strong **Master Password** to initialize your vault.
3. **Add Entries:** Use the "Vault" tab to add your accounts, usernames, and passwords.
4. **💾 Save Your Data:** Click the **Save** button. This will download a file named `my_passwords.vault`.
5. **Secure Your File:** Move your `.vault` file to a secure location, such as an encrypted thumbdrive.

## 🔓 Accessing Your Existing Vault
1. Open the `index.html` file.
2. Click **Load Vault File** and select your `.vault` file.
3. Enter your **Master Password** to decrypt and view your passwords.

## 🛡️ Security & Privacy
- **No Recovery:** If you lose your Master Password or delete your `.vault` file, your data **cannot** be recovered.
- **Auto-Lock:** The vault automatically locks after 5 minutes of inactivity (adjustable in Settings).
- **Clipboard Protection:** Copied passwords are automatically cleared from your clipboard after 30 seconds.
- **Export Options:** You can export your data to unencrypted JSON or CSV formats from the Settings tab for easy backup or migration.

## 🛠️ Tech Stack
- Vanilla HTML5 / CSS3
- Vanilla JavaScript (Web Crypto API)
- Zero external libraries or frameworks.

## 📄 License
This project is open-source and available under the [MIT License](LICENSE).

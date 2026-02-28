# SecureVault: Portable Password Manager

A secure, single-file, offline password manager designed for portability on thumbdrives.

## Project Overview
- **Type:** Web-based (HTML/JS) Local Application
- **Tech Stack:** Vanilla HTML5, Vanilla CSS3, Vanilla JavaScript (Web Crypto API)
- **Portability:** No external dependencies, no internet required, runs in any modern browser (Desktop & Mobile).

## Key Features
- **AES-256-GCM Encryption:** Military-grade authenticated encryption for all vault data.
- **PBKDF2 Key Derivation:** Uses 100,000 iterations with a unique salt to protect against brute-force attacks.
- **Password Generator:** Customizable length and character sets (Uppercase, Numbers, Symbols).
- **Auto-Lock Timer:** Automatically clears memory and locks the vault after a period of inactivity (default 5m).
- **Category Management:** Organize entries into General, Work, Social, and Banking.
- **CSV Import:** Support for importing existing passwords from other managers.
- **Dark/Light Mode:** User-selectable themes saved locally.
- **Zero-Trace Architecture:** No data is stored in the browser's persistent storage (LocalStorage/IndexedDB) except for UI preferences (theme). All sensitive data remains in volatile memory until saved to a file.

## Usage Instructions
1. **Initial Setup:** Open `index.html` and click "Create Vault" to set a Master Password.
2. **Adding Entries:** Use the "Vault" tab to add service names, usernames, and passwords.
3. **Saving:** Click **💾 Save**. The browser will download `my_passwords.vault` to your **Downloads** folder.
   - *CRITICAL:* Manually move this `.vault` file to your thumbdrive.
4. **Loading:** Open the HTML file, click **Load Vault File**, select your `.vault` file, and enter your Master Password.
5. **Portability:** You can copy `index.html` to any device. It will always open as a blank vault unless you load your specific `.vault` file.

## Security Mandates
- **Master Password:** Must be strong and unique. It is the only way to derive the encryption key.
- **No Recovery:** If the Master Password is forgotten or the `.vault` file is deleted, data recovery is impossible.
- **Backups:** Users are encouraged to keep copies of their `.vault` file in multiple secure locations (Second thumbdrive, encrypted cloud storage).

## Future Enhancement Ideas
- [ ] QR Code login support.
- [ ] TOTP (2-Factor Authentication) generator.
- [ ] Custom categories.
- [ ] PWA Manifest for "Home Screen" installation on Android/iOS.

# 🛡️ SecureVault — Portable Password Manager & 2FA Authenticator

SecureVault is an offline-first, single-file password manager and 2FA authenticator designed for zero-trust portability, sovereign data ownership, and high-density executive aesthetics.

It runs entirely in your web browser with **zero external runtime dependencies**, **no server backends**, and **zero telemetry**. The entire application — cryptography, live TOTP generator, password health auditor, fonts, and UI — compiles into a single, standalone `index.html` file (~1 MB).

---

## 🎯 Who Is SecureVault For?

If you just want convenient cloud autofill across everyday consumer apps and don't mind third-party server hosting, standard cloud managers (Bitwarden, 1Password) work well. **SecureVault is built for scenarios where cloud managers fail, are forbidden, or pose single-point-of-failure risks:**

1. **Air-Gapped & Restricted Field Operations (Maritime, Defense, Gov, ICS):**
   - Workstations or field laptops on isolated networks, ships, or command centers where cloud sync is blocked by policy or lack of connectivity.
   - Requires zero installation, no admin rights, and no internet. Copy `index.html` and `my_passwords.vault` to a secure USB drive and run on any machine.
2. **Sysadmins & Self-Hosters ("Break-Glass" Emergency Disaster Recovery):**
   - Solves the bootstrapping dilemma: when your self-hosted server, NAS, Proxmox cluster, or network goes down, your recovery SSH keys, root passwords, and TOTP 2FA seeds are safe in an offline, portable vault.
3. **Sovereign-Data & Zero-Cloud Users ($0 Infrastructure):**
   - No multi-tenant cloud servers to be breached; no 24/7 VPS/Docker stacks to maintain. Your data lives in an encrypted `.vault` file with optional 1-click push/pull sync to your private GitHub repository via REST API.
4. **Portable 2FA & Migration Ledger:**
   - Full-fidelity import from **Bitwarden** (`.json`/`.csv`) and **KeePass 2.x / KeePassXC** (`.xml`/`.csv`). Serves as an independent offline replica and password-health auditor.

---

## ✨ Features & Architecture

### 🔒 Cryptographic Baseline
- **AES-256-GCM:** Authenticated symmetric encryption for all vault data payloads.
- **Hardened Key Derivation:** PBKDF2-SHA256 with 600,000 iterations (OWASP benchmark baseline) to resist brute-force attacks.
- **Volatile Session Decryption:** Decrypted data exists only in memory; locked sessions wipe cryptographic keys and transient data immediately.
- **Anti-Leak Protections:** Inactivity auto-lock timer (configurable 1–60m) with live visual progress bar; 30-second clipboard auto-clear countdown.

### 📱 Rich Entry Types
- **Logins:** Username/email, password, live 2FA TOTP badge, URL/service matching.
- **Payment Cards:** Cardholder name, card number (masked/revealable/copyable), expiry date (`MM/YY`), and CVV code.
- **Identity Documents & Secure Notes:** Full name / holder, document number, and encrypted multi-line secure notes.
- **SSH & API Keys:** Key labels, fingerprint/public key, and private key / secret token ledger.
- *Scoped Auditing:* Password strength, reuse, and length vulnerability metrics are strictly scoped to login credentials, avoiding false alerts on card numbers or documents.

### ⏱️ RFC 6238 Offline TOTP Generator
- Built-in Web Crypto HMAC-SHA1 2FA code generator.
- Live 30-second countdown badge with automatic expiration warning.
- Supports both raw Base32 secret keys and `otpauth://totp/...` standard URIs.
- Click-to-copy TOTP codes directly from vault cards.

### 🧠 Pattern-Aware Password Strength Scorer
- Embedded zxcvbn-style pattern engine (~3.5 KB, zero dependencies).
- Accurately discounts:
  - Common dictionary roots and password stems.
  - L33tspeak substitutions (`p@ssw0rd`, `4dm1n`).
  - Spatial keyboard walks (`qwerty`, `asdfgh`).
  - Alphanumeric sequences (`abcde`, `12345`).
  - Repeated character clusters (`aaa`, `888`).
  - Calendar years (`1980`–`2029`).

### 📥 Universal High-Fidelity Import
- **Bitwarden Import (`.json` / `.csv`):**
  - Preserves folders by automatically mapping them to SecureVault categories.
  - Imports Logins, Cards (with expiry/CVV), Identities, Secure Notes, and TOTP seeds.
  - Handles username-only credentials and raw JSON payloads.
- **KeePass 2.x / KeePassXC (`.xml` / `.csv`):**
  - Maps `<Group>` hierarchy directly to categories.
  - Extracts `<History>` revisions to prevent stale duplicate entries.
  - Decodes XML entities and extracts `otp` / `TOTP Seed` fields.

### 🎨 Executive Design System & Micro-Interactions
- **`interior.dev`-Inspired Floating Labels:** Labels make room smoothly on focus or when filled via GPU transform (`translate3d`), reserving a dedicated 20px top slot so layouts never shift.
- **Sliding-Thumb Segmented Control:** Modal type tabs (`Login · Card · Identity · SSH Key`) feature a sliding thumb with real-time clipped text inversion across cell boundaries.
- **Single-Surface Focus Glow:** Clean single-box focus ring without nested container double-borders.
- **Top-Anchored Modal:** Dialog position is anchored along the Y-axis so switching entry types dynamically expands/contracts only downward, eliminating cursor jumping.
- **Dual Themes:** **Warm Editorial** light mode (`editorial-light`, archival cream) and **Midnight Executive** dark mode (`executive-dark`, obsidian slate).

### ⚡ Browser Extension (Manifest V3)
- Dedicated browser toolbar popup extension in `extension/`.
- Active-tab domain matching and 1-click in-page credential autofill for Chrome, Brave, and Edge.

---

## 🚀 Quick Start

### Option A: Standalone Single-File (Recommended)
1. Open `index.html` in any web browser.
2. Set a **Master Password** to create a new vault, or click **Unlock** to access an existing vault stored in browser local storage.
3. Click **Save** in the top navigation bar to download your encrypted `my_passwords.vault` backup.

### Option B: Windows App Launcher
Double-click `Launch-SecureVault.bat` to run SecureVault in a dedicated, frameless desktop application window.

### Option C: Browser Extension
Load the `extension/` directory as an unpacked extension via `chrome://extensions` (or `edge://extensions`) for toolbar integration and form autofill.

---

## 🛠️ Build & Verification

SecureVault adheres to strict dependency minimization: zero runtime packages and single-file bundling via standard Node.js scripts:

```bash
# Build single-file artifact (src/ -> index.html)
npm run build

# Run unit & regression test suite (13 passing tests)
npm test
```

Test suite covers:
- RFC 4648 Base32 decode & validation.
- RFC 6238 TOTP HMAC code generation.
- Pattern-aware password entropy calculation & rating.
- AES-GCM encryption/decryption round-trip.
- KeePass XML & Bitwarden JSON/CSV parser integrity.
- HTML event handler linkage to top-level app functions.
- Inlined bundle script syntax verification (prevents `$` substitution corruption).

---

## 📄 License
Open-source under the [MIT License](LICENSE).

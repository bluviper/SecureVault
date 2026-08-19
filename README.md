# 🛡️ SecureVault — Portable Password Manager (V2.0 Executive Edition)

SecureVault is a secure, single-file, offline-first password manager designed for zero-trust portability and high-density executive aesthetics. It runs entirely in your web browser with zero external dependencies, no server backends, and zero telemetry.

---

## ✨ Highlights & Features

- **🔒 Military-Grade Encryption:** AES-256-GCM authenticated encryption for all vault payloads.
- **🛡️ Hardened Key Derivation:** PBKDF2 with 600,000 iterations (OWASP recommendation) to resist brute-force attacks.
- **📦 Single-File Portability:** Everything (HTML, CSS, JS, and typography) is bundled into a single standalone `index.html` file (~999 KB) that runs offline on any desktop or mobile browser.
- **🎨 21st.dev Design System & Dual Themes:**
  - **Animated Glow Feature Card:** Login screen featuring a continuous rotating conic light beam border and dark background mask.
  - **Squircle Logo Enclosure:** High-contrast squircle logo framed by a vibrant orange border and tight slate-500 micro-dot matrix pattern.
  - **Dual Themes:** **Warm Editorial** light theme (`editorial-light`, archival cream) and **Midnight Executive** dark theme (`executive-dark`, obsidian slate).
  - **Dense Desktop Ledger:** Scaled `JetBrains Mono` typography for clear `I`/`l`/`1` & `O`/`0` glyph distinction, permanent interaction controls (no hover hunting), and inline password reveal toggles.
- **⚡ Browser Extension (Manifest V3):** Dedicated popup vault with active-tab domain matching and active form autofill (`extension/`).
- **☁️ $0 Encrypted Cloud Sync:** Optional 1-click push/pull sync to a private GitHub repository via REST API.
- **🖥️ Native Desktop Launcher:** Includes `Launch-SecureVault.bat` for launching as a frameless, standalone desktop app on Windows.
- **⏱️ Auto-Lock & Anti-Leak:** Volatile in-memory session decryption, 5-minute inactivity auto-lock, and 30-second clipboard auto-clear.

---

## 🚀 Quick Start

### Option A: Standard Single-File Use
1. Open [index.html](file:///D:/ai-playgrnd/secVault/index.html) in any web browser.
2. Set a **Master Password** to initialize a new vault, or click **Unlock** if a vault payload is saved in local storage.
3. Click **Save** to export your encrypted `.vault` file to disk or USB drive.

### Option B: Windows Desktop App Mode
Double-click `Launch-SecureVault.bat` to launch SecureVault as a standalone desktop app window using Microsoft Edge / Chrome.

### Option C: Browser Extension
Load the `extension/` directory as an unpacked extension in Chrome/Edge (`chrome://extensions`) for toolbar access and ⚡ autofill.

---

## 🛠️ Development & Building

SecureVault uses a zero-dependency ESM build script:

```bash
# Build single-file bundle (src/ -> index.html)
node build.js

# Build in watch mode
node build.js --watch

# Run unit test suite (crypto, parsers, XSS helpers, handler maps)
npm test
```

---

## 📄 License
Open-source under the [MIT License](LICENSE).

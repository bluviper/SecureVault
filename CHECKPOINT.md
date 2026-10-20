# CHECKPOINT — SecureVault (2026-10-20)

Backtrackable snapshot. Read this before resuming work. Supersedes guessing from code alone.

## Current state
- **Branch:** `master` (tracks `origin/master`), clean working tree — no uncommitted code changes.
- **Version:** 2.0.0. Pure web app + Manifest V3 browser extension. Zero runtime dependencies.
- **Crypto:** AES-256-GCM + PBKDF2-SHA256 @ 600,000 iterations. One-shot GitHub REST push/pull of a single encrypted `.vault` file.
- **Build:** `node build.js` inlines `src/` → `index.html`, stripping `export {}`. Tests: `npm test`.
- **Scratch dirs (untracked, safe to delete):** `.tmp_apk_analysis/`, `.tmp_apkm_analysis/`.

## Decided roadmap (priority order)
1. **TOTP generator** — DONE. Pure JS (`base32ToUint8`, `parseTotpInput`, `generateTOTP` via Web Crypto HMAC), zero deps, live 30s countdown badge, supports raw Base32 and `otpauth://` URIs.
2. **zxcvbn strength** — DONE. Replaced naive charset heuristic with `analyzePasswordEntropy` in `src/app.js` (discounts common stems, l33tspeak, keyboard/alphanumeric sequences, repeats, and years in ~3.5 KB with zero dependencies).
3. **Argon2id KDF** — SKIPPED (Deliberate). Kept PBKDF2-SHA256 @ 600,000 iterations (OWASP baseline) to preserve zero-dependency single-file Web Crypto + Native Android `javax.crypto` compatibility without WASM/JNI overhead.
4. **KeePass import (`.xml` / `.csv`)** — DONE. Added `parseKeePassXML` (with folder-to-category mapping, TOTP, and `<History>` revision stripping) plus KeePass CSV header mapping in `src/app.js`.
5. **Rich entry types (card/identity/ssh)** — DONE. Added `login`, `card` (with Expiry + CVV), `identity`, and `ssh` entry types in `src/index.html` and `src/app.js`, with type badges, scoped password-health metrics (`isLoginEntry`), and Bitwarden/SecureVault JSON import support.

## Ruled out — architecture mismatches, do NOT attempt
- **Native AutofillService / CredentialProviderService** — Android-only; a browser can't host them. Content-script autofill (`extension/content/content.js`) is the ceiling for this architecture.
- **Passkey / WebAuthn ceremony** — issuing/asserting passkeys needs a relying server. Offline-only SecureVault can store passkeys, not issue them.
- **Biometric unlock** — no web API unlocks a local vault with a fingerprint. Would need a native wrapper (Electron/Tauri) SecureVault doesn't have.

## Key constraints
- Zero-dependency single-file identity is a stated feature; justify any new library and keep it small.
- Offline-first: nothing in the adoptable list touches the network.
- `tests/crypto.test.js` has a regression test asserting every `onclick`/`onchange`/`oninput` handler in `index.html` maps to a defined function in `app.js` — new UI must add matching handlers.

## Analysis artifacts
- `bitwarden-new.apkm` = genuine Bitwarden 2026.10.0 (`com.x8bit.bitwarden`, build 21955, apkmirror). Argon2id+PBKDF2, AES-GCM, native AutofillService, WebAuthn/Passkey, YubiKey, TOTP, zxcvbn, kdbx import, rich entry types, Firebase push.
- `bitwarden.apk` (15 MB) is NOT Bitwarden — it is the Uptodown app store (`com.uptodown` v7.41, signed by Uptodown Technologies SL) requesting dangerous permissions (`ACCESS_SUPERUSER`, `INSTALL_PACKAGES`, `DELETE_PACKAGES`, `QUERY_ALL_PACKAGES`) real Bitwarden never would. Do not analyze it as a password manager.
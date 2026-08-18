# Changelog

All notable **architectural** changes to SecureVault are documented here.

> Scope: this changelog captures structural/architectural milestones — *what* changed, *how* it was implemented, and *why*. Routine UI polish and minor bug fixes are omitted unless they alter architecture.

---

## [Unreleased]

### Refactor: code-quality hardening & slimming

- **What** — Completed the strength-token refactor and removed ~60 lines of dead/duplicated code across `src/app.js`, `src/style.css`, and `src/index.html`.
- **How** —
  - Fixed `triggerFileSelect()` / `triggerFileInput()` rename drift (HTML invoked a function the refactor had renamed — clicking *Import .vault File* threw a `ReferenceError`).
  - Renamed strength-fill CSS classes to match the new semantic tokens (`strength-muted/danger/warning/success`) so the generator + modal strength bars actually render; removed the `online` modifier from credential strength dots so `bg-danger/warning/success` color coding works.
  - Collapsed three toast functions (`showToast`, `showCountdownToast`, `updateCountdownToast`) into one `showToast(msg, countdown)`; rewrote `copyCredentialPassword` around a self-contained countdown tick.
  - Slimmed `updateOnlineStatus` to a single templated branch; deleted dead `.strength-indicator-dot` CSS and the hard-coded category `<option>`s (now rebuilt by JS).
  - Added an automated regression test asserting every HTML event handler maps to a defined function — the class of bug that had broken the unlock flow twice.
- **Why** — Earlier refactors (see below) fixed the `escapeHtml` crash and swapped strength classes to tokens but left the CSS fill classes and the `online` modifier out of sync, silently disabling visual strength indicators. This pass closes the loop, guards against handler/definition drift, and keeps the bundle slim.

---

## v2.0.0 — Multi-platform architecture

### Browser extension (Manifest V3)

- **What** — Added an `extension/` package: popup vault, ⚡ autofill, active-tab domain matching, GitHub sync, and four icon themes.
- **How** — MV3 manifest with an `action` popup, a background service worker holding the in-memory decrypted session (`STORE_SESSION`/`GET_SESSION`/`CLEAR_SESSION`), and a `<all_urls>` content script that detects username/password inputs and dispatches native-compatible input/change/blur events for React/Vue forms.
- **Why** — Extends the single-file app into the browser's native context (toolbar, autofill on any site) while keeping all vault crypto client-side.

### Lock screen orientation: saved-vault auto-detect + local persistence

- **What** — The lock screen now detects a previously saved vault and offers explicit Create/Unlock mode toggles; encrypted state persists to `localStorage`.
- **How** — `checkSavedVault()` reads `securevault_encrypted_payload` (salt + IV + AES-256-GCM ciphertext) and routes to the unlock or init prompt; `persistEncryptedVault()` writes it back on every vault mutation; `showInitPrompt()` / `showUnlockPrompt()` replace the old hard-coded prompt swap.
- **Why** — Removes the "vault file or no vault" ambiguity on every load and makes the app resume-friendly; only ciphertext ever touches disk, so the master password stays the sole secret.

### Code-quality refactor

- **What** — Fixed the `escapeHtml` `ReferenceError` that broke unlock, isolated clipboard auto-clear, mapped strength classes to semantic CSS tokens, deduplicated base64 handling, and passed 7/7 tests.
- **How** — Added the missing `escapeHtml` helper (now exported + unit-tested); introduced `getReusedPasswordSet()` to replace the mutating `detectPasswordReuse()` (so derived flags no longer serialize into the `.vault`); moved toast auto-hide onto its own `toastHideTimeout` so generic toasts can't cancel the 30s clipboard wipe; reused `uint8ToBase64`/`base64ToUint8` in GitHub push/pull instead of hand-rolled loops; switched strength output from `class` strings to semantic `token` values (`muted/danger/warning/success`).
- **Why** — The app could not be unlocked (correct password was rejected with "Invalid master password"), clipboard-clearing could silently not happen, and derived data was leaking into the encrypted payload. Token-based strength also unblocks the CSS dedup below.

---

## v2.0.0-rc — Feature build-out

### GitHub REST API 1-Click Cloud Sync

- **What** — $0 cloud backup: push/pull the encrypted `.vault` payload directly to a GitHub repo.
- **How** — `pushToGitHub()` re-encrypts, base64-encodes (Unicode-safe), GETs the existing file SHA, then PUTs a new commit; `pullFromGitHub()` decodes, validates structure, and either decrypts immediately (unlocked) or stages for unlock.
- **Why** — Gives a cross-device sync channel without any paid backend; the vault remains end-to-end encrypted so GitHub never sees plaintext.

### Windows launcher

- **What** — Native Windows launcher script + shortcut builder for the desktop.
- **How** — Script opens the single-file app in the default browser as a standalone app-style launch.
- **Why** — Improves the "app on this machine" experience beyond opening a file in a tab.

### Audit-gap hardening

- **What** — Custom category/tag management, dynamic online/offline detection, save ripple feedback, CSV/JSON import unit tests, and export stripping in the build.
- **How** — `defaultCategories` + `getCategories()` power live-updating selects with a custom-category prompt; `updateOnlineStatus()` toggles a Secure-Local/Strict-Offline badge; `build.js` strips `export {}` blocks before inlining `app.js`.
- **Why** — Fills functional gaps surfaced during audit and makes the single-file bundle testable/portable.

### Offline typography: embedded fonts

- **What** — Plus Jakarta Sans & JetBrains Mono embedded as base64 `@font-face` data URIs.
- **How** — `embed-fonts.js` downloads TTF files and emits `src/fonts.css`; `build.js` inlines it into the bundle.
- **Why** — Guarantees pixel-identical typography offline/USB without any runtime font network requests.

---

## v1.x — Initial architecture

### Modular source + build pipeline

- **What** — Moved from a single self-contained file to a `src/` (HTML/CSS/JS) + `tests/` structure with a build step.
- **How** — `build.js` inlines `style.css`, `fonts.css`, and `app.js` into a single portable `index.html`; `npm test` runs Web Crypto/PBKDF2/AES-GCM + parser unit tests against the source via ESM exports; watch mode (`--watch`) rebuilds on change.
- **Why** — Separates authoring (readable modules, testable exports) from distribution (one portable, offline-capable HTML file for hosting, USB, and the extension) while keeping the zero-dependency, offline-first promise.

### Core security architecture

- **What** — The foundational crypto layer and file-based vault model.
- **How** — PBKDF2 (600k iterations, SHA-256) derives an AES-256-GCM key from the master password + random salt; vault data lives only in volatile memory and is written to an encrypted `.vault` file (salt + IV + ciphertext); exports support Bitwarden/LastPass-style CSV/JSON imports and unencrypted JSON/CSV exports; auto-lock and 30s clipboard clearing are built-in.
- **Why** — Zero-trace, file-portable vault: hosting or running from a USB drive never changes where secrets live (only the user's encrypted file does), and there is deliberately no server-side store.

---

## Legend

- **What** — the architectural deliverable
- **How** — the implementation approach
- **Why** — the design rationale / problem solved
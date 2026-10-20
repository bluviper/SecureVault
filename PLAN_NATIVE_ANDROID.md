# SecureVault Native Android — Deployment Plan

## 1. Identity & Shared Format

SecureVault's identity is **"single-file, offline-first, zero-telemetry."** A native build must not dilute it.

- **App label**: **SecureVault**
- **Package**: `com.bluviper.securevault`
- **Tagline**: *"Secure, offline-first, single-file password manager"* (stay distinct; do not rebrand as Bitwarden).
- **Thin-Container Rule**: The native shell handles OS integration (`WebView`, `Keystore`, `BiometricPrompt`, `AutofillService`, `CredentialProviderService`); the UI and vault management remain one shared web codebase.
- **Shared `.vault` Contract**: The boundary between Web (`src/crypto.js`) and Native Android is the `.vault` JSON schema:
  ```json
  { "salt": "<base64>", "iv": "<base64>", "data": "<base64>" }
  ```
  - **Cipher**: `PBKDF2-SHA256` (600,000 iterations) + 12-byte IV + `AES-256-GCM`.
  - **Future KDF Note**: `PBKDF2WithHmacSHA256` and `AES/GCM/NoPadding` are natively supported by Android's standard `javax.crypto`. If the web vault upgrades to **Argon2id** later, the Android build must add native/JNI parity (e.g., BouncyCastle or `lazysodium-android`) to maintain format compatibility.

---

## 2. The WebView-to-Native Storage Bridge (Solving the Autofill Lifecycle Wall)

### Why WebView `localStorage` Fails for Autofill
When a user taps a login field in another app, the Android OS wakes `AutofillService` or `CredentialProviderService` in the background with a strict execution timeout and **no active `MainActivity` or `WebView`**.
- The background service cannot read Chromium's private `localStorage` SQLite database.
- Spinning up a headless `WebView` inside `onFillRequest()` is too slow, memory-heavy, and prone to OS time-outs.

### Bridge Architecture
```text
[WebView UI] <--(window.AndroidVaultBridge)--> [context.filesDir/securevault.vault] <---> [AutofillService / CredentialProviderService]
                                                        ^
                                                        |
                                   [Android Hardware Keystore + BiometricPrompt]
```

1. **Native File Persistence (`AndroidVaultBridge`)**:
   - In the web app, storage persistence checks for `window.AndroidVaultBridge` first and falls back to `localStorage` on standard browsers.
   - `AndroidVaultBridge.saveVault(jsonString)` and `AndroidVaultBridge.loadVault()` read/write the encrypted `.vault` payload directly to native app-private storage (`context.filesDir/securevault.vault`).
2. **Hardware Keystore & Biometric Key Wrapping**:
   - When the user unlocks the vault with their Master Password, the derived 256-bit AES key is passed to the native layer and wrapped (encrypted) using an Android Hardware Keystore `SecretKey` gated by `BiometricPrompt`.
   - Subsequent unlocks (in the main app or during an autofill prompt) authenticate via `BiometricPrompt` to unwrap the 256-bit AES key in memory without re-running 600,000 PBKDF2 iterations or requiring the Master Password.
3. **Direct Kotlin Decryption in Background Services**:
   - Both `MainActivity` and background `AutofillService` / `CredentialProviderService` read `context.filesDir/securevault.vault` directly and decrypt/encrypt it in Kotlin using `javax.crypto` (`PBKDF2WithHmacSHA256` + `AES/GCM/NoPadding`) and the unwrapped AES key.

---

## 3. Phased Execution Plan

### Phase 1: Native Shell + Storage Bridge + Biometric Unlock
- **`MainActivity` WebView**: Host the bundled single-file HTML/JS UI with zero external network permissions (`INTERNET` permission omitted or restricted to offline local assets).
- **`AndroidVaultBridge` (`@JavascriptInterface`)**: Route `.vault` load/save operations to `context.filesDir/securevault.vault` and handle native file import/export (`ActivityResultContracts.CreateDocument` / `OpenDocument`).
- **Keystore + `BiometricPrompt`**: Wrap the derived vault AES key in Android Hardware Keystore on Master Password unlock; provide biometric quick-unlock on subsequent launches.

### Phase 2: `AutofillService` + Inline Suggestions (IME) + Quick-Settings Tiles
- **`AutofillService` (`onFillRequest`)**:
  - Parse the target app's `AssistStructure` (package name / web domain).
  - Read `context.filesDir/securevault.vault`; if locked, return an authentication `Dataset` PendingIntent that triggers `BiometricPrompt` + Kotlin `javax.crypto` decryption.
  - Return matching `Dataset` entries for both standard dropdowns and **Android 11+ Inline Autofill Suggestions** (keyboard/IME strip).
- **`AutofillService` (`onSaveRequest`)**:
  - Capture new or updated credentials submitted in other apps, decrypt the native `.vault` file, append the entry, re-encrypt with a fresh 12-byte IV, and write atomically to `context.filesDir`.
- **Quick-Settings Tiles (`MyVaultTileService` / `GeneratorTileService`)**:
  - Provide one-tap notification shade tiles to open the vault overlay or generate/copy a password on demand.

### Phase 3: `CredentialProviderService` (Android 14+ / `androidx.credentials`)
- Implement `CredentialProviderService` via `androidx.credentials` to register SecureVault with the unified Android 14+ Credential Manager selector.
- Support native Passkey (`PublicKeyCredential`) creation/assertion and password credential retrieval alongside `AutofillService`.

---

## 4. Why `BIND_ACCESSIBILITY_SERVICE` Is Dropped

Earlier plans considered an Accessibility Service fallback for apps that bypass the standard Autofill framework. **This is explicitly dropped:**
1. **Android 13+ "Restricted Setting" Wall**: Android 13+ blocks `BIND_ACCESSIBILITY_SERVICE` for sideloaded APKs (`adb` or GitHub Releases) behind a multi-step "Restricted Setting" security lockout that degrades usability.
2. **Play Store Policy Rejections**: Google Play strictly prohibits using Accessibility APIs for password autofill unless the app's primary purpose is assisting users with disabilities.
3. **Modern Replacements**: Combining standard `AutofillService` with **Android 11+ Inline IME Suggestions** (keyboard bar) and the **`MyVaultTileService` Quick-Settings Tile** covers recalcitrant login screens cleanly without invasive screen-reading permissions.
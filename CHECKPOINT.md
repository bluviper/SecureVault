# CHECKPOINT — SecureVault (2026-10-20)

Backtrackable snapshot. Read this before resuming work. Supersedes guessing from code alone.

---

## 1. Current Repository State
- **Active Feature Branch:** `feat/android-companion` (tracks `origin/feat/android-companion`, clean working tree).
- **Production Web Branch:** `master` (clean, history purged of sensitive test vaults, 100% synchronized with `origin/master`).
- **Core Version:** 2.0.0.
  - **Desktop / Web:** Single-file standalone HTML (`index.html`, ~1050 KB), zero runtime dependencies, offline-first.
  - **Mobile Companion:** Native Android application located in `android/` subfolder.
- **Crypto Parity:** PBKDF2-SHA256 @ 600,000 iterations + AES-256-GCM (12-byte IV, 128-bit tag). Identical implementations in both Web Crypto (`src/app.js`) and native Kotlin (`android/.../crypto/VaultCrypto.kt`).
- **Build & Tests:**
  - Web: `npm run build` (bundles to `index.html` and mirrors to `android/app/src/main/assets/index.html`); `npm test` (13/13 test suites pass).
  - Android: `gradlew.bat compileDebugKotlin testDebugUnitTest assembleDebug` (100% pass, debug APK built in `android/app/build/outputs/apk/debug/app-debug.apk`).

---

## 2. Completed Milestones

### A. Web & Crypto Engine (v2.0) — [master]
1. **RFC 6238 TOTP Generator**: Offline HMAC-SHA1/256/512 with 30s live circular badge.
2. **zxcvbn-Style Pattern Entropy Scorer**: Discounts dictionary words, sequences, repeats, and l33tspeak.
3. **Universal Importers**: Full-fidelity Bitwarden JSON (with folders) and KeePass 2.x XML (with history stripping).
4. **Rich Entry Types**: Full schema support for `login`, `card` (Expiry/CVV), `identity` (Secure Notes), and `ssh`.
5. **Interior.dev UI Polish**: Floating labels, 3-layer sliding segmented control, and single-surface focus glow.

### B. Android Native Companion (Phase 1) — [feat/android-companion]
1. **Android Project Structure (`android/`)**: Standard Gradle 8.7 + AGP 8.5.2, targeting Android 8.0 (minSdk 26) through Android 14+ (targetSdk 34). Turnkey compilation via `gradlew.bat` / `gradlew`.
2. **Hardened Android Shell**:
   - `FLAG_SECURE` enabled in `MainActivity.kt` (blocks Android task-switcher snapshots and screenshots).
   - `USE_BIOMETRIC` permission with OS cloud backup exclusions (`backup_rules.xml`, `data_extraction_rules.xml`).
3. **Hardware Keystore & Biometrics**:
   - `KeystoreHelper.kt` wraps the 256-bit AES master key in the hardware Secure Element / ARM TrustZone (`AUTH_BIOMETRIC_STRONG`).
   - Integrated with `BiometricPrompt` for instantaneous fingerprint unlock.
4. **Native Storage Bridge**:
   - `AndroidVaultBridge.kt` writes encrypted `.vault` payloads atomically via `AtomicFile` to app-private storage (`context.filesDir/vault.json`).
   - Android 13+ sensitive clipboard protection (`ClipDescription.EXTRA_IS_SENSITIVE`).
5. **Mobile Bottom Navigation Bar**:
   - Intricate 5-destination bottom bar docked in the thumb zone (Vault, Security Audit, Center Hero FAB `+`, Settings, Lock).
   - Dedicated "Security Audit" pane for Bento grid password health metrics.
   - Desktop view preserved via responsive media queries.

### C. Product Strategy & Competitive Moats
- Formally documented in [PRODUCT_STRATEGY.md](PRODUCT_STRATEGY.md):
  - BSL 1.1 / Source-Available licensing recommendations.
  - Positioning: Anti-cloud, anti-subscription sovereign vault with dual form factor (air-gapped USB + native mobile companion).

---

---

## 3. Phase 2 (Native Autofill Engine) — COMPLETED
1. **`AutofillService` Registration**:
   - Declared `com.bluviper.securevault.autofill.VaultAutofillService` in `AndroidManifest.xml` with `BIND_AUTOFILL_SERVICE` permission and `res/xml/autofill_service_config.xml`.
2. **Headless Native Autofill Parser (`AutofillStructureParser.kt`)**:
   - Walks `AssistStructure` node hierarchy to extract target package, web domain, username/email `AutofillId`, and password `AutofillId`.
3. **Session Cache & Heuristic Matching (`VaultMemoryCache.kt`)**:
   - Parses unlocked vault items in memory; matches foreground packages and domains with 5-minute auto-wipe timeout.
4. **Biometric Autofill Authentication (`AutofillAuthActivity.kt`)**:
   - If vault is locked when autofill is requested, returns an authentication dataset. Tapping prompts the hardware fingerprint sensor, unwraps the AES master key from the Keystore, and delivers credentials to third-party apps.
5. **Autofill RemoteViews Dropdown Layouts**:
   - Built `res/layout/autofill_dataset_item.xml` (service title + username) and `res/layout/autofill_auth_item.xml` (unlock prompt).
6. **Automated Unit Tests**:
   - Added `AutofillMatchingTest.kt` verifying domain, package, and subdomain matching + non-login credential filtering. All Android unit tests pass (100%).
7. **Android 14+ Credential Manager (`VaultCredentialProviderService.kt`)**:
   - Implemented `CredentialProviderService` with `res/xml/credential_provider_config.xml` (`TYPE_PASSWORD_CREDENTIAL`) and vector logo `res/drawable/ic_vault_logo.xml`.
   - Added `openAutofillSettings()` in `AndroidVaultBridge.kt`. SecureVault is verified selectable in Android 14+ unified "Passwords, passkeys & autofill" settings.

---

## 4. Key Constraints & Non-Negotiables
- **Zero Cloud / Zero Network**: No backend servers, no analytics, no external trackers.
- **Single Source of Truth**: `src/index.html` + `src/app.js` + `src/style.css` compile to root `index.html` and auto-sync to `android/app/src/main/assets/index.html`.
- **Security Baseline**: Never commit `*.vault`, `*.jks`, `*.keystore`, or unencrypted exports.
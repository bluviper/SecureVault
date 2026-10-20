/* ==========================================================================
   🛡️ SecureVault Core Logic & Cryptography
   ========================================================================== */

// --- Application State ---
let masterKey = null;             // Decrypted CryptoKey object
let vaultData = [];              // Array of saved credential items
let currentEditId = null;         // ID of the item being edited in modal
let salt = null;                  // PBKDF2 salt (Uint8Array)
let timeoutMinutes = 5;           // Inactivity auto-lock timeout (minutes)
let clipboardClearTimer = null;   // Reference for clipboard auto-wipe timer
let toastHideTimeout = null;      // Reference for UI toast notification hide timer
let pendingData = null;           // Staged encrypted payload awaiting master password unlock
let activeDashboardFilter = null; // 'weak', 'reused', 'vulnerable', or null

// Auto-lock activity tracking
let lastActivityTime = Date.now();
let autoLockInterval = null;
let totpRefreshInterval = null;

// --- Cryptographic & Utility Functions ---

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes an RFC 4648 Base32 string into a Uint8Array.
 * Ignores spaces, hyphens, and padding ('='). Throws on invalid characters.
 */
function base32ToUint8(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('Base32 secret is empty');
    }
    const clean = input.replace(/[\s\-=]+/g, '').toUpperCase();
    if (!clean.length) {
        throw new Error('Base32 secret is empty');
    }

    const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
    let bits = 0;
    let value = 0;
    let index = 0;

    for (let i = 0; i < clean.length; i++) {
        const idx = BASE32_ALPHABET.indexOf(clean[i]);
        if (idx === -1) {
            throw new Error(`Invalid Base32 character: ${clean[i]}`);
        }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[index++] = (value >>> bits) & 0xff;
        }
    }
    return out;
}

/**
 * Parses a raw Base32 secret or an otpauth://totp/... URI into TOTP parameters.
 */
function parseTotpInput(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('TOTP input is empty');
    }
    const trimmed = input.trim();
    if (!trimmed) {
        throw new Error('TOTP input is empty');
    }

    if (/^otpauth:\/\//i.test(trimmed)) {
        let url;
        try {
            url = new URL(trimmed);
        } catch {
            throw new Error('Malformed otpauth:// URI');
        }
        const secret = url.searchParams.get('secret') || '';
        const digitsParam = parseInt(url.searchParams.get('digits') || '6', 10);
        const periodParam = parseInt(url.searchParams.get('period') || '30', 10);
        const rawAlg = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');

        const algMap = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
        const algorithm = algMap[rawAlg] || 'SHA-1';
        const digits = (digitsParam === 6 || digitsParam === 8) ? digitsParam : 6;
        const period = periodParam > 0 ? periodParam : 30;

        base32ToUint8(secret);
        return { secret, digits, period, algorithm };
    }

    base32ToUint8(trimmed);
    return { secret: trimmed, digits: 6, period: 30, algorithm: 'SHA-1' };
}

/**
 * Generates an RFC 6238 TOTP code using Web Crypto HMAC.
 */
async function generateTOTP(secretInput, timestampMs = Date.now()) {
    const { secret, digits, period, algorithm } = parseTotpInput(secretInput);
    const keyBytes = base32ToUint8(secret);

    const epochSeconds = Math.floor(timestampMs / 1000);
    const counter = Math.floor(epochSeconds / period);
    const remaining = period - (epochSeconds % period);

    const counterBytes = new Uint8Array(8);
    const high = Math.floor(counter / 0x100000000);
    const low = counter >>> 0;
    counterBytes[0] = (high >>> 24) & 0xff;
    counterBytes[1] = (high >>> 16) & 0xff;
    counterBytes[2] = (high >>> 8) & 0xff;
    counterBytes[3] = high & 0xff;
    counterBytes[4] = (low >>> 24) & 0xff;
    counterBytes[5] = (low >>> 16) & 0xff;
    counterBytes[6] = (low >>> 8) & 0xff;
    counterBytes[7] = low & 0xff;

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: { name: algorithm } },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, counterBytes);
    const hmac = new Uint8Array(sig);

    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    const code = (binary % (10 ** digits)).toString().padStart(digits, '0');
    return { code, remaining, period };
}

/**
 * Converts a Uint8Array to a Base64 string.
 */
function uint8ToBase64(arr) {
    let binary = '';
    const len = arr.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(arr[i]);
    }
    return btoa(binary);
}

/**
 * Converts a Base64 string to a Uint8Array.
 */
function base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Safely escapes HTML special characters to prevent XSS attacks.
 */
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Derives a 256-bit AES-GCM key from a master password and salt using PBKDF2.
 * Uses 600,000 iterations and SHA-256 hashing (OWASP recommended baseline).
 */
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw", 
        encoder.encode(password), 
        "PBKDF2", 
        false, 
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { 
            name: "PBKDF2", 
            salt: salt, 
            iterations: 600000, 
            hash: "SHA-256" 
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts an object using AES-256-GCM.
 */
async function encrypt(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(JSON.stringify(data));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, 
        key, 
        encodedData
    );
    return {
        iv: uint8ToBase64(iv),
        data: uint8ToBase64(new Uint8Array(encrypted))
    };
}

/**
 * Decrypts an AES-256-GCM encrypted payload.
 */
async function decrypt(encryptedDataBase64, ivBase64, key) {
    const iv = base64ToUint8(ivBase64);
    const data = base64ToUint8(encryptedDataBase64);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, 
        key, 
        data
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
}

// --- Security & Strength Assessment Functions ---

// Compact high-frequency leaked password stems for offline pattern scoring
const COMMON_PASSWORD_STEMS = [
    'password', 'qwerty', 'asdfgh', 'zxcvbn', 'admin', 'welcome', 'letmein',
    'monkey', 'dragon', 'master', 'login', 'princess', 'sunshine', 'football',
    'baseball', 'iloveyou', 'trustno', 'superman', 'batman', 'shadow', 'michael',
    'charlie', 'andrew', 'robert', 'thomas', 'daniel', 'matthew', 'joshua',
    'jessica', 'ashley', 'amanda', 'nicole', 'secret', 'autumn', 'winter',
    'summer', 'spring', 'access', 'computer', 'internet', 'service', 'account',
    'freedom', 'whatever', 'nothing', 'forever', 'killer', 'pepper', 'ginger',
    'bailey', 'buster', 'harley', 'hunter', 'ranger', 'soccer', 'hockey',
    'silver', 'matrix', 'falcon', 'wizard', 'knight', 'viking', 'crypto',
    'bitcoin', 'google', 'github', 'amazon', 'apple'
];

const SEQUENCE_ROWS = [
    'abcdefghijklmnopqrstuvwxyz',
    '01234567890',
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm'
];

const LEET_MAP = {
    '@': 'a', '4': 'a', '0': 'o', '1': 'i', '!': 'i',
    '3': 'e', '$': 's', '5': 's', '7': 't'
};

/**
 * Normalizes common leetspeak substitutions to lowercase ASCII for dictionary matching.
 */
function normalizeLeet(str) {
    let out = '';
    for (let i = 0; i < str.length; i++) {
        const ch = str[i].toLowerCase();
        out += LEET_MAP[ch] || ch;
    }
    return out;
}

/**
 * Evaluates effective password entropy (in bits) by discounting predictable patterns:
 * dictionary stems (including l33t), repeated characters, keyboard/alphanumeric sequences, and years.
 */
function analyzePasswordEntropy(password) {
    if (!password) return { entropy: 0, warning: '' };

    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    if (charsetSize === 0) return { entropy: 0, warning: '' };

    const bitsPerChar = Math.log2(charsetSize);
    const len = password.length;
    const discounted = new Uint8Array(len);
    const lower = password.toLowerCase();
    const leet = normalizeLeet(password);

    let patternBits = 0;
    let warning = '';

    // 1. Dictionary & l33tspeak stems
    for (const stem of COMMON_PASSWORD_STEMS) {
        for (const source of [lower, leet]) {
            let pos = source.indexOf(stem);
            while (pos !== -1) {
                let overlap = false;
                for (let i = pos; i < pos + stem.length; i++) {
                    if (discounted[i]) { overlap = true; break; }
                }
                if (!overlap) {
                    for (let i = pos; i < pos + stem.length; i++) discounted[i] = 1;
                    const rawSlice = password.slice(pos, pos + stem.length);
                    const hasUpper = /[A-Z]/.test(rawSlice);
                    const hasLeet = lower.slice(pos, pos + stem.length) !== leet.slice(pos, pos + stem.length);
                    patternBits += 10 + (hasUpper ? 1 : 0) + (hasLeet ? 2 : 0);
                    if (!warning) warning = 'Common word pattern';
                }
                pos = source.indexOf(stem, pos + 1);
            }
        }
    }

    // 2. Repeated character runs (3+ identical chars, e.g. "aaaa", "1111")
    for (let i = 0; i < len;) {
        let j = i + 1;
        while (j < len && password[j] === password[i]) j++;
        if (j - i >= 3) {
            let uncounted = 0;
            for (let k = i; k < j; k++) {
                if (!discounted[k]) { discounted[k] = 1; uncounted++; }
            }
            if (uncounted > 0) {
                patternBits += bitsPerChar + 1.5;
                if (!warning) warning = 'Repeated characters';
            }
        }
        i = j;
    }

    // 3. Keyboard & alphanumeric sequences (3+ chars forward or reverse, e.g. "12345", "qwerty")
    for (let i = 0; i <= len - 3; i++) {
        if (discounted[i] && discounted[i + 1] && discounted[i + 2]) continue;
        let maxSeq = 0;
        for (const row of SEQUENCE_ROWS) {
            const rev = row.split('').reverse().join('');
            for (let subLen = len - i; subLen >= 3; subLen--) {
                const sub = lower.slice(i, i + subLen);
                if (row.includes(sub) || rev.includes(sub)) {
                    if (subLen > maxSeq) maxSeq = subLen;
                    break;
                }
            }
        }
        if (maxSeq >= 3) {
            for (let k = i; k < i + maxSeq; k++) discounted[k] = 1;
            patternBits += 4;
            if (!warning) warning = 'Sequential pattern';
            i += maxSeq - 1;
        }
    }

    // 4. 4-digit years (1900-2099)
    const yearRegex = /(?:19|20)\d{2}/g;
    let match;
    while ((match = yearRegex.exec(password)) !== null) {
        const start = match.index;
        if (!discounted[start] && !discounted[start + 1] && !discounted[start + 2] && !discounted[start + 3]) {
            for (let k = start; k < start + 4; k++) discounted[k] = 1;
            patternBits += 6.5;
            if (!warning) warning = 'Year pattern';
        }
    }

    // 5. Remaining unpredictable characters get full charset entropy
    let randomChars = 0;
    for (let i = 0; i < len; i++) {
        if (!discounted[i]) randomChars++;
    }

    const entropy = Math.round(patternBits + randomChars * bitsPerChar);
    return { entropy, warning };
}

/**
 * Calculates pattern-adjusted effective entropy (in bits) for a password.
 */
function calculateEntropy(password) {
    return analyzePasswordEntropy(password).entropy;
}

/**
 * Returns strength classification object mapped to semantic theme tokens (danger, warning, success).
 */
function assessPasswordStrength(password) {
    if (!password) return { score: 0, label: 'None', token: 'muted', entropy: 0, warning: '' };
    const { entropy, warning } = analyzePasswordEntropy(password);

    if (password.length < 8 || entropy < 42 || (password.length < 10 && entropy < 52)) {
        return {
            score: 1,
            label: 'Weak',
            token: 'danger',
            entropy,
            warning: warning || (password.length < 8 ? 'Too short (< 8 chars)' : '')
        };
    } else if (entropy < 68 || (password.length < 12 && entropy < 75)) {
        return { score: 2, label: 'Medium', token: 'warning', entropy, warning };
    } else {
        return { score: 3, label: 'Strong', token: 'success', entropy, warning: '' };
    }
}

/**
 * Returns true if the entry is a standard login record (default when type is omitted).
 */
function isLoginEntry(item) {
    return !item || !item.type || item.type === 'login';
}

/**
 * Returns a Set of passwords that appear more than once among login entries in the active vault.
 */
function getReusedPasswordSet() {
    const counts = new Map();
    vaultData.forEach(item => {
        if (isLoginEntry(item) && item.pass) {
            counts.set(item.pass, (counts.get(item.pass) || 0) + 1);
        }
    });
    const reusedSet = new Set();
    counts.forEach((count, pass) => {
        if (count > 1) reusedSet.add(pass);
    });
    return reusedSet;
}

// --- Vault Initialization & State Control ---

/**
 * Switches the lock screen view to prompt for Master Password unlock.
 */
function showUnlockPrompt() {
    const initPrompt = document.getElementById('initialize-prompt');
    const unlockPrompt = document.getElementById('unlock-prompt');
    if (initPrompt) initPrompt.classList.add('hidden');
    if (unlockPrompt) unlockPrompt.classList.remove('hidden');
}

/**
 * Switches the lock screen view to prompt for new vault creation.
 */
function showInitPrompt() {
    const initPrompt = document.getElementById('initialize-prompt');
    const unlockPrompt = document.getElementById('unlock-prompt');
    if (initPrompt) initPrompt.classList.remove('hidden');
    if (unlockPrompt) unlockPrompt.classList.add('hidden');
}

/**
 * Persists current encrypted vault state in browser local storage or Android native storage.
 */
async function persistEncryptedVault() {
    if (!masterKey || !salt) return;
    try {
        const encrypted = await encrypt(vaultData, masterKey);
        const payload = {
            salt: uint8ToBase64(salt),
            iv: encrypted.iv,
            data: encrypted.data
        };
        const payloadJson = JSON.stringify(payload);
        if (window.AndroidVaultBridge && typeof window.AndroidVaultBridge.saveVault === 'function') {
            window.AndroidVaultBridge.saveVault(payloadJson);
        } else if (typeof localStorage !== 'undefined') {
            localStorage.setItem('securevault_encrypted_payload', payloadJson);
        }
    } catch (e) {
        console.error("Failed to persist encrypted vault", e);
    }
}

/**
 * Checks for previously saved encrypted vault in Android private storage or browser local storage.
 */
function checkSavedVault() {
    let saved = null;
    if (window.AndroidVaultBridge && typeof window.AndroidVaultBridge.loadVault === 'function') {
        saved = window.AndroidVaultBridge.loadVault();
    } else if (typeof localStorage !== 'undefined') {
        saved = localStorage.getItem('securevault_encrypted_payload');
    }

    if (saved) {
        try {
            const content = JSON.parse(saved);
            if (content.salt && content.iv && content.data) {
                salt = base64ToUint8(content.salt);
                pendingData = { iv: content.iv, data: content.data };
                showUnlockPrompt();
                updateBiometricUnlockButton();
                return true;
            }
        } catch (e) {
            if (!window.AndroidVaultBridge && typeof localStorage !== 'undefined') {
                localStorage.removeItem('securevault_encrypted_payload');
            }
        }
    }
    showInitPrompt();
    return false;
}

/**
 * Initializes a brand new vault in memory.
 */
async function initializeVault() {
    const pwInput = document.getElementById('new-master-pw');
    const pw = pwInput ? pwInput.value : '';
    if (pw.length < 8) {
        return alert("Master password must be at least 8 characters.");
    }
    
    salt = crypto.getRandomValues(new Uint8Array(16));
    masterKey = await deriveKey(pw, salt);
    vaultData = [];
    await persistEncryptedVault();
    showApp();
    showToast("Vault initialized successfully.");
}

/**
 * Updates visibility of the native Biometric Unlock button if running on Android with enrolled credentials.
 */
function updateBiometricUnlockButton() {
    const bioBtn = document.getElementById('btn-biometric-unlock');
    if (!bioBtn) return;
    if (window.AndroidVaultBridge && typeof window.AndroidVaultBridge.hasBiometricKey === 'function') {
        if (window.AndroidVaultBridge.hasBiometricKey()) {
            bioBtn.classList.remove('hidden');
            return;
        }
    }
    bioBtn.classList.add('hidden');
}

/**
 * Triggers native Android BiometricPrompt unlock.
 */
function triggerBiometricUnlock() {
    if (typeof window === 'undefined' || !window.AndroidVaultBridge || typeof window.AndroidVaultBridge.requestBiometricUnlock !== 'function') return;
    window.AndroidVaultBridge.requestBiometricUnlock('onNativeBiometricResult');
}

if (typeof window !== 'undefined') {
    window.onNativeBiometricResult = function(success, decryptedJson, errorMsg) {
        if (success && decryptedJson) {
            try {
                vaultData = JSON.parse(decryptedJson);
                pendingData = null;
                showApp();
                showToast("Unlocked with biometrics.");
            } catch (e) {
                showToast("Failed to parse vault: " + e.message);
            }
        } else if (errorMsg) {
            showToast("Biometric: " + errorMsg);
        }
    };

    window.onNativeBiometricEnrolled = function(success, errorMsg) {
        if (success) {
            showToast("Biometric unlock enabled.");
            updateBiometricUnlockButton();
        } else if (errorMsg) {
            showToast("Biometric setup: " + errorMsg);
        }
    };
}

/**
 * Unlocks vault by decrypting loaded data.
 */
async function unlockVault() {
    const pwInput = document.getElementById('master-pw');
    const pw = pwInput ? pwInput.value : '';
    if (!pw) return;
    if (!salt) return alert("Please upload or import a vault file first.");
    
    try {
        masterKey = await deriveKey(pw, salt);
        if (pendingData) {
            vaultData = await decrypt(pendingData.data, pendingData.iv, masterKey);
            pendingData = null;
        }
        await persistEncryptedVault();
        showApp();
        showToast("Vault unlocked.");

        // Offer biometric enrollment on Android if hardware is available and not yet enrolled
        if (window.AndroidVaultBridge && typeof window.AndroidVaultBridge.isBiometricAvailable === 'function') {
            if (window.AndroidVaultBridge.isBiometricAvailable() && !window.AndroidVaultBridge.hasBiometricKey()) {
                setTimeout(() => {
                    if (confirm("Enable fingerprint unlock for SecureVault?")) {
                        window.AndroidVaultBridge.requestEnableBiometric(pw, 'onNativeBiometricEnrolled');
                    }
                }, 400);
            }
        }
    } catch (e) {
        masterKey = null;
        alert("Invalid master password.");
    }
}

/**
 * Locks the vault, wiping cryptographic keys and transient data from RAM.
 */
function lockVault() {
    masterKey = null;
    vaultData = [];
    activeDashboardFilter = null;
    
    // UI resets
    const appUi = document.getElementById('app-ui');
    const lockScreen = document.getElementById('lock-screen');
    if (appUi) appUi.classList.add('hidden');
    if (lockScreen) lockScreen.classList.remove('hidden');
    
    const masterPwInput = document.getElementById('master-pw');
    const newMasterPwInput = document.getElementById('new-master-pw');
    if (masterPwInput) masterPwInput.value = '';
    if (newMasterPwInput) newMasterPwInput.value = '';
    
    // Stop intervals
    clearInterval(autoLockInterval);
    clearInterval(totpRefreshInterval);
    totpRefreshInterval = null;
    clearTimeout(clipboardClearTimer);
    
    const progressBar = document.getElementById('auto-lock-progressbar');
    if (progressBar) progressBar.style.transform = 'scaleX(0)';

    syncFloatingLabels();
    checkSavedVault();
}

/**
 * Shows the unlocked main application interface.
 */
function showApp() {
    const lockScreen = document.getElementById('lock-screen');
    const appUi = document.getElementById('app-ui');
    const statusText = document.getElementById('vault-status-text');
    
    if (lockScreen) lockScreen.classList.add('hidden');
    if (appUi) appUi.classList.remove('hidden');
    if (statusText) statusText.innerText = 'Vault Unlocked';
    
    renderDashboard();
    renderVault();
    startAutoLockTimer();
}

// --- Auto-Lock Idle Timer Logic ---

/**
 * Instantiates the auto-lock activity checker.
 */
function startAutoLockTimer() {
    clearInterval(autoLockInterval);
    lastActivityTime = Date.now();
    
    autoLockInterval = setInterval(() => {
        if (!masterKey) {
            clearInterval(autoLockInterval);
            return;
        }
        
        const elapsed = Date.now() - lastActivityTime;
        const total = timeoutMinutes * 60 * 1000;
        const fraction = Math.max(0, 1 - (elapsed / total));
        
        const progressBar = document.getElementById('auto-lock-progressbar');
        if (progressBar) {
            progressBar.style.transform = `scaleX(${fraction})`;
        }
        
        if (elapsed >= total) {
            lockVault();
            showToast("Vault locked due to inactivity.");
        }
    }, 1000);
}

/**
 * Resets the idle countdown indicator.
 */
function resetAutoLock() {
    lastActivityTime = Date.now();
    const progressBar = document.getElementById('auto-lock-progressbar');
    if (progressBar) {
        progressBar.style.transform = 'scaleX(1)';
    }
}

/**
 * Updates lock settings timer from the UI.
 */
function updateTimeout() {
    const input = document.getElementById('setting-timeout').value;
    timeoutMinutes = Math.min(60, Math.max(1, parseInt(input) || 5));
    document.getElementById('setting-timeout').value = timeoutMinutes;
    resetAutoLock();
    showToast(`Inactivity timeout set to ${timeoutMinutes}m`);
}

// --- Navigation Tabs ---

function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(c => c.classList.remove('active'));
    
    const tabBtn = document.getElementById(`tab-btn-${tab}`);
    const tabPane = document.getElementById(`tab-${tab}`);
    if (tabBtn) tabBtn.classList.add('active');
    if (tabPane) tabPane.classList.add('active');
}

// --- Dashboard & Metrics Visualizer ---

/**
 * Summarizes current vault state metrics for the Bento Grid.
 */
function renderDashboard() {
    const reusedSet = getReusedPasswordSet();
    
    let total = vaultData.length;
    let weak = 0;
    let reused = 0;
    let vulnerable = 0;
    
    vaultData.forEach(item => {
        if (!isLoginEntry(item)) return;
        const rating = assessPasswordStrength(item.pass);
        if (rating.label === 'Weak') weak++;
        if (item.pass.length < 12) vulnerable++;
        if (item.pass && reusedSet.has(item.pass)) reused++;
    });
    
    const totalEl = document.getElementById('dash-total');
    const weakEl = document.getElementById('dash-weak');
    const reusedEl = document.getElementById('dash-reused');
    const vulnEl = document.getElementById('dash-vulnerable');

    if (totalEl) totalEl.innerText = total;
    if (weakEl) weakEl.innerText = weak;
    if (reusedEl) reusedEl.innerText = reused;
    if (vulnEl) vulnEl.innerText = vulnerable;
    
    populateCategorySelectors();
}

/**
 * Filters credential list by password strength.
 */
function filterByStrength(strength) {
    activeDashboardFilter = strength === 'weak' ? 'weak' : null;
    updateFilterBarUI();
    renderVault();
}

/**
 * Filters credential list by password reuse.
 */
function filterByReused() {
    activeDashboardFilter = 'reused';
    updateFilterBarUI();
    renderVault();
}

/**
 * Filters credential list by password vulnerability (< 12 chars).
 */
function filterByVulnerable() {
    activeDashboardFilter = 'vulnerable';
    updateFilterBarUI();
    renderVault();
}

/**
 * Clear dashboard filtering criteria.
 */
function clearDashboardFilters() {
    activeDashboardFilter = null;
    updateFilterBarUI();
    renderVault();
}

/**
 * Updates UI message indicating active dashboard filters.
 */
function updateFilterBarUI() {
    const bar = document.getElementById('filter-alert');
    const label = document.getElementById('filter-alert-text');
    if (!bar || !label) return;
    
    if (activeDashboardFilter) {
        bar.classList.remove('hidden');
        if (activeDashboardFilter === 'weak') label.innerText = 'Weak Passwords';
        else if (activeDashboardFilter === 'reused') label.innerText = 'Reused Passwords';
        else if (activeDashboardFilter === 'vulnerable') label.innerText = 'Vulnerable Passwords (< 12 chars)';
    } else {
        bar.classList.add('hidden');
    }
}

// --- List View Rendering ---

/**
 * Formats a numeric OTP code with a middle space for readability (e.g. "123 456").
 */
function formatTotpDisplay(code) {
    if (!code) return '--- ---';
    const mid = Math.floor(code.length / 2);
    return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

/**
 * Refreshes all visible TOTP badges in the rendered vault list.
 */
async function refreshVisibleTotpBadges() {
    if (typeof document === 'undefined' || !masterKey) return;
    const buttons = document.querySelectorAll('.totp-code-btn[data-totp-secret]');
    if (buttons.length === 0) {
        clearInterval(totpRefreshInterval);
        totpRefreshInterval = null;
        return;
    }

    const now = Date.now();
    for (const btn of buttons) {
        const secret = btn.getAttribute('data-totp-secret');
        const codeEl = btn.querySelector('.totp-code-text');
        const timerEl = btn.querySelector('.totp-timer-pill');
        if (!secret || !codeEl || !timerEl) continue;

        try {
            const { code, remaining } = await generateTOTP(secret, now);
            codeEl.innerText = formatTotpDisplay(code);
            timerEl.innerText = `${remaining}s`;
            timerEl.classList.toggle('expiring', remaining <= 5);
        } catch {
            codeEl.innerText = 'Invalid 2FA';
            timerEl.innerText = '';
        }
    }
}

/**
 * Starts or stops the 1s TOTP refresh timer depending on whether TOTP items are visible.
 */
function syncTotpLiveTimer() {
    clearInterval(totpRefreshInterval);
    totpRefreshInterval = null;
    if (typeof document === 'undefined' || !masterKey) return;

    const buttons = document.querySelectorAll('.totp-code-btn[data-totp-secret]');
    if (buttons.length > 0) {
        refreshVisibleTotpBadges();
        totpRefreshInterval = setInterval(refreshVisibleTotpBadges, 1000);
    }
}

/**
 * Generates and copies the current TOTP code for a secret to the clipboard.
 */
async function copyTotpCode(secret) {
    if (!secret) return;
    try {
        const { code } = await generateTOTP(secret);
        copyCredentialPassword(code);
    } catch {
        alert('Invalid TOTP secret.');
    }
}

const ENTRY_TYPE_META = {
    login: {
        badge: 'LOGIN',
        secLabel: 'Login Credential',
        serviceLabel: 'Service Name / Website',
        servicePlaceholder: 'e.g. Google, Amazon...',
        userLabel: 'Username / Email',
        userPlaceholder: 'e.g. email@domain.com',
        passLabel: 'Password',
        notesPlaceholder: 'API keys, secret questions, URLs...'
    },
    card: {
        badge: 'CARD',
        secLabel: 'Payment Card',
        serviceLabel: 'Card Label / Bank',
        servicePlaceholder: 'e.g. Chase Sapphire, Corporate Visa...',
        userLabel: 'Cardholder Name',
        userPlaceholder: 'e.g. J. Dela Cruz',
        passLabel: 'Card Number',
        notesPlaceholder: 'Billing address, PIN notes, support phone...'
    },
    identity: {
        badge: 'IDENTITY',
        secLabel: 'Identity Document',
        serviceLabel: 'Document / ID Type',
        servicePlaceholder: 'e.g. Passport, Driver License, National ID...',
        userLabel: 'Full Name / Holder',
        userPlaceholder: 'e.g. Juan Dela Cruz',
        passLabel: 'Document / ID Number',
        notesPlaceholder: 'Issuing authority, expiry date, address...'
    },
    ssh: {
        badge: 'SSH KEY',
        secLabel: 'SSH / API Key',
        serviceLabel: 'Host / Key Label',
        servicePlaceholder: 'e.g. Prod Bastion, GitHub Deploy Key...',
        userLabel: 'Username / Fingerprint / Public Key',
        userPlaceholder: 'e.g. root@10.0.0.5 or SHA256:...',
        passLabel: 'Private Key / Secret Token',
        notesPlaceholder: 'Passphrase hint, port, jump host config...'
    }
};

/**
 * Render items in vault credentials list.
 */
function renderVault() {
    const list = document.getElementById('vault-list');
    if (!list) return;

    const searchInput = document.getElementById('search-input');
    const categorySelect = document.getElementById('filter-category');
    
    const searchQuery = searchInput ? searchInput.value.toLowerCase() : '';
    const categoryFilter = categorySelect ? categorySelect.value : 'All';
    
    const reusedSet = getReusedPasswordSet();
    list.innerHTML = '';
    
    const filtered = vaultData.filter(item => {
        // Search matches
        const matchesTags = (item.tags || []).some(t => t.toLowerCase().includes(searchQuery));
        const matchesSearch = item.service.toLowerCase().includes(searchQuery) || 
                              item.user.toLowerCase().includes(searchQuery) ||
                              (item.notes || '').toLowerCase().includes(searchQuery) ||
                              matchesTags;
        
        // Category filter
        const matchesCategory = categoryFilter === 'All' || item.category === categoryFilter;
        
        // Active Dashboard stats filters (apply only to login entries)
        let matchesDashboard = true;
        if (activeDashboardFilter === 'weak') {
            matchesDashboard = isLoginEntry(item) && assessPasswordStrength(item.pass).label === 'Weak';
        } else if (activeDashboardFilter === 'reused') {
            matchesDashboard = isLoginEntry(item) && item.pass && reusedSet.has(item.pass);
        } else if (activeDashboardFilter === 'vulnerable') {
            matchesDashboard = isLoginEntry(item) && item.pass.length < 12;
        }
        
        return matchesSearch && matchesCategory && matchesDashboard;
    });

    if (filtered.length === 0) {
        clearInterval(totpRefreshInterval);
        totpRefreshInterval = null;
        list.innerHTML = `
            <div class="empty-state">
                <p>No credentials found matching filters.</p>
            </div>
        `;
        return;
    }
    
    filtered.forEach((item, index) => {
        const entryType = item.type && ENTRY_TYPE_META[item.type] ? item.type : 'login';
        const typeMeta = ENTRY_TYPE_META[entryType];

        const outer = document.createElement('div');
        outer.className = 'vault-item-outer';
        outer.style.animationDelay = `${index * 0.05}s`;
        
        const inner = document.createElement('div');
        inner.className = 'vault-item-inner';
        
        const info = document.createElement('div');
        info.className = 'item-info';
        
        const titleRow = document.createElement('div');
        titleRow.className = 'item-title-row';
        
        const h4 = document.createElement('h4');
        h4.innerText = item.service;
        titleRow.appendChild(h4);

        if (entryType !== 'login') {
            const typeBadge = document.createElement('span');
            typeBadge.className = 'badge-tag badge-accent';
            typeBadge.innerText = typeMeta.badge;
            titleRow.appendChild(typeBadge);
        }
        
        const badge = document.createElement('span');
        badge.className = 'badge-tag';
        badge.innerText = item.category || 'General';
        titleRow.appendChild(badge);
        
        const userP = document.createElement('p');
        userP.className = 'item-user-text';
        let subtitle = item.user || (entryType === 'login' ? 'No username' : '—');
        if (entryType === 'card' && item.cardExpiry) {
            subtitle += ` • Exp: ${item.cardExpiry}`;
        }
        userP.innerText = subtitle;

        // Revealable secret cell (mono credential value, hidden by default)
        const passRow = document.createElement('div');
        passRow.className = 'item-pass-row hidden';
        const passText = document.createElement('span');
        passText.className = 'credential-value';
        passText.innerText = (entryType === 'card' && item.cardCvv)
            ? `${item.pass}  (CVV: ${item.cardCvv})`
            : item.pass;
        passRow.appendChild(passText);

        // Live TOTP 2FA badge row if entry has a TOTP secret configured
        let totpRow = null;
        if (item.totp && entryType === 'login') {
            totpRow = document.createElement('div');
            totpRow.className = 'item-totp-row';

            const totpBtn = document.createElement('button');
            totpBtn.type = 'button';
            totpBtn.className = 'totp-code-btn';
            totpBtn.setAttribute('data-totp-secret', item.totp);
            totpBtn.title = 'Click to copy 2FA TOTP code';
            totpBtn.onclick = () => copyTotpCode(item.totp);

            const codeSpan = document.createElement('span');
            codeSpan.className = 'totp-code-text';
            codeSpan.innerText = '••• •••';

            const timerSpan = document.createElement('span');
            timerSpan.className = 'totp-timer-pill';
            timerSpan.innerText = '--s';

            totpBtn.appendChild(codeSpan);
            totpBtn.appendChild(timerSpan);
            totpRow.appendChild(totpBtn);
        }

        // Render tags if present
        if (item.tags && item.tags.length > 0) {
            const tagsContainer = document.createElement('div');
            tagsContainer.className = 'tags-container';
            item.tags.forEach(t => {
                const tagPill = document.createElement('span');
                tagPill.className = 'tag-pill';
                tagPill.innerText = `#${t}`;
                tagsContainer.appendChild(tagPill);
            });
            info.appendChild(tagsContainer);
        }
        
        // Security visual markers
        const secRow = document.createElement('div');
        secRow.className = 'item-security-row';
        
        if (entryType === 'login') {
            const rating = assessPasswordStrength(item.pass);
            const dot = document.createElement('span');
            dot.className = `status-indicator-dot bg-${rating.token}`;
            
            const label = document.createElement('span');
            label.className = `strength-text-label text-${rating.token}`;
            label.innerText = rating.label;
            
            secRow.appendChild(dot);
            secRow.appendChild(label);
            
            if (item.pass && reusedSet.has(item.pass)) {
                const reuseLabel = document.createElement('span');
                reuseLabel.className = 'strength-text-label strength-reuse';
                reuseLabel.innerText = '• Reused';
                secRow.appendChild(reuseLabel);
            }
        } else {
            const dot = document.createElement('span');
            dot.className = 'status-indicator-dot online';
            const label = document.createElement('span');
            label.className = 'strength-text-label text-muted';
            label.innerText = typeMeta.secLabel;
            secRow.appendChild(dot);
            secRow.appendChild(label);
        }
        
        info.appendChild(titleRow);
        info.appendChild(userP);
        info.appendChild(passRow);
        if (totpRow) info.appendChild(totpRow);
        info.appendChild(secRow);
        
        // Actions
        const actions = document.createElement('div');
        actions.className = 'item-actions';
        
        const revealBtn = document.createElement('button');
        revealBtn.className = 'btn-action-icon btn-reveal';
        revealBtn.title = `Reveal ${typeMeta.passLabel}`;
        revealBtn.setAttribute('aria-label', `Reveal ${typeMeta.passLabel}`);
        revealBtn.onclick = () => toggleEntryReveal(passRow, revealBtn);
        revealBtn.innerHTML = EYE_OPEN_SVG;
        
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-action-icon';
        copyBtn.title = `Copy ${typeMeta.passLabel}`;
        copyBtn.setAttribute('aria-label', `Copy ${typeMeta.passLabel}`);
        copyBtn.onclick = () => copyCredentialPassword(item.pass);
        copyBtn.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
        `;
        
        const editBtn = document.createElement('button');
        editBtn.className = 'btn-action-icon';
        editBtn.title = 'Edit';
        editBtn.setAttribute('aria-label', 'Edit Entry');
        editBtn.onclick = () => showEditModal(item.id);
        editBtn.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <path d="M12 20h9"/>
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
            </svg>
        `;
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn-action-icon btn-delete';
        deleteBtn.title = 'Delete';
        deleteBtn.setAttribute('aria-label', 'Delete Entry');
        deleteBtn.onclick = () => deleteEntry(item.id);
        deleteBtn.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <polyline points="3 6 5 6 21 6"/>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
        `;
        
        actions.appendChild(revealBtn);
        actions.appendChild(copyBtn);
        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);
        
        inner.appendChild(info);
        inner.appendChild(actions);
        outer.appendChild(inner);
        list.appendChild(outer);
    });

    syncTotpLiveTimer();
}

// --- Category & Tag Management ---
let defaultCategories = ['General', 'Work', 'Social', 'Banking'];

function getCategories() {
    const set = new Set(defaultCategories);
    vaultData.forEach(i => {
        if (i.category) set.add(i.category);
    });
    return Array.from(set);
}

function populateCategorySelectors() {
    if (typeof document === 'undefined') return;
    const categories = getCategories();
    
    const filterSel = document.getElementById('filter-category');
    if (filterSel) {
        const cur = filterSel.value || 'All';
        filterSel.innerHTML = `<option value="All">All Categories</option>` +
            categories.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
        if (categories.includes(cur) || cur === 'All') filterSel.value = cur;
    }
    
    const modalSel = document.getElementById('entry-category');
    if (modalSel) {
        const cur = modalSel.value || 'General';
        modalSel.innerHTML = categories.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('') +
            `<option value="__custom__">+ Custom Category...</option>`;
        if (categories.includes(cur)) modalSel.value = cur;
        modalSel.onchange = handleCategoryChange;
    }
}

function handleCategoryChange(e) {
    if (e.target.value === '__custom__') {
        const val = prompt("Enter new category name:");
        if (val && val.trim()) {
            const clean = val.trim();
            if (!defaultCategories.includes(clean)) defaultCategories.push(clean);
            populateCategorySelectors();
            e.target.value = clean;
        } else {
            e.target.value = 'General';
        }
    }
}

// --- Entry Editing & Addition Modal ---
let modalPassWasGenerated = false;
let currentEntryType = 'login';
const ENTRY_TYPE_ORDER = ['login', 'card', 'identity', 'ssh'];

/**
 * Syncs the .is-raised class on all .floating-field wrappers based on whether their input/textarea has a value.
 */
function syncFloatingLabels() {
    if (typeof document === 'undefined') return;
    document.querySelectorAll('.floating-field').forEach(wrapper => {
        const control = wrapper.querySelector('input, select, textarea');
        if (!control) return;
        const isSelect = control.tagName === 'SELECT';
        const hasVal = isSelect || (control.value && control.value.length > 0);
        wrapper.classList.toggle('is-raised', Boolean(hasVal));
    });
}

/**
 * Switches the Add/Edit modal between 'login', 'card', 'identity', and 'ssh' entry types.
 */
function setModalEntryType(type) {
    currentEntryType = ENTRY_TYPE_META[type] ? type : 'login';
    const meta = ENTRY_TYPE_META[currentEntryType];

    if (typeof document === 'undefined') return;

    const index = Math.max(0, ENTRY_TYPE_ORDER.indexOf(currentEntryType));
    const thumb = document.getElementById('entry-type-thumb');
    const thumbInner = document.getElementById('entry-type-thumb-inner');
    if (thumb) {
        thumb.style.transform = `translate3d(${index * 100}%, 0, 0)`;
    }
    if (thumbInner) {
        thumbInner.style.transform = `translate3d(${index * -25}%, 0, 0)`;
    }

    document.querySelectorAll('.entry-type-btn').forEach(btn => {
        const isActive = btn.getAttribute('data-entry-type') === currentEntryType;
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-checked', isActive ? 'true' : 'false');
    });

    const serviceLabel = document.getElementById('label-entry-service');
    const serviceInput = document.getElementById('entry-service');
    const userLabel = document.getElementById('label-entry-user');
    const userInput = document.getElementById('entry-user');
    const passLabel = document.getElementById('label-entry-pass');
    const notesInput = document.getElementById('entry-notes');

    if (serviceLabel) serviceLabel.innerText = meta.serviceLabel;
    if (serviceInput) serviceInput.placeholder = meta.servicePlaceholder;
    if (userLabel) userLabel.innerText = meta.userLabel;
    if (userInput) userInput.placeholder = meta.userPlaceholder;
    if (passLabel) passLabel.innerText = meta.passLabel;
    if (notesInput) notesInput.placeholder = meta.notesPlaceholder;

    const isLogin = currentEntryType === 'login';
    const isCard = currentEntryType === 'card';

    const strengthSec = document.getElementById('modal-pass-strength-section');
    const totpSec = document.getElementById('modal-totp-section');
    const diceBtn = document.getElementById('btn-dice-pass');
    const cardExtra = document.getElementById('modal-card-extra');

    if (strengthSec) strengthSec.classList.toggle('hidden', !isLogin);
    if (totpSec) totpSec.classList.toggle('hidden', !isLogin);
    if (diceBtn) diceBtn.classList.toggle('hidden', !isLogin);
    if (cardExtra) cardExtra.classList.toggle('hidden', !isCard);
    syncFloatingLabels();
}

function handleModalGenOptionChange() {
    const modalLen = document.getElementById('modal-gen-length');
    if (modalLen) {
        modalLen.value = Math.min(64, Math.max(8, parseInt(modalLen.value, 10) || 16));
    }
    if (modalPassWasGenerated) {
        fillGeneratedPass();
    }
}

function showAddModal() {
    currentEditId = null;
    modalPassWasGenerated = false;
    document.getElementById('modal-title').innerText = 'Add Entry';
    populateCategorySelectors();
    setModalEntryType('login');
    document.getElementById('entry-category').value = 'General';
    document.getElementById('entry-service').value = '';
    document.getElementById('entry-user').value = '';
    document.getElementById('entry-pass').value = '';
    const expEl = document.getElementById('entry-card-expiry');
    if (expEl) expEl.value = '';
    const cvvEl = document.getElementById('entry-card-cvv');
    if (cvvEl) cvvEl.value = '';
    const totpEl = document.getElementById('entry-totp');
    if (totpEl) totpEl.value = '';
    const tagsEl = document.getElementById('entry-tags');
    if (tagsEl) tagsEl.value = '';
    document.getElementById('entry-notes').value = '';
    
    const pwInput = document.getElementById('entry-pass');
    if (pwInput) pwInput.type = 'password';
    
    analyzeEntryPasswordStrength('');
    syncFloatingLabels();
    document.getElementById('modal').classList.add('active');
}

function showEditModal(id) {
    const item = vaultData.find(i => i.id === id);
    if (!item) return;
    
    currentEditId = id;
    modalPassWasGenerated = false;
    document.getElementById('modal-title').innerText = 'Edit Entry';
    populateCategorySelectors();
    setModalEntryType(item.type || 'login');
    document.getElementById('entry-category').value = item.category || 'General';
    document.getElementById('entry-service').value = item.service;
    document.getElementById('entry-user').value = item.user || '';
    document.getElementById('entry-pass').value = item.pass;
    const expEl = document.getElementById('entry-card-expiry');
    if (expEl) expEl.value = item.cardExpiry || '';
    const cvvEl = document.getElementById('entry-card-cvv');
    if (cvvEl) cvvEl.value = item.cardCvv || '';
    const totpEl = document.getElementById('entry-totp');
    if (totpEl) totpEl.value = item.totp || '';
    const tagsEl = document.getElementById('entry-tags');
    if (tagsEl) tagsEl.value = (item.tags || []).join(', ');
    document.getElementById('entry-notes').value = item.notes || '';
    
    const pwInput = document.getElementById('entry-pass');
    if (pwInput) pwInput.type = 'password';
    
    analyzeEntryPasswordStrength(item.pass);
    syncFloatingLabels();
    document.getElementById('modal').classList.add('active');
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
}

function analyzeEntryPasswordStrength(password) {
    const rating = assessPasswordStrength(password);
    const fill = document.getElementById('modal-strength-fill');
    const label = document.getElementById('modal-strength-label');
    
    if (fill) {
        fill.className = `strength-bar-fill strength-${rating.token}`;
    }
    if (label) {
        label.innerText = rating.warning ? `${rating.label} (${rating.warning})` : rating.label;
        label.className = `text-${rating.token}`;
    }
}

/**
 * Handles saving credential record across all entry types.
 */
async function saveEntry() {
    const type = currentEntryType || 'login';
    const meta = ENTRY_TYPE_META[type] || ENTRY_TYPE_META.login;
    const category = document.getElementById('entry-category').value;
    const service = document.getElementById('entry-service').value.trim();
    const user = document.getElementById('entry-user').value.trim();
    const pass = document.getElementById('entry-pass').value;
    const cardExpiry = document.getElementById('entry-card-expiry') ? document.getElementById('entry-card-expiry').value.trim() : '';
    const cardCvv = document.getElementById('entry-card-cvv') ? document.getElementById('entry-card-cvv').value.trim() : '';
    const totp = (type === 'login' && document.getElementById('entry-totp')) ? document.getElementById('entry-totp').value.trim() : '';
    const tagsRaw = document.getElementById('entry-tags') ? document.getElementById('entry-tags').value.trim() : '';
    const notes = document.getElementById('entry-notes').value;
    
    if (!service || !pass) {
        return alert(`${meta.serviceLabel} and ${meta.passLabel} are required.`);
    }

    if (totp) {
        try {
            parseTotpInput(totp);
        } catch (err) {
            return alert(`Invalid TOTP secret or URI: ${err.message}`);
        }
    }
    
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim().toLowerCase()).filter(Boolean) : [];
    const record = {
        id: currentEditId !== null ? currentEditId : (Date.now() + Math.floor(Math.random() * 100)),
        type,
        category,
        service,
        user,
        pass,
        totp,
        tags,
        notes
    };
    if (type === 'card') {
        if (cardExpiry) record.cardExpiry = cardExpiry;
        if (cardCvv) record.cardCvv = cardCvv;
    }
    
    if (currentEditId !== null) {
        const index = vaultData.findIndex(i => i.id === currentEditId);
        vaultData[index] = record;
        showToast("Entry updated.");
    } else {
        vaultData.push(record);
        showToast("New entry created.");
    }
    
    closeModal();
    renderDashboard();
    renderVault();
    resetAutoLock();
    await persistEncryptedVault();
}

async function deleteEntry(id) {
    if (confirm("Are you sure you want to delete this credential?")) {
        vaultData = vaultData.filter(i => i.id !== id);
        renderDashboard();
        renderVault();
        resetAutoLock();
        await persistEncryptedVault();
        showToast("Entry deleted.");
    }
}

// --- Password Generator Logic ---

/**
 * Generates cryptographically secure random password using rejection sampling to prevent modulo bias.
 */
function generatePassword() {
    const lengthInput = document.getElementById('modal-gen-length');
    const length = lengthInput ? Math.min(64, Math.max(8, parseInt(lengthInput.value, 10) || 16)) : 16;
    
    const incLower = document.getElementById('modal-gen-lower')?.checked ?? true;
    const incUpper = document.getElementById('modal-gen-upper')?.checked ?? true;
    const incNumbers = document.getElementById('modal-gen-numbers')?.checked ?? true;
    const incSymbols = document.getElementById('modal-gen-symbols')?.checked ?? true;
    
    let charset = '';
    if (incLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (incUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (incNumbers) charset += '0123456789';
    if (incSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (!charset) return '';
    
    let generated = '';
    const maxUint32 = 0xFFFFFFFF;
    const range = maxUint32 - (maxUint32 % charset.length);
    
    while (generated.length < length) {
        const rand = new Uint32Array(1);
        crypto.getRandomValues(rand);
        if (rand[0] < range) {
            generated += charset.charAt(rand[0] % charset.length);
        }
    }
    return generated;
}

function fillGeneratedPass() {
    const pass = generatePassword();
    if (!pass) {
        return alert("Select at least one character set (A-Z, a-z, 0-9, or !@#$) to generate a password.");
    }
    modalPassWasGenerated = true;
    document.getElementById('entry-pass').value = pass;
    analyzeEntryPasswordStrength(pass);
    syncFloatingLabels();
}

// --- Import & Export Mechanics ---

function handleUniversalImport(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const extension = file.name.split('.').pop().toLowerCase();
    
    if (extension === 'csv') {
        handleCSVImport(file);
    } else if (extension === 'json') {
        handleJSONImport(file);
    } else if (extension === 'xml') {
        handleXMLImport(file);
    } else {
        alert("Unsupported file type. SecureVault parses standard .csv, .json, or KeePass .xml exports.");
    }
    event.target.value = '';
}

function unescapeXmlEntities(str) {
    if (!str) return '';
    return String(str)
        .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
        .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
}

/**
 * Parses a KeePass 2.x / KeePassXC XML export (<KeePassFile>) into SecureVault entries.
 * Strips <History> blocks so old password revisions are not imported as duplicate entries.
 */
function parseKeePassXML(xmlText) {
    if (!xmlText || typeof xmlText !== 'string') return [];
    const cleaned = xmlText.replace(/<History\b[^>]*>[\s\S]*?<\/History>/gi, '');

    const parsed = [];
    const groupStack = [];
    const tokenRegex = /<Group\b[^>]*>([\s\S]*?)(?=<Group\b|<\/Group>|<Entry\b)|<\/Group>|<Entry\b[^>]*>([\s\S]*?)<\/Entry>/gi;

    let match;
    let index = 0;
    while ((match = tokenRegex.exec(cleaned)) !== null) {
        if (match[0].startsWith('</Group') || match[0].startsWith('</group')) {
            groupStack.pop();
            continue;
        }
        if (match[1] !== undefined) {
            const nameMatch = match[1].match(/<Name>([\s\S]*?)<\/Name>/i);
            const groupName = nameMatch ? unescapeXmlEntities(nameMatch[1]).trim() : '';
            groupStack.push(groupName);
            continue;
        }
        if (match[2] !== undefined) {
            const entryBody = match[2];
            const fields = {};
            const strRegex = /<String>\s*<Key>([\s\S]*?)<\/Key>\s*<Value[^>]*>([\s\S]*?)<\/Value>\s*<\/String>/gi;
            let sm;
            while ((sm = strRegex.exec(entryBody)) !== null) {
                const key = unescapeXmlEntities(sm[1]).trim().toLowerCase();
                fields[key] = unescapeXmlEntities(sm[2]);
            }

            const service = (fields['title'] || fields['url'] || '').trim();
            const user = (fields['username'] || '').trim();
            const pass = fields['password'] || '';
            const totp = (fields['otp'] || fields['totp seed'] || fields['totp'] || '').trim();
            const notes = (fields['notes'] || '').trim();

            const tagsMatch = entryBody.match(/<Tags>([\s\S]*?)<\/Tags>/i);
            const tagsRaw = tagsMatch ? unescapeXmlEntities(tagsMatch[1]) : '';
            const tags = tagsRaw ? tagsRaw.split(/[,;]/).map(t => t.trim().toLowerCase()).filter(Boolean) : [];

            let category = 'General';
            for (let i = groupStack.length - 1; i >= 0; i--) {
                const g = groupStack[i];
                if (g && !/^(root|database|keepass|passwords|recycle bin|trash)$/i.test(g)) {
                    category = g;
                    break;
                }
            }

            if (service && pass) {
                const entry = {
                    id: Date.now() + index++,
                    category,
                    service,
                    user,
                    pass,
                    tags,
                    notes
                };
                if (totp) entry.totp = totp;
                parsed.push(entry);
            }
        }
    }
    return parsed;
}

function handleXMLImport(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const imported = parseKeePassXML(e.target.result);
            vaultData.push(...imported);
            renderDashboard();
            renderVault();
            await persistEncryptedVault();
            showToast(`Imported ${imported.length} KeePass XML entries.`);
        } catch (err) {
            alert("Error parsing KeePass XML file.");
        }
    };
    reader.readAsText(file);
}

function parseJSONImportData(jsonString) {
    const data = typeof jsonString === 'string' ? JSON.parse(jsonString) : jsonString;
    const items = Array.isArray(data) ? data : (data.items || []);
    const folderMap = new Map();
    if (data && Array.isArray(data.folders)) {
        data.folders.forEach(f => {
            if (f && f.id && f.name) {
                folderMap.set(f.id, String(f.name).trim());
            }
        });
    }
    const parsed = [];
    
    items.forEach((item, index) => {
        let type = (typeof item.type === 'string' && ENTRY_TYPE_META[item.type]) ? item.type : 'login';
        let service = item.service || item.name || item.title || '';
        let user = item.user || item.username || '';
        let pass = item.pass || item.password || '';
        let totp = item.totp || '';
        let cardExpiry = item.cardExpiry || '';
        let cardCvv = item.cardCvv || '';
        let notes = item.notes || '';
        let category = item.category || item.folder || (item.folderId && folderMap.get(item.folderId)) || 'General';
        let tagsRaw = item.tags ? (Array.isArray(item.tags) ? item.tags : String(item.tags).split(/[,;]/)) : [];
        let tags = tagsRaw.map(t => String(t).trim().toLowerCase()).filter(Boolean);
        
        if (item.login) {
            type = 'login';
            if (!user) user = item.login.username || '';
            if (!pass) pass = item.login.password || '';
            if (!totp) totp = item.login.totp || '';
        } else if (item.card) {
            type = 'card';
            if (!user) user = item.card.cardholderName || '';
            if (!pass) pass = item.card.number || '';
            if (!cardExpiry && (item.card.expMonth || item.card.expYear)) {
                cardExpiry = `${String(item.card.expMonth || '').padStart(2, '0')}/${String(item.card.expYear || '').slice(-2)}`;
            }
            if (!cardCvv) cardCvv = item.card.code || '';
        } else if (item.identity) {
            type = 'identity';
            const fullName = [item.identity.firstName, item.identity.lastName].filter(Boolean).join(' ');
            if (!user) user = fullName || item.identity.username || '';
            if (!pass) pass = item.identity.passportNumber || item.identity.licenseNumber || item.identity.ssn || item.identity.phone || item.identity.email || '';
        } else if (item.sshKey) {
            type = 'ssh';
            if (!user) user = item.sshKey.keyFingerprint || item.sshKey.publicKey || '';
            if (!pass) pass = item.sshKey.privateKey || '';
        } else if (item.type === 2 && !pass && notes) {
            // Bitwarden Secure Note: store note body in masked/revealable pass field
            type = 'identity';
            if (!user) user = 'Secure Note';
            pass = notes;
        }
        
        if (service && (pass || user || notes)) {
            const entry = {
                id: Date.now() + index,
                type,
                category: category,
                service: service.trim(),
                user: user.trim(),
                pass: pass || '',
                tags: tags,
                notes: notes.trim()
            };
            if (totp && String(totp).trim() && type === 'login') {
                entry.totp = String(totp).trim();
            }
            if (type === 'card') {
                if (cardExpiry) entry.cardExpiry = String(cardExpiry).trim();
                if (cardCvv) entry.cardCvv = String(cardCvv).trim();
            }
            parsed.push(entry);
        }
    });
    return parsed;
}

function handleJSONImport(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const imported = parseJSONImportData(e.target.result);
            vaultData.push(...imported);
            renderDashboard();
            renderVault();
            await persistEncryptedVault();
            showToast(`Imported ${imported.length} records successfully.`);
        } catch (err) {
            alert("Error parsing JSON file. Check format.");
        }
    };
    reader.readAsText(file);
}

function handleCSVImport(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const rows = parseCSVContent(e.target.result);
            if (rows.length === 0) return;
            
            let count = 0;
            const header = rows[0].map(h => String(h).toLowerCase().trim());
            
            const findIndex = (fields) => {
                for (const field of fields) {
                    const idx = header.indexOf(field.toLowerCase());
                    if (idx !== -1) return idx;
                }
                return -1;
            };
            
            const serviceIdx = findIndex(['service', 'name', 'url', 'title', 'account']);
            const userIdx = findIndex(['username', 'login_username', 'user', 'login name']);
            const passIdx = findIndex(['password', 'login_password', 'pass']);
            const totpIdx = findIndex(['totp', 'login_totp', 'otp']);
            const notesIdx = findIndex(['notes', 'extra', 'description', 'comments']);
            const categoryIdx = findIndex(['category', 'folder', 'grouping', 'group']);
            const tagsIdx = findIndex(['tags', 'tag', 'labels']);
            
            const hasHeader = (serviceIdx !== -1 || userIdx !== -1 || passIdx !== -1);
            const startRow = hasHeader ? 1 : 0;
            
            for (let i = startRow; i < rows.length; i++) {
                const row = rows[i];
                if (row.length < 2) continue;
                
                let service = "", user = "", pass = "", totp = "", notes = "", category = "General", tags = [];
                
                if (hasHeader) {
                    if (serviceIdx !== -1) service = row[serviceIdx] || "";
                    if (userIdx !== -1) user = row[userIdx] || "";
                    if (passIdx !== -1) pass = row[passIdx] || "";
                    if (totpIdx !== -1) totp = row[totpIdx] || "";
                    if (notesIdx !== -1) notes = row[notesIdx] || "";
                    if (categoryIdx !== -1) category = row[categoryIdx] || "General";
                    if (tagsIdx !== -1 && row[tagsIdx]) {
                        tags = row[tagsIdx].split(/[,;]/).map(t => t.trim().toLowerCase()).filter(Boolean);
                    }
                } else {
                    service = row[0] || "";
                    user = row[1] || "";
                    pass = row[2] || "";
                    notes = row[3] || "";
                }
                
                if (service && pass) {
                    const entry = {
                        id: Date.now() + Math.floor(Math.random() * 1000) + count,
                        category: category,
                        service: service.trim(),
                        user: user.trim(),
                        pass: pass,
                        tags: tags,
                        notes: notes.trim()
                    };
                    if (totp.trim()) entry.totp = totp.trim();
                    vaultData.push(entry);
                    count++;
                }
            }
            
            renderDashboard();
            renderVault();
            await persistEncryptedVault();
            showToast(`Imported ${count} entries.`);
        } catch (e) {
            alert("Error parsing CSV data.");
        }
    };
    reader.readAsText(file);
}

function parseCSVContent(text) {
    const rows = [];
    let current = '';
    let inQuotes = false;
    let parts = [];
    
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        if (char === '"') {
            if (inQuotes && text[i+1] === '"') {
                current += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (char === ',' && !inQuotes) {
            parts.push(current.trim());
            current = '';
        } else if ((char === '\n' || char === '\r') && !inQuotes) {
            if (current || parts.length > 0) {
                parts.push(current.trim());
                rows.push(parts);
                parts = [];
                current = '';
            }
            if (char === '\r' && text[i+1] === '\n') i++;
        } else {
            current += char;
        }
    }
    if (current || parts.length > 0) {
        parts.push(current.trim());
        rows.push(parts);
    }
    return rows;
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const content = JSON.parse(e.target.result);
            if (!content.salt || !content.iv || !content.data) {
                throw new Error();
            }
            
            salt = base64ToUint8(content.salt);
            pendingData = { iv: content.iv, data: content.data };
            showUnlockPrompt();
            showToast("Vault file loaded. Enter your Master Password.");
        } catch (err) {
            alert("Invalid vault file format.");
        }
    };
    reader.readAsText(file);
}

function triggerFileSelect() {
    const fileInput = document.getElementById('file-input');
    if (fileInput) fileInput.click();
}

// --- GitHub REST API Cloud Sync ($0 Free) ---

/**
 * Pushes the encrypted vault state directly to GitHub repository via GitHub REST API.
 */
async function pushToGitHub() {
    if (!masterKey) return alert("Vault must be unlocked to push data to GitHub.");
    
    const token = document.getElementById('setting-gh-token').value.trim();
    const owner = document.getElementById('setting-gh-owner').value.trim();
    const repo = document.getElementById('setting-gh-repo').value.trim();
    const path = 'my_passwords.vault';
    
    if (!token || !owner || !repo) {
        return alert("Please fill in your GitHub Personal Access Token, Repository Owner, and Repository Name.");
    }
    
    showToast("Encrypting & pushing to GitHub...");
    
    try {
        const encrypted = await encrypt(vaultData, masterKey);
        const payload = {
            salt: uint8ToBase64(salt),
            iv: encrypted.iv,
            data: encrypted.data
        };
        const payloadString = JSON.stringify(payload, null, 2);
        
        const bytes = new TextEncoder().encode(payloadString);
        const contentBase64 = uint8ToBase64(bytes);
        
        const getUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
        let sha = null;
        
        const getRes = await fetch(getUrl, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        if (getRes.ok) {
            const getData = await getRes.json();
            sha = getData.sha;
        }
        
        const putBody = {
            message: `Update encrypted vault payload [SecureVault App]`,
            content: contentBase64,
            branch: 'master'
        };
        if (sha) putBody.sha = sha;
        
        const putRes = await fetch(getUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(putBody)
        });
        
        if (!putRes.ok) {
            const errData = await putRes.json();
            throw new Error(errData.message || 'GitHub API rejected commit');
        }
        
        showToast("Synced encrypted vault to GitHub!");
        alert(`Success!\n\nEncrypted vault committed and pushed to GitHub repository:\nhttps://github.com/${owner}/${repo}`);
    } catch (err) {
        alert("GitHub Sync Error: " + err.message);
    }
}

/**
 * Pulls the latest encrypted vault payload from GitHub repository via GitHub REST API.
 */
async function pullFromGitHub() {
    const token = document.getElementById('setting-gh-token').value.trim();
    const owner = document.getElementById('setting-gh-owner').value.trim();
    const repo = document.getElementById('setting-gh-repo').value.trim();
    const path = 'my_passwords.vault';
    
    if (!token || !owner || !repo) {
        return alert("Please fill in your GitHub Personal Access Token, Repository Owner, and Repository Name.");
    }
    
    showToast("Pulling encrypted vault from GitHub...");
    
    try {
        const getUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
        const getRes = await fetch(getUrl, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        
        if (!getRes.ok) {
            const errData = await getRes.json();
            throw new Error(errData.message || 'File not found on GitHub repo');
        }
        
        const getData = await getRes.json();
        
        const cleanBase64 = getData.content.replace(/\s/g, '');
        const bytes = base64ToUint8(cleanBase64);
        const payloadString = new TextDecoder().decode(bytes);
        
        const content = JSON.parse(payloadString);
        if (!content.salt || !content.iv || !content.data) {
            throw new Error("Invalid vault payload structure on GitHub.");
        }
        
        salt = base64ToUint8(content.salt);
        
        if (masterKey) {
            vaultData = await decrypt(content.data, content.iv, masterKey);
            renderDashboard();
            renderVault();
            showToast("Latest vault pulled and decrypted from GitHub!");
        } else {
            pendingData = { iv: content.iv, data: content.data };
            showUnlockPrompt();
            showToast("Latest vault loaded from GitHub. Ready to unlock.");
        }
    } catch (err) {
        alert("GitHub Pull Error: " + err.message);
    }
}

/**
 * Encrypts state and triggers a browser download of the encrypted vault file.
 */
async function saveVaultFile() {
    if (!masterKey) return;
    
    try {
        const encrypted = await encrypt(vaultData, masterKey);
        const payload = {
            salt: uint8ToBase64(salt),
            iv: encrypted.iv,
            data: encrypted.data
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'my_passwords.vault';
        a.click();
        
        showToast("Vault file downloaded.");
        alert("Success!\n\nYour encrypted 'my_passwords.vault' file has been saved to your Downloads folder.\n\nREMINDER: Copy this file to a secure thumbdrive/USB stick now.");
    } catch (err) {
        alert("Failed to encrypt and save vault: " + err.message);
    }
}

function exportToJson() {
    if (!masterKey || vaultData.length === 0) {
        return alert("Vault is empty or locked.");
    }
    
    const blob = new Blob([JSON.stringify(vaultData, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vault_export_unencrypted.json';
    a.click();
    showToast("Exported unencrypted JSON.");
}

function exportToCsv() {
    if (!masterKey || vaultData.length === 0) {
        return alert("Vault is empty or locked.");
    }
    
    const headers = ["Service", "Username", "Password", "TOTP", "Category", "Tags", "Notes"];
    const rows = vaultData.map(item => [
        item.service,
        item.user,
        item.pass,
        item.totp || '',
        item.category,
        (item.tags || []).join(';'),
        item.notes || ''
    ]);
    
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vault_export_unencrypted.csv';
    a.click();
    showToast("Exported unencrypted CSV.");
}

// --- Interface Helper & Toast Utilities ---

function updateOnlineStatus() {
    if (typeof document === 'undefined') return;
    const badge = document.querySelector('.offline-badge');
    if (!badge) return;
    
    const online = navigator.onLine;
    badge.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M1 1v22h22V1H1zm20 20H3V3h18v18z"/>
            <path d="M9.5 8.5l5 5m0-5l-5 5"/>
        </svg>
        <span>${online ? 'Secure Local' : 'Strict Offline'}</span>
    `;
    badge.className = online ? 'offline-badge' : 'offline-badge strict-offline';
    badge.title = online ? 'Offline secure environment' : 'No network connection active (Maximum Security)';
}

// Shared visibility-toggle icons (open eye / slashed eye)
const EYE_OPEN_SVG = `
    <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
    </svg>
`;
const EYE_CLOSED_SVG = `
    <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
`;

/**
 * Handles password input visibility toggle (eye SVG switch).
 */
function togglePasswordInput(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    const button = input.nextElementSibling;

    if (input.type === 'password') {
        input.type = 'text';
        if (button) button.innerHTML = EYE_CLOSED_SVG;
    } else {
        input.type = 'password';
        if (button) button.innerHTML = EYE_OPEN_SVG;
    }
}

/**
 * Reveals / hides a credential's password inline within its vault ledger row.
 */
function toggleEntryReveal(passRow, btn) {
    if (!passRow) return;
    const isHidden = passRow.classList.contains('hidden');

    passRow.classList.toggle('hidden', !isHidden);
    btn.innerHTML = isHidden ? EYE_CLOSED_SVG : EYE_OPEN_SVG;
    btn.title = isHidden ? 'Hide Password' : 'Reveal Password';
    btn.setAttribute('aria-label', btn.title);
    resetAutoLock();
}

/**
 * Theme toggle handler ("Warm Editorial" light / "Midnight Executive" dark).
 */
function toggleTheme() {
    const root = document.documentElement;
    const next = root.getAttribute('data-theme') === 'editorial-light'
        ? 'executive-dark'
        : 'editorial-light';
    root.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
}

/**
 * Copies password text to clipboard, starting a 30s auto-wipe countdown indicator.
 */
function copyCredentialPassword(text) {
    if (!text) return;
    
    if (window.AndroidVaultBridge && typeof window.AndroidVaultBridge.copyToClipboard === 'function') {
        window.AndroidVaultBridge.copyToClipboard("Password", text, true);
    }

    const startCountdown = () => {
        let seconds = 30;
        clearInterval(clipboardClearTimer);
        
        const tick = () => {
            if (seconds <= 0) {
                clearInterval(clipboardClearTimer);
                if (window.AndroidVaultBridge && typeof window.AndroidVaultBridge.copyToClipboard === 'function') {
                    window.AndroidVaultBridge.copyToClipboard("Password", "", true);
                } else if (navigator.clipboard) {
                    navigator.clipboard.writeText('');
                }
                showToast("Clipboard cleared for safety.");
            } else {
                showToast("Password copied to clipboard.", seconds--);
            }
        };
        tick();
        clipboardClearTimer = setInterval(tick, 1000);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(startCountdown).catch(startCountdown);
    } else {
        startCountdown();
    }
}

/**
 * Displays a toast notification. Pass a `countdown` number to render a live
 * clipboard auto-clear indicator; countdown toasts do not auto-hide.
 */
function showToast(msg, countdown) {
    clearTimeout(toastHideTimeout);
    
    const toast = document.getElementById('toast');
    const msgEl = document.getElementById('toast-message');
    const ring = document.getElementById('toast-countdown-ring');
    
    if (msgEl) msgEl.innerText = countdown ? `${msg} (Clears in ${countdown}s)` : msg;
    if (ring) ring.style.display = countdown ? 'block' : 'none';
    if (!toast) return;
    
    toast.classList.add('active');
    if (!countdown) {
        toastHideTimeout = setTimeout(() => {
            toast.classList.remove('active');
        }, 2500);
    }
}

// --- Global Event Handling & Auto-Init ---

if (typeof window !== 'undefined') {
    ['mousedown', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach(evt => {
        window.addEventListener(evt, resetAutoLock, true);
    });

    ['input', 'change'].forEach(evt => {
        window.addEventListener(evt, syncFloatingLabels, true);
    });

    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);

    window.onload = () => {
        const saved = localStorage.getItem('theme');
        if (saved === 'light' || saved === 'editorial-light') {
            document.documentElement.setAttribute('data-theme', 'editorial-light');
        } else if (saved === 'dark' || saved === 'executive-dark') {
            document.documentElement.setAttribute('data-theme', 'executive-dark');
        }
        updateOnlineStatus();
        checkSavedVault();
        syncFloatingLabels();
    };
}

// Exports for testing in Node.js environments
export {
    calculateEntropy,
    assessPasswordStrength,
    deriveKey,
    encrypt,
    decrypt,
    base32ToUint8,
    parseTotpInput,
    generateTOTP,
    base64ToUint8,
    uint8ToBase64,
    escapeHtml,
    parseCSVContent,
    parseJSONImportData,
    parseKeePassXML,
    getReusedPasswordSet
};

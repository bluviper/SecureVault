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

// --- Cryptographic & Utility Functions ---

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

/**
 * Calculates entropy-based strength for a password.
 */
function calculateEntropy(password) {
    if (!password) return 0;
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    
    if (charsetSize === 0) return 0;
    return Math.round(password.length * Math.log2(charsetSize));
}

/**
 * Returns strength classification object mapped to semantic theme tokens (danger, warning, success).
 */
function assessPasswordStrength(password) {
    if (!password) return { score: 0, label: 'None', token: 'muted' };
    if (password.length < 8) return { score: 1, label: 'Weak', token: 'danger' };
    
    const entropy = calculateEntropy(password);
    
    if (entropy < 40 || password.length < 10) {
        return { score: 1, label: 'Weak', token: 'danger' };
    } else if (entropy < 70 || password.length < 14) {
        return { score: 2, label: 'Medium', token: 'warning' };
    } else {
        return { score: 3, label: 'Strong', token: 'success' };
    }
}

/**
 * Returns a Set of passwords that appear more than once in the active vault.
 */
function getReusedPasswordSet() {
    const counts = new Map();
    vaultData.forEach(item => {
        if (item.pass) {
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
 * Persists current encrypted vault state in browser local storage.
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
        localStorage.setItem('securevault_encrypted_payload', JSON.stringify(payload));
    } catch (e) {
        console.error("Failed to persist encrypted vault locally", e);
    }
}

/**
 * Checks for previously saved encrypted vault in browser local storage.
 */
function checkSavedVault() {
    if (typeof localStorage === 'undefined') return false;
    const saved = localStorage.getItem('securevault_encrypted_payload');
    if (saved) {
        try {
            const content = JSON.parse(saved);
            if (content.salt && content.iv && content.data) {
                salt = base64ToUint8(content.salt);
                pendingData = { iv: content.iv, data: content.data };
                showUnlockPrompt();
                return true;
            }
        } catch (e) {
            localStorage.removeItem('securevault_encrypted_payload');
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
    clearTimeout(clipboardClearTimer);
    
    const progressBar = document.getElementById('auto-lock-progressbar');
    if (progressBar) progressBar.style.transform = 'scaleX(0)';

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
    
    if (tab === 'generator') {
        const genResult = document.getElementById('gen-result');
        if (!genResult || genResult.innerText === "Select options") {
            generatePassword();
        }
    }
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
        
        // Active Dashboard stats filters
        let matchesDashboard = true;
        if (activeDashboardFilter === 'weak') {
            matchesDashboard = assessPasswordStrength(item.pass).label === 'Weak';
        } else if (activeDashboardFilter === 'reused') {
            matchesDashboard = item.pass && reusedSet.has(item.pass);
        } else if (activeDashboardFilter === 'vulnerable') {
            matchesDashboard = item.pass.length < 12;
        }
        
        return matchesSearch && matchesCategory && matchesDashboard;
    });

    if (filtered.length === 0) {
        list.innerHTML = `
            <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                <p>No credentials found matching filters.</p>
            </div>
        `;
        return;
    }
    
    filtered.forEach((item, index) => {
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
        
        const badge = document.createElement('span');
        badge.className = 'badge-tag';
        badge.innerText = item.category || 'General';
        
        titleRow.appendChild(h4);
        titleRow.appendChild(badge);
        
        const userP = document.createElement('p');
        userP.className = 'item-user-text';
        userP.innerText = item.user || 'No username';

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
        
        const rating = assessPasswordStrength(item.pass);
        const dot = document.createElement('span');
        dot.className = `status-indicator-dot online bg-${rating.token}`;
        
        const label = document.createElement('span');
        label.className = `strength-text-label text-${rating.token}`;
        label.innerText = rating.label;
        
        secRow.appendChild(dot);
        secRow.appendChild(label);
        
        if (item.pass && reusedSet.has(item.pass)) {
            const reuseLabel = document.createElement('span');
            reuseLabel.className = 'strength-text-label text-warning';
            reuseLabel.innerText = '• Reused';
            reuseLabel.style.marginLeft = '8px';
            secRow.appendChild(reuseLabel);
        }
        
        info.appendChild(titleRow);
        info.appendChild(userP);
        info.appendChild(secRow);
        
        // Actions
        const actions = document.createElement('div');
        actions.className = 'item-actions';
        
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-action-icon';
        copyBtn.title = 'Copy Password';
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
        deleteBtn.onclick = () => deleteEntry(item.id);
        deleteBtn.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <polyline points="3 6 5 6 21 6"/>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
        `;
        
        actions.appendChild(copyBtn);
        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);
        
        inner.appendChild(info);
        inner.appendChild(actions);
        outer.appendChild(inner);
        list.appendChild(outer);
    });
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

function showAddModal() {
    currentEditId = null;
    document.getElementById('modal-title').innerText = 'Add Entry';
    populateCategorySelectors();
    document.getElementById('entry-category').value = 'General';
    document.getElementById('entry-service').value = '';
    document.getElementById('entry-user').value = '';
    document.getElementById('entry-pass').value = '';
    const tagsEl = document.getElementById('entry-tags');
    if (tagsEl) tagsEl.value = '';
    document.getElementById('entry-notes').value = '';
    
    const pwInput = document.getElementById('entry-pass');
    if (pwInput) pwInput.type = 'password';
    
    analyzeEntryPasswordStrength('');
    document.getElementById('modal').classList.add('active');
}

function showEditModal(id) {
    const item = vaultData.find(i => i.id === id);
    if (!item) return;
    
    currentEditId = id;
    document.getElementById('modal-title').innerText = 'Edit Entry';
    populateCategorySelectors();
    document.getElementById('entry-category').value = item.category || 'General';
    document.getElementById('entry-service').value = item.service;
    document.getElementById('entry-user').value = item.user || '';
    document.getElementById('entry-pass').value = item.pass;
    const tagsEl = document.getElementById('entry-tags');
    if (tagsEl) tagsEl.value = (item.tags || []).join(', ');
    document.getElementById('entry-notes').value = item.notes || '';
    
    const pwInput = document.getElementById('entry-pass');
    if (pwInput) pwInput.type = 'password';
    
    analyzeEntryPasswordStrength(item.pass);
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
        label.innerText = rating.label;
        label.className = `text-${rating.token}`;
    }
}

/**
 * Handles saving password record.
 */
async function saveEntry() {
    const category = document.getElementById('entry-category').value;
    const service = document.getElementById('entry-service').value.trim();
    const user = document.getElementById('entry-user').value.trim();
    const pass = document.getElementById('entry-pass').value;
    const tagsRaw = document.getElementById('entry-tags') ? document.getElementById('entry-tags').value.trim() : '';
    const notes = document.getElementById('entry-notes').value;
    
    if (!service || !pass) {
        return alert("Service name and password are required.");
    }
    
    const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim().toLowerCase()).filter(Boolean) : [];
    
    if (currentEditId !== null) {
        const index = vaultData.findIndex(i => i.id === currentEditId);
        vaultData[index] = { 
            id: currentEditId, 
            category, 
            service, 
            user, 
            pass,
            tags,
            notes 
        };
        showToast("Entry updated.");
    } else {
        vaultData.push({ 
            id: Date.now() + Math.floor(Math.random() * 100), 
            category, 
            service, 
            user, 
            pass,
            tags,
            notes 
        });
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
    const lengthInput = document.getElementById('gen-length');
    const length = lengthInput ? parseInt(lengthInput.value) || 16 : 16;
    
    const incLower = document.getElementById('gen-lower')?.checked ?? true;
    const incUpper = document.getElementById('gen-upper')?.checked ?? true;
    const incNumbers = document.getElementById('gen-numbers')?.checked ?? true;
    const incSymbols = document.getElementById('gen-symbols')?.checked ?? true;
    
    let charset = '';
    if (incLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (incUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (incNumbers) charset += '0123456789';
    if (incSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (!charset) {
        document.getElementById('gen-result').innerText = "Select options";
        return;
    }
    
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
    
    const genResult = document.getElementById('gen-result');
    if (genResult) genResult.innerText = generated;
    
    const strength = assessPasswordStrength(generated);
    const fill = document.getElementById('gen-strength-fill');
    const label = document.getElementById('gen-strength-label');
    
    if (fill) fill.className = `strength-bar-fill strength-${strength.token}`;
    if (label) {
        label.innerText = strength.label;
        label.className = `text-${strength.token}`;
    }
}

function copyGeneratedPassword() {
    const pass = document.getElementById('gen-result')?.innerText;
    if (!pass || pass === "Select options") return;
    copyCredentialPassword(pass);
}

function fillGeneratedPass() {
    generatePassword();
    const pass = document.getElementById('gen-result')?.innerText;
    if (pass && pass !== "Select options") {
        document.getElementById('entry-pass').value = pass;
        analyzeEntryPasswordStrength(pass);
    }
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
    } else {
        alert("Unsupported file type. SecureVault parses standard .csv or .json datasets.");
    }
    event.target.value = '';
}

function parseJSONImportData(jsonString) {
    const data = typeof jsonString === 'string' ? JSON.parse(jsonString) : jsonString;
    const items = Array.isArray(data) ? data : (data.items || []);
    const parsed = [];
    
    items.forEach((item, index) => {
        let service = item.service || item.name || item.title || '';
        let user = item.user || item.username || '';
        let pass = item.pass || item.password || '';
        let notes = item.notes || '';
        let category = item.category || item.folder || 'General';
        let tagsRaw = item.tags ? (Array.isArray(item.tags) ? item.tags : String(item.tags).split(/[,;]/)) : [];
        let tags = tagsRaw.map(t => String(t).trim().toLowerCase()).filter(Boolean);
        
        if (item.login) {
            if (!user) user = item.login.username || '';
            if (!pass) pass = item.login.password || '';
        }
        
        if (service && pass) {
            parsed.push({
                id: Date.now() + index,
                category: category,
                service: service.trim(),
                user: user.trim(),
                pass: pass,
                tags: tags,
                notes: notes.trim()
            });
        }
    });
    return parsed;
}

function handleJSONImport(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const imported = parseJSONImportData(e.target.result);
            vaultData.push(...imported);
            renderDashboard();
            renderVault();
            showToast(`Imported ${imported.length} records successfully.`);
        } catch (err) {
            alert("Error parsing JSON file. Check format.");
        }
    };
    reader.readAsText(file);
}

function handleCSVImport(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
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
            
            const serviceIdx = findIndex(['service', 'name', 'url', 'title']);
            const userIdx = findIndex(['username', 'login_username', 'user']);
            const passIdx = findIndex(['password', 'login_password', 'pass']);
            const notesIdx = findIndex(['notes', 'extra', 'description']);
            const categoryIdx = findIndex(['category', 'folder', 'grouping']);
            const tagsIdx = findIndex(['tags', 'tag', 'labels']);
            
            const hasHeader = (serviceIdx !== -1 || userIdx !== -1 || passIdx !== -1);
            const startRow = hasHeader ? 1 : 0;
            
            for (let i = startRow; i < rows.length; i++) {
                const row = rows[i];
                if (row.length < 2) continue;
                
                let service = "", user = "", pass = "", notes = "", category = "General", tags = [];
                
                if (hasHeader) {
                    if (serviceIdx !== -1) service = row[serviceIdx] || "";
                    if (userIdx !== -1) user = row[userIdx] || "";
                    if (passIdx !== -1) pass = row[passIdx] || "";
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
                    vaultData.push({
                        id: Date.now() + Math.floor(Math.random() * 1000) + count,
                        category: category,
                        service: service.trim(),
                        user: user.trim(),
                        pass: pass,
                        tags: tags,
                        notes: notes.trim()
                    });
                    count++;
                }
            }
            
            renderDashboard();
            renderVault();
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

function triggerFileInput() {
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
 * Encrypts state and triggers browser download download.
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
    
    const headers = ["Service", "Username", "Password", "Category", "Tags", "Notes"];
    const rows = vaultData.map(item => [
        item.service,
        item.user,
        item.pass,
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

// --- Session & UI Settings Wipes ---

function confirmWipeSession() {
    if (confirm("Wipe entire local session? Any unsaved changes will be lost permanently if you have not exported your data file!")) {
        lockVault();
        location.reload();
    }
}

// --- Interface Helper & Toast Utilities ---

function updateOnlineStatus() {
    if (typeof document === 'undefined') return;
    const badge = document.querySelector('.offline-badge');
    if (!badge) return;
    if (navigator.onLine) {
        badge.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M1 1v22h22V1H1zm20 20H3V3h18v18z"/>
                <path d="M9.5 8.5l5 5m0-5l-5 5"/>
            </svg>
            <span>Secure Local</span>
        `;
        badge.className = 'offline-badge';
        badge.title = 'Offline secure environment';
    } else {
        badge.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M1 1v22h22V1H1zm20 20H3V3h18v18z"/>
                <path d="M9.5 8.5l5 5m0-5l-5 5"/>
            </svg>
            <span>Strict Offline</span>
        `;
        badge.className = 'offline-badge strict-offline';
        badge.title = 'No network connection active (Maximum Security)';
    }
}

/**
 * Handles password input visibility toggle (eye SVG switch).
 */
function togglePasswordInput(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    const button = input.nextElementSibling;
    
    if (input.type === 'password') {
        input.type = 'text';
        if (button) {
            button.innerHTML = `
                <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                    <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
            `;
        }
    } else {
        input.type = 'password';
        if (button) {
            button.innerHTML = `
                <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            `;
        }
    }
}

/**
 * Theme toggle handler (light mode/dark mode).
 */
function toggleTheme() {
    document.body.classList.toggle('light-mode');
    const isLight = document.body.classList.contains('light-mode');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
}

/**
 * Copies password text to clipboard, starting a 30s auto-wipe countdown indicator.
 */
function copyCredentialPassword(text) {
    if (!text) return;
    
    navigator.clipboard.writeText(text).then(() => {
        let seconds = 30;
        showCountdownToast("Password copied to clipboard.", seconds);
        
        clearInterval(clipboardClearTimer);
        
        clipboardClearTimer = setInterval(() => {
            seconds--;
            if (seconds <= 0) {
                clearInterval(clipboardClearTimer);
                navigator.clipboard.writeText('');
                showToast("Clipboard cleared for safety.");
            } else {
                updateCountdownToast(seconds);
            }
        }, 1000);
    });
}

/**
 * Displays a non-destructive notification toast without interrupting clipboard auto-clear timers.
 */
function showToast(msg) {
    clearTimeout(toastHideTimeout);
    
    const toast = document.getElementById('toast');
    const msgEl = document.getElementById('toast-message');
    const ring = document.getElementById('toast-countdown-ring');
    
    if (msgEl) msgEl.innerText = msg;
    if (ring) ring.style.display = 'none';
    
    if (toast) {
        toast.classList.add('active');
        toastHideTimeout = setTimeout(() => {
            toast.classList.remove('active');
        }, 2500);
    }
}

function showCountdownToast(msg, seconds) {
    const toast = document.getElementById('toast');
    const msgEl = document.getElementById('toast-message');
    const ring = document.getElementById('toast-countdown-ring');
    
    if (msgEl) msgEl.innerText = `${msg} (Clears in ${seconds}s)`;
    if (ring) ring.style.display = 'block';
    if (toast) toast.classList.add('active');
}

function updateCountdownToast(seconds) {
    const msgEl = document.getElementById('toast-message');
    if (msgEl) msgEl.innerText = `Password copied to clipboard. (Clears in ${seconds}s)`;
}

// --- Global Event Handling & Auto-Init ---

if (typeof window !== 'undefined') {
    ['mousedown', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach(evt => {
        window.addEventListener(evt, resetAutoLock, true);
    });

    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);

    window.onload = () => {
        if (localStorage.getItem('theme') === 'light') {
            document.body.classList.add('light-mode');
        }
        updateOnlineStatus();
        checkSavedVault();
    };
}

// Exports for testing in Node.js environments
export {
    calculateEntropy,
    assessPasswordStrength,
    deriveKey,
    encrypt,
    decrypt,
    base64ToUint8,
    uint8ToBase64,
    escapeHtml,
    parseCSVContent,
    parseJSONImportData,
    getReusedPasswordSet
};

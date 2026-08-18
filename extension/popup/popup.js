// SecureVault Extension Popup Logic

let masterKey = null;
let vaultData = [];
let activeTabDomain = '';

document.addEventListener('DOMContentLoaded', async () => {
    initTabDetection();
    bindEvents();
    checkSession();
});

async function initTabDetection() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            const url = new URL(tab.url);
            activeTabDomain = url.hostname.replace(/^www\./, '');
        }
    } catch (e) {
        console.log("Tab domain detection error:", e);
    }
}

function bindEvents() {
    document.getElementById('btn-unlock').addEventListener('click', handleUnlock);
    document.getElementById('popup-master-pass').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') handleUnlock();
    });
    
    document.getElementById('btn-load-file').addEventListener('click', () => {
        document.getElementById('popup-file-input').click();
    });
    document.getElementById('popup-file-input').addEventListener('change', handleFileLoad);

    document.getElementById('btn-pull-gh').addEventListener('click', handleGitHubPullPrompt);
    document.getElementById('btn-sync').addEventListener('click', handleGitHubPullPrompt);
    
    document.getElementById('btn-lock').addEventListener('click', lockVault);
    document.getElementById('popup-search').addEventListener('input', renderVaultList);

    // Nav tabs
    document.getElementById('tab-passwords').addEventListener('click', () => switchView('vault'));
    document.getElementById('tab-generator').addEventListener('click', () => {
        switchView('generator');
        generatePassword();
    });

    document.getElementById('gen-length').addEventListener('input', (e) => {
        document.getElementById('gen-length-val').innerText = e.target.value;
        generatePassword();
    });

    document.getElementById('btn-copy-gen').addEventListener('click', () => {
        const pass = document.getElementById('gen-result').innerText;
        copyTextToClipboard(pass);
    });
}

function switchView(pane) {
    document.querySelectorAll('.view-pane').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

    if (pane === 'vault') {
        document.getElementById('view-vault').classList.add('active');
        document.getElementById('tab-passwords').classList.add('active');
    } else if (pane === 'generator') {
        document.getElementById('view-generator').classList.add('active');
        document.getElementById('tab-generator').classList.add('active');
    }
}

async function checkSession() {
    chrome.runtime.sendMessage({ type: 'GET_SESSION' }, (response) => {
        if (response && response.vaultData) {
            vaultData = response.vaultData;
            showUnlockedState();
        }
    });
}

let pendingPayload = null;

async function handleUnlock() {
    const password = document.getElementById('popup-master-pass').value;
    if (!password) return showToast("Enter password");

    if (pendingPayload) {
        try {
            await decryptAndUnlock(pendingPayload, password);
            return;
        } catch (err) {
            return showToast("Invalid master password!");
        }
    }

    const fileInput = document.getElementById('popup-file-input');
    if (!fileInput.files || fileInput.files.length === 0) {
        return showToast("Please load a .vault file or pull from GitHub first.");
    }

    const file = fileInput.files[0];
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            pendingPayload = JSON.parse(e.target.result);
            await decryptAndUnlock(pendingPayload, password);
        } catch (err) {
            showToast("Invalid file or password!");
        }
    };
    reader.readAsText(file);
}

async function handleFileLoad(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                pendingPayload = JSON.parse(e.target.result);
                showToast(`Loaded ${file.name}. Enter password to unlock.`);
            } catch (err) {
                showToast("Invalid .vault file format.");
            }
        };
        reader.readAsText(file);
    }
}

async function handleGitHubPullPrompt() {
    const token = prompt("Enter your GitHub Access Token:");
    if (!token) return;
    const owner = prompt("Enter Repository Owner (default: bluviper):", "bluviper") || "bluviper";
    const repo = prompt("Enter Repository Name (default: SecureVault):", "SecureVault") || "SecureVault";
    
    const password = prompt("Enter Master Password to decrypt:");
    if (!password) return;

    showToast("Pulling from GitHub...");

    try {
        const url = `https://api.github.com/repos/${owner}/${repo}/contents/my_passwords.vault`;
        const res = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });

        if (!res.ok) throw new Error("GitHub file fetch failed");
        
        const data = await res.json();
        const cleanBase64 = data.content.replace(/\s/g, '');
        const binary = atob(cleanBase64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const payloadString = new TextDecoder().decode(bytes);
        const payload = JSON.parse(payloadString);

        await decryptAndUnlock(payload, password);
    } catch (err) {
        showToast("GitHub Pull failed: " + err.message);
    }
}

async function decryptAndUnlock(payload, password) {
    const salt = base64ToUint8(payload.salt);
    const key = await deriveKey(password, salt);
    const decrypted = await decrypt(payload.data, payload.iv, key);

    masterKey = key;
    vaultData = decrypted;

    // Save session in background worker
    chrome.runtime.sendMessage({ type: 'STORE_SESSION', vaultData: vaultData });
    showUnlockedState();
}

function showUnlockedState() {
    document.getElementById('view-lock').classList.remove('active');
    document.getElementById('view-vault').classList.add('active');
    document.getElementById('btn-lock').classList.remove('hidden');
    document.getElementById('popup-footer').classList.remove('hidden');

    if (activeTabDomain) {
        document.getElementById('domain-match-banner').classList.remove('hidden');
        document.getElementById('current-domain').innerText = activeTabDomain;
    }

    renderVaultList();
}

function lockVault() {
    masterKey = null;
    vaultData = [];
    chrome.runtime.sendMessage({ type: 'CLEAR_SESSION' });

    document.getElementById('view-vault').classList.remove('active');
    document.getElementById('view-generator').classList.remove('active');
    document.getElementById('view-lock').classList.add('active');
    document.getElementById('btn-lock').classList.add('hidden');
    document.getElementById('popup-footer').classList.add('hidden');
    document.getElementById('popup-master-pass').value = '';
    showToast("Vault locked");
}

function renderVaultList() {
    const listEl = document.getElementById('credentials-list');
    const query = document.getElementById('popup-search').value.toLowerCase();
    listEl.innerHTML = '';

    let items = [...vaultData];

    // Priority match for active tab domain
    if (activeTabDomain) {
        items.sort((a, b) => {
            const matchA = a.service.toLowerCase().includes(activeTabDomain);
            const matchB = b.service.toLowerCase().includes(activeTabDomain);
            return matchB - matchA;
        });
    }

    const filtered = items.filter(item => {
        const tags = (item.tags || []).join(' ').toLowerCase();
        return item.service.toLowerCase().includes(query) ||
               item.user.toLowerCase().includes(query) ||
               tags.includes(query);
    });

    if (filtered.length === 0) {
        listEl.innerHTML = `<div style="text-align:center; padding:20px; color:#94a3b8; font-size:0.8rem;">No passwords found.</div>`;
        return;
    }

    filtered.forEach(item => {
        const card = document.createElement('div');
        card.className = 'cred-card';

        const isDomainMatch = activeTabDomain && item.service.toLowerCase().includes(activeTabDomain);

        card.innerHTML = `
            <div class="cred-header">
                <span class="cred-title">${escapeHtml(item.service)} ${isDomainMatch ? '⭐' : ''}</span>
                <span style="font-size:0.65rem; color:#06b6d4; background:rgba(6,182,212,0.1); padding:2px 6px; border-radius:4px;">${escapeHtml(item.category || 'General')}</span>
            </div>
            <div class="cred-user">${escapeHtml(item.user || 'No username')}</div>
            <div class="cred-actions">
                <button class="btn-autofill" data-user="${escapeHtml(item.user)}" data-pass="${escapeHtml(item.pass)}">⚡ Auto-Fill</button>
                <button class="btn-copy btn-copy-pass" data-pass="${escapeHtml(item.pass)}">📋 Password</button>
                <button class="btn-copy btn-copy-user" data-user="${escapeHtml(item.user)}">👤 User</button>
            </div>
        `;

        // Bind button events
        card.querySelector('.btn-autofill').addEventListener('click', (e) => {
            const user = e.target.getAttribute('data-user');
            const pass = e.target.getAttribute('data-pass');
            chrome.runtime.sendMessage({ type: 'AUTOFILL_PAGE', username: user, password: pass }, () => {
                showToast("Auto-filled active tab!");
            });
        });

        card.querySelector('.btn-copy-pass').addEventListener('click', (e) => {
            const pass = e.target.getAttribute('data-pass');
            copyTextToClipboard(pass);
        });

        card.querySelector('.btn-copy-user').addEventListener('click', (e) => {
            const user = e.target.getAttribute('data-user');
            copyTextToClipboard(user);
        });

        listEl.appendChild(card);
    });
}

function generatePassword(length = 16) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
    let res = "";
    const maxUint32 = 0xFFFFFFFF;
    const range = maxUint32 - (maxUint32 % charset.length);
    
    while (res.length < length) {
        const rand = new Uint32Array(1);
        crypto.getRandomValues(rand);
        if (rand[0] < range) {
            res += charset.charAt(rand[0] % charset.length);
        }
    }
    document.getElementById('gen-result').innerText = res;
}

function copyTextToClipboard(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        showToast("Copied to clipboard!");
        setTimeout(() => {
            navigator.clipboard.writeText('');
        }, 30000);
    });
}

function showToast(msg) {
    const toast = document.getElementById('toast');
    document.getElementById('toast-msg').innerText = msg;
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 2500);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// --- CRYPTO HELPERS (Native Web Crypto API) ---
async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function decrypt(ciphertextBase64, ivBase64, key) {
    const ciphertext = base64ToUint8(ciphertextBase64);
    const iv = base64ToUint8(ivBase64);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decrypted));
}

function base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

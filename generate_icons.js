import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const iconsDir = path.join(__dirname, 'extension', 'icons');

if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
}

// 1. Cyber-Shield (Neon Cyan & Obsidian - Keyhole Shield)
const cyberShieldSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
    <defs>
        <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#0a0f1d"/>
            <stop offset="100%" stop-color="#030508"/>
        </linearGradient>
        <linearGradient id="neonCyan" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#06b6d4"/>
            <stop offset="100%" stop-color="#3b82f6"/>
        </linearGradient>
    </defs>
    <rect width="128" height="128" rx="28" fill="url(#bgGrad)" stroke="rgba(255,255,255,0.1)" stroke-width="2"/>
    <!-- Outer Shield Frame -->
    <path d="M64 18 L104 34 V68 C104 92 64 110 64 110 C64 110 24 92 24 68 V34 Z" fill="none" stroke="url(#neonCyan)" stroke-width="7" stroke-linejoin="round"/>
    <!-- Inner Keyhole -->
    <circle cx="64" cy="54" r="12" fill="url(#neonCyan)"/>
    <path d="M57 58 L52 82 H76 L71 58 Z" fill="url(#neonCyan)"/>
</svg>`;

// 2. Quantum Keyhole (Gold & Titanium Square)
const quantumKeyholeSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
    <defs>
        <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#fbbf24"/>
            <stop offset="100%" stop-color="#d97706"/>
        </linearGradient>
        <linearGradient id="titanium" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#1e293b"/>
            <stop offset="100%" stop-color="#0f172a"/>
        </linearGradient>
    </defs>
    <rect width="128" height="128" rx="28" fill="url(#titanium)" stroke="#fbbf24" stroke-width="2"/>
    <circle cx="64" cy="64" r="42" fill="none" stroke="url(#goldGrad)" stroke-width="5" stroke-dasharray="8 4"/>
    <circle cx="64" cy="52" r="14" fill="url(#goldGrad)"/>
    <path d="M56 56 L50 86 H78 L72 56 Z" fill="url(#goldGrad)"/>
</svg>`;

// 3. Cyber Lock & Key (Vibrant Laser Sapphire)
const cyberLockSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
    <defs>
        <linearGradient id="laserBlue" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#38bdf8"/>
            <stop offset="100%" stop-color="#818cf8"/>
        </linearGradient>
    </defs>
    <rect width="128" height="128" rx="28" fill="#090d16" stroke="rgba(255,255,255,0.08)" stroke-width="2"/>
    <!-- Padlock Shackle -->
    <path d="M44 56 V38 C44 26 53 18 64 18 C75 18 84 26 84 38 V56" fill="none" stroke="url(#laserBlue)" stroke-width="8" stroke-linecap="round"/>
    <!-- Padlock Body -->
    <rect x="32" y="54" width="64" height="52" rx="14" fill="#0f172a" stroke="url(#laserBlue)" stroke-width="6"/>
    <!-- Central Keyhole -->
    <circle cx="64" cy="74" r="8" fill="url(#laserBlue)"/>
    <rect x="61" y="74" width="6" height="16" fill="url(#laserBlue)"/>
</svg>`;

// 4. Hex-Vault (Minimalist Brutalist Hexagon)
const hexVaultSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
    <defs>
        <linearGradient id="emerald" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#10b981"/>
            <stop offset="100%" stop-color="#059669"/>
        </linearGradient>
    </defs>
    <rect width="128" height="128" rx="28" fill="#04070a"/>
    <polygon points="64,16 106,40 106,88 64,112 22,88 22,40" fill="none" stroke="url(#emerald)" stroke-width="6"/>
    <circle cx="64" cy="64" r="16" fill="url(#emerald)"/>
    <rect x="61" y="64" width="6" height="24" rx="3" fill="url(#emerald)"/>
</svg>`;

fs.writeFileSync(path.join(iconsDir, 'icon-cyber-shield.svg'), cyberShieldSvg, 'utf8');
fs.writeFileSync(path.join(iconsDir, 'icon-quantum-keyhole.svg'), quantumKeyholeSvg, 'utf8');
fs.writeFileSync(path.join(iconsDir, 'icon-cyber-lock.svg'), cyberLockSvg, 'utf8');
fs.writeFileSync(path.join(iconsDir, 'icon-hex-vault.svg'), hexVaultSvg, 'utf8');

// Default primary icon set
fs.writeFileSync(path.join(iconsDir, 'icon.svg'), cyberShieldSvg, 'utf8');

console.log('✅ Created 4 premium SVG extension icon themes in extension/icons/');

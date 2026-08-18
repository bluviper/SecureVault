import assert from 'assert';
import test from 'node:test';

// Web Crypto shim for older Node versions
if (typeof globalThis.crypto === 'undefined') {
    const nodeCrypto = await import('node:crypto');
    globalThis.crypto = nodeCrypto.webcrypto;
}

// Import app functions
import {
    calculateEntropy,
    assessPasswordStrength,
    uint8ToBase64,
    base64ToUint8,
    deriveKey,
    encrypt,
    decrypt,
    parseCSVContent,
    parseJSONImportData
} from '../src/app.js';

test('Password Entropy Calculation', () => {
    // Test base cases
    assert.strictEqual(calculateEntropy(''), 0);
    
    // Test lowercase only (26 possibilities)
    // 8 * log2(26) = 8 * 4.7 = ~38 entropy
    const entropyLower = calculateEntropy('password');
    assert.ok(entropyLower > 30 && entropyLower < 45);

    // Test numbers & characters variety
    const entropyStrong = calculateEntropy('P@ssw0rd2026!');
    assert.ok(entropyStrong > 60);
});

test('Password Strength Rating', () => {
    // Weak cases
    assert.strictEqual(assessPasswordStrength('').label, 'None');
    assert.strictEqual(assessPasswordStrength('short').label, 'Weak');
    assert.strictEqual(assessPasswordStrength('12345678').label, 'Weak');
    
    // Medium cases
    assert.strictEqual(assessPasswordStrength('Password123').label, 'Medium');
    
    // Strong cases
    assert.strictEqual(assessPasswordStrength('SuperSecureP@ssw0rd2026!').label, 'Strong');
});

test('Base64 Conversion Utility Round-Trip', () => {
    const original = new Uint8Array([72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100]); // "Hello, World"
    const base64 = uint8ToBase64(original);
    assert.strictEqual(base64, 'SGVsbG8sIFdvcmxk');
    
    const converted = base64ToUint8(base64);
    assert.deepStrictEqual(converted, original);
});

test('AES-GCM Encryption / Decryption Round-Trip', async () => {
    const password = 'SuperSecretMasterPassword123!';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Derive key
    const key = await deriveKey(password, salt);
    assert.strictEqual(key.type, 'secret');
    assert.strictEqual(key.algorithm.name, 'AES-GCM');
    assert.strictEqual(key.algorithm.length, 256);
    
    // Mock credentials data
    const mockData = [
        { id: 1, service: 'Gmail', user: 'user@gmail.com', pass: 'secretpass' },
        { id: 2, service: 'GitHub', user: 'gituser', pass: 'token123' }
    ];
    
    // Encrypt
    const encrypted = await encrypt(mockData, key);
    assert.ok(encrypted.iv);
    assert.ok(encrypted.data);
    
    // Decrypt
    const decrypted = await decrypt(encrypted.data, encrypted.iv, key);
    assert.deepStrictEqual(decrypted, mockData);
});

test('CSV Content Parser', () => {
    const sampleCsv = 'Service,Username,Password,Notes\n"Google","user@gmail.com","pass123","Main account"\n"GitHub","gitdev","token456","Dev key"';
    const rows = parseCSVContent(sampleCsv);
    
    assert.strictEqual(rows.length, 3);
    assert.deepStrictEqual(rows[0], ['Service', 'Username', 'Password', 'Notes']);
    assert.strictEqual(rows[1][0], 'Google');
    assert.strictEqual(rows[1][2], 'pass123');
    assert.strictEqual(rows[2][1], 'gitdev');
});

test('JSON Import Data Parser (Bitwarden & Generic formats)', () => {
    const sampleJson = JSON.stringify([
        { title: 'Amazon', login: { username: 'buyer@amazon.com', password: 'shoppingpass' }, notes: 'Prime member' },
        { service: 'Slack', user: 'dev', pass: 'chatpass', category: 'Work', tags: ['work', 'chat'] }
    ]);
    
    const parsed = parseJSONImportData(sampleJson);
    assert.strictEqual(parsed.length, 2);
    
    assert.strictEqual(parsed[0].service, 'Amazon');
    assert.strictEqual(parsed[0].user, 'buyer@amazon.com');
    assert.strictEqual(parsed[0].pass, 'shoppingpass');
    
    assert.strictEqual(parsed[1].service, 'Slack');
    assert.strictEqual(parsed[1].category, 'Work');
    assert.deepStrictEqual(parsed[1].tags, ['work', 'chat']);
});

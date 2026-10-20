import assert from 'assert';
import test from 'node:test';
import fs from 'node:fs';

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
    base32ToUint8,
    parseTotpInput,
    generateTOTP,
    deriveKey,
    encrypt,
    decrypt,
    escapeHtml,
    parseCSVContent,
    parseJSONImportData,
    parseKeePassXML
} from '../src/app.js';

test('Password Entropy Calculation (Pattern-Aware)', () => {
    // Base case
    assert.strictEqual(calculateEntropy(''), 0);
    
    // Common dictionary word 'password' is heavily discounted (~10 bits instead of 38)
    const entropyDict = calculateEntropy('password');
    assert.ok(entropyDict <= 15);

    // L33tspeak + year ('P@ssw0rd2026!') is discounted (< 35 bits) vs genuinely random string (> 75 bits)
    const entropyLeetYear = calculateEntropy('P@ssw0rd2026!');
    assert.ok(entropyLeetYear < 35);

    const entropyRandom = calculateEntropy('v9#kL2$mP8@qR5!x');
    assert.ok(entropyRandom > 80);
});

test('Password Strength Rating (zxcvbn-style Pattern Scorer)', () => {
    // Weak cases: empty, short, sequential, common dictionary, l33tspeak + year, repeated chars
    assert.strictEqual(assessPasswordStrength('').label, 'None');
    assert.strictEqual(assessPasswordStrength('short').label, 'Weak');
    assert.strictEqual(assessPasswordStrength('12345678').label, 'Weak');
    assert.strictEqual(assessPasswordStrength('Password123!').label, 'Weak');
    assert.strictEqual(assessPasswordStrength('P@ssw0rd2026!').label, 'Weak');
    assert.strictEqual(assessPasswordStrength('qwertyuiop1234').label, 'Weak');
    assert.strictEqual(assessPasswordStrength('aaaa1111AAAA!!!!').label, 'Weak');
    
    // Medium cases: moderate unpredictable password
    assert.strictEqual(assessPasswordStrength('Tr0ub4dor&3').label, 'Medium');
    
    // Strong cases: multi-word passphrase and high-entropy random password
    assert.strictEqual(assessPasswordStrength('correct-horse-battery-staple').label, 'Strong');
    assert.strictEqual(assessPasswordStrength('v9#kL2$mP8@qR5!x').label, 'Strong');
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
        { title: 'Amazon', login: { username: 'buyer@amazon.com', password: 'shoppingpass', totp: 'JBSWY3DPEHPK3PXP' }, notes: 'Prime member' },
        { service: 'Slack', user: 'dev', pass: 'chatpass', category: 'Work', tags: ['work', 'chat'] }
    ]);
    
    const parsed = parseJSONImportData(sampleJson);
    assert.strictEqual(parsed.length, 2);
    
    assert.strictEqual(parsed[0].service, 'Amazon');
    assert.strictEqual(parsed[0].user, 'buyer@amazon.com');
    assert.strictEqual(parsed[0].pass, 'shoppingpass');
    assert.strictEqual(parsed[0].totp, 'JBSWY3DPEHPK3PXP');
    
    assert.strictEqual(parsed[1].service, 'Slack');
    assert.strictEqual(parsed[1].category, 'Work');
    assert.deepStrictEqual(parsed[1].tags, ['work', 'chat']);
});

test('KeePass 2.x / KeePassXC XML Import Parser (Groups, TOTP, Entities & History Stripping)', () => {
    const sampleXml = `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Group>
        <Name>Banking &amp; Finance</Name>
        <Entry>
          <String><Key>Title</Key><Value>Chase &amp; Co</Value></String>
          <String><Key>UserName</Key><Value>alice@chase.com</Value></String>
          <String><Key>Password</Key><Value ProtectInMemory="True">p@ss&lt;1&gt;</Value></String>
          <String><Key>otp</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
          <String><Key>Notes</Key><Value>Main checking</Value></String>
          <Tags>bank;urgent</Tags>
          <History>
            <Entry>
              <String><Key>Title</Key><Value>Chase &amp; Co</Value></String>
              <String><Key>Password</Key><Value>old_password_should_be_ignored</Value></String>
            </Entry>
          </History>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>`;

    const parsed = parseKeePassXML(sampleXml);
    assert.strictEqual(parsed.length, 1);
    assert.strictEqual(parsed[0].category, 'Banking & Finance');
    assert.strictEqual(parsed[0].service, 'Chase & Co');
    assert.strictEqual(parsed[0].user, 'alice@chase.com');
    assert.strictEqual(parsed[0].pass, 'p@ss<1>');
    assert.strictEqual(parsed[0].totp, 'JBSWY3DPEHPK3PXP');
    assert.deepStrictEqual(parsed[0].tags, ['bank', 'urgent']);
    assert.strictEqual(parsed[0].notes, 'Main checking');
});

test('RFC 4648 Base32 Decode & Validation', () => {
    // "12345678901234567890" in ASCII -> GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const decoded = base32ToUint8('gezd-gnbv gy3t-qojq gezd-gnbv gy3t-qojq===');
    const ascii = new TextDecoder().decode(decoded);
    assert.strictEqual(ascii, '12345678901234567890');

    // Rejects invalid Base32 characters ('0', '1', '8', '9') and empty strings
    assert.throws(() => base32ToUint8(''), /empty/i);
    assert.throws(() => base32ToUint8('INVALID0189'), /Invalid Base32 character/i);
});

test('RFC 6238 TOTP Generation (Raw Secret & otpauth:// URI)', async () => {
    // RFC 6238 SHA-1 test seed: "12345678901234567890"
    const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    // t = 59s -> 6-digit code 287082, 1s remaining in 30s window
    const res59 = await generateTOTP(rfcSecret, 59 * 1000);
    assert.strictEqual(res59.code, '287082');
    assert.strictEqual(res59.remaining, 1);
    assert.strictEqual(res59.period, 30);

    // t = 1111111109s -> 8-digit code 07081804 via otpauth:// URI (1111111109 % 30 === 29 -> 1s remaining)
    const uri = `otpauth://totp/Example:alice@google.com?secret=${rfcSecret}&issuer=Example&digits=8&period=30&algorithm=SHA1`;
    const resUri = await generateTOTP(uri, 1111111109 * 1000);
    assert.strictEqual(resUri.code, '07081804');
    assert.strictEqual(resUri.remaining, 1);

    // parseTotpInput rejects malformed otpauth:// URIs or missing secrets
    assert.throws(() => parseTotpInput('otpauth://totp/Test?issuer=NoSecret'), /empty/i);
});

test('HTML Escaping Helper (Prevents XSS in Category Selectors)', () => {
    assert.strictEqual(escapeHtml(''), '');
    assert.strictEqual(escapeHtml('Work'), 'Work');
    assert.strictEqual(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
    assert.strictEqual(escapeHtml('Category & "More" \'Tags\''), 'Category &amp; &quot;More&quot; &#039;Tags&#039;');
});

test('HTML event handlers map to defined app functions', () => {
    const html = fs.readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
    const js = fs.readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');

    const defined = new Set();
    for (const m of js.matchAll(/(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g)) {
        defined.add(m[1]);
    }

    const called = new Set();
    const skip = new Set(['document', 'getElementById', 'click', 'return', 'this', 'console']);
    for (const m of html.matchAll(/on(?:click|change|input)="([^"]+)"/g)) {
        for (const call of m[1].matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) {
            if (!skip.has(call[1])) called.add(call[1]);
        }
    }

    const missing = [...called].filter(name => !defined.has(name));
    assert.deepStrictEqual(missing, []);
});

test('Built index.html inlined script has valid JS syntax (no String.replace $-corruption)', () => {
    const builtHtml = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
    const match = builtHtml.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(match, 'Expected inlined <script> tag in built index.html');
    // Verify the inlined script compiles cleanly as a Function without syntax errors
    assert.doesNotThrow(() => new Function(match[1]));
});

test('Rich Entry Types (login, card, identity, ssh) & Bitwarden Folder JSON Import', () => {
    const payload = JSON.stringify({
        folders: [
            { id: 'folder-gov-1', name: 'Government IDs' },
            { id: 'folder-infra-2', name: 'DevOps' }
        ],
        items: [
            {
                type: 'card',
                service: 'Chase Sapphire',
                user: 'Juan Dela Cruz',
                pass: '4111222233334444',
                cardExpiry: '08/29',
                cardCvv: '999',
                category: 'Banking'
            },
            {
                name: 'Passport PH',
                folderId: 'folder-gov-1',
                identity: {
                    firstName: 'Juan',
                    lastName: 'Dela Cruz',
                    passportNumber: 'P1234567A'
                }
            },
            {
                name: 'Prod Bastion Key',
                folderId: 'folder-infra-2',
                sshKey: {
                    keyFingerprint: 'SHA256:abcd1234',
                    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----'
                }
            }
        ]
    });

    const parsed = parseJSONImportData(payload);
    assert.strictEqual(parsed.length, 3);

    assert.strictEqual(parsed[0].type, 'card');
    assert.strictEqual(parsed[0].category, 'Banking');
    assert.strictEqual(parsed[0].cardExpiry, '08/29');
    assert.strictEqual(parsed[0].cardCvv, '999');

    assert.strictEqual(parsed[1].type, 'identity');
    assert.strictEqual(parsed[1].category, 'Government IDs');
    assert.strictEqual(parsed[1].user, 'Juan Dela Cruz');
    assert.strictEqual(parsed[1].pass, 'P1234567A');

    assert.strictEqual(parsed[2].type, 'ssh');
    assert.strictEqual(parsed[2].category, 'DevOps');
    assert.strictEqual(parsed[2].user, 'SHA256:abcd1234');
    assert.strictEqual(parsed[2].pass, '-----BEGIN OPENSSH PRIVATE KEY-----');
});



import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const iconsDir = path.join(__dirname, 'extension', 'icons');

function createPngBuffer(width, height, drawFn) {
    const rawData = Buffer.alloc(height * (1 + width * 4));
    for (let y = 0; y < height; y++) {
        const rowOffset = y * (1 + width * 4);
        rawData[rowOffset] = 0; // Filter type None
        for (let x = 0; x < width; x++) {
            const pixelOffset = rowOffset + 1 + x * 4;
            const [r, g, b, a] = drawFn(x, y, width, height);
            rawData[pixelOffset] = r;
            rawData[pixelOffset + 1] = g;
            rawData[pixelOffset + 2] = b;
            rawData[pixelOffset + 3] = a;
        }
    }

    const compressed = zlib.deflateSync(rawData);

    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8; // 8 bits per channel
    ihdr[9] = 6; // RGBA
    ihdr[10] = 0;
    ihdr[11] = 0;
    ihdr[12] = 0;

    const ihdrChunk = createChunk('IHDR', ihdr);
    const idatChunk = createChunk('IDAT', compressed);
    const iendChunk = createChunk('IEND', Buffer.alloc(0));

    const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function createChunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const typeAndData = Buffer.concat([typeBuf, data]);
    const crc = crc32(typeAndData);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc, 0);
    return Buffer.concat([len, typeAndData, crcBuf]);
}

function crc32(buf) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) {
        let c = (crc ^ buf[i]) & 0xFF;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xED888320 ^ (c >>> 1)) : (c >>> 1);
        }
        crc = (crc >>> 8) ^ c;
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

// Draw Cyber Keyhole Shield (Cyan & Blue)
function drawCyberShield(x, y, w, h) {
    const nx = (x / w) * 100;
    const ny = (y / h) * 100;

    // Outer border & background
    const cornerRadius = 18;
    const isInsideBg = (nx >= 4 && nx <= 96 && ny >= 4 && ny <= 96);
    
    // Shield shape calculation
    const dx = Math.abs(nx - 50);
    const inShieldUpper = (ny >= 20 && ny <= 60 && dx <= (20 + (ny - 20) * 0.4));
    const inShieldLower = (ny > 60 && ny <= 90 && dx <= (36 - (ny - 60) * 1.2));
    const isShield = inShieldUpper || inShieldLower;

    // Keyhole shape
    const distKeyCircle = Math.sqrt((nx - 50) ** 2 + (ny - 48) ** 2);
    const inKeyholeCircle = distKeyCircle < 9;
    const inKeyholeStem = (ny >= 52 && ny <= 74 && dx <= 4);
    const isKeyhole = inKeyholeCircle || inKeyholeStem;

    if (isKeyhole && isShield) {
        return [6, 182, 212, 255]; // Bright Neon Cyan (#06b6d4)
    } else if (isShield) {
        return [59, 130, 246, 255]; // Royal Blue Accent (#3b82f6)
    } else if (isInsideBg) {
        return [10, 15, 29, 255]; // Dark Obsidian (#0a0f1d)
    } else {
        return [0, 0, 0, 0]; // Transparent padding
    }
}

[16, 48, 128].forEach(size => {
    const buf = createPngBuffer(size, size, drawCyberShield);
    fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), buf);
});

console.log('✅ Rendered crisp 16x16, 48x48, 128x128 PNG extension icons.');

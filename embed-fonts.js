/**
 * Downloads Google Font TTF files and converts them to base64 data URIs,
 * then generates a self-contained CSS @font-face block for offline use.
 */
import fs from 'fs';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const fonts = [
    { family: 'JetBrains Mono', weight: 300, url: 'https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8lqxjPQ.ttf' },
    { family: 'JetBrains Mono', weight: 400, url: 'https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKxjPQ.ttf' },
    { family: 'JetBrains Mono', weight: 500, url: 'https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbY2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8-qxjPQ.ttf' },
    { family: 'Plus Jakarta Sans', weight: 300, url: 'https://fonts.gstatic.com/s/plusjakartasans/v12/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_907NSg.ttf' },
    { family: 'Plus Jakarta Sans', weight: 400, url: 'https://fonts.gstatic.com/s/plusjakartasans/v12/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_qU7NSg.ttf' },
    { family: 'Plus Jakarta Sans', weight: 500, url: 'https://fonts.gstatic.com/s/plusjakartasans/v12/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_m07NSg.ttf' },
    { family: 'Plus Jakarta Sans', weight: 600, url: 'https://fonts.gstatic.com/s/plusjakartasans/v12/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_d0nNSg.ttf' },
    { family: 'Plus Jakarta Sans', weight: 700, url: 'https://fonts.gstatic.com/s/plusjakartasans/v12/LDIbaomQNQcsA88c7O9yZ4KMCoOg4IA6-91aHEjcWuA_TknNSg.ttf' },
];

function download(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                return download(res.headers.location).then(resolve).catch(reject);
            }
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
        }).on('error', reject);
    });
}

async function main() {
    console.log('📥 Downloading and encoding 8 font files...\n');
    let css = '/* Embedded Google Fonts — Plus Jakarta Sans & JetBrains Mono (offline) */\n\n';

    for (const font of fonts) {
        process.stdout.write(`  ↓ ${font.family} ${font.weight}... `);
        const buffer = await download(font.url);
        const base64 = buffer.toString('base64');
        const sizeKB = Math.round(buffer.length / 1024);
        console.log(`${sizeKB} KB`);

        css += `@font-face {\n`;
        css += `  font-family: '${font.family}';\n`;
        css += `  font-style: normal;\n`;
        css += `  font-weight: ${font.weight};\n`;
        css += `  font-display: swap;\n`;
        css += `  src: url(data:font/truetype;base64,${base64}) format('truetype');\n`;
        css += `}\n\n`;
    }

    const outPath = path.join(__dirname, 'src', 'fonts.css');
    fs.writeFileSync(outPath, css, 'utf8');
    console.log(`\n✅ Written to ${outPath} (${Math.round(fs.statSync(outPath).size / 1024)} KB)`);
}

main().catch(err => { console.error('❌', err); process.exit(1); });

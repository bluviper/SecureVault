import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SRC_DIR = path.join(__dirname, 'src');
const DIST_FILE = path.join(__dirname, 'index.html');

function build() {
    console.log('📦 Building SecureVault...');
    try {
        const htmlPath = path.join(SRC_DIR, 'index.html');
        const cssPath = path.join(SRC_DIR, 'style.css');
        const jsPath = path.join(SRC_DIR, 'app.js');

        if (!fs.existsSync(htmlPath)) {
            throw new Error(`Source HTML template not found at ${htmlPath}`);
        }

        let html = fs.readFileSync(htmlPath, 'utf8');

        // Inline CSS
        if (fs.existsSync(cssPath)) {
            const css = fs.readFileSync(cssPath, 'utf8');
            const cssRegex = /<link\s+rel="stylesheet"\s+href="style\.css"\s*\/?>/i;
            if (cssRegex.test(html)) {
                html = html.replace(cssRegex, `<style>\n${css}\n</style>`);
                console.log('  🎨 style.css inlined');
            } else {
                console.warn('  ⚠️ Warning: No stylesheet link found in index.html to replace.');
            }
        } else {
            console.warn('  ⚠️ Warning: src/style.css not found, skipping inline CSS.');
        }

        // Inline JS
        if (fs.existsSync(jsPath)) {
            const js = fs.readFileSync(jsPath, 'utf8');
            const jsRegex = /<script\s+src="app\.js"\s*><\/script>/i;
            if (jsRegex.test(html)) {
                html = html.replace(jsRegex, `<script>\n${js}\n</script>`);
                console.log('  ⚙️ app.js inlined');
            } else {
                console.warn('  ⚠️ Warning: No app.js script tag found in index.html to replace.');
            }
        } else {
            console.warn('  ⚠️ Warning: src/app.js not found, skipping inline JS.');
        }

        // Write output
        fs.writeFileSync(DIST_FILE, html, 'utf8');
        console.log(`🚀 Build complete! Output written to ${DIST_FILE} (${fs.statSync(DIST_FILE).size} bytes)`);
    } catch (error) {
        console.error('❌ Build failed:', error.message);
    }
}

// Watch mode
if (process.argv.includes('--watch') || process.argv.includes('-w')) {
    console.log('👀 Watching src/ directory for changes...');
    build();
    fs.watch(SRC_DIR, { recursive: true }, (eventType, filename) => {
        if (filename && (filename.endsWith('.html') || filename.endsWith('.css') || filename.endsWith('.js'))) {
            console.log(`🔄 File changed: src/${filename}`);
            build();
        }
    });
} else {
    build();
}

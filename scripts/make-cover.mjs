import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('../frontend/node_modules/@playwright/test');
const root = resolve(import.meta.dirname, '..');
const html = pathToFileURL(resolve(root, 'assets/cover/cover.html')).href;
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });
  await page.goto(html);
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.images].map(image => image.decode()));
  });
  for (const [file, width, height] of [['social-preview.png', 1280, 640], ['og-image.png', 1200, 630]]) {
    await page.setViewportSize({ width, height });
    await page.screenshot({ path: resolve(root, 'assets', file), animations: 'disabled' });
    const { stat } = await import('node:fs/promises');
    const output = await stat(resolve(root, 'assets', file));
    console.log(`${file}: ${width}x${height}, ${output.size} bytes`);
  }
} finally {
  await browser.close();
}

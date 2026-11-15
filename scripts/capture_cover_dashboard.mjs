import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { writeFile } from 'node:fs/promises';
const require = createRequire(import.meta.url);
const { chromium } = require('../frontend/node_modules/@playwright/test');

const root = resolve(import.meta.dirname, '..');
const tmp = await mkdtemp(resolve(tmpdir(), 'chinescan-cover-'));
const scratch = resolve(tmpdir(), 'chinescan-cover-debug');
await mkdir(scratch, { recursive: true });
const dir = resolve(tmp, 'instance');
const output = resolve(root, 'assets/cover/raw');
await mkdir(output, { recursive: true });
const email = `browser-${randomBytes(4).toString('hex')}@example.test`;
const password = randomBytes(24).toString('base64url');
const child = spawn('py', ['-3.12', resolve(root, 'tests/browser/serve.py'), '--data-dir', dir, '--ttl', '1800'], {
  cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'inherit'],
  env: { ...process.env, PYTHONPATH: root, CHINESCAN_CONFIG_PATH: resolve(dir, 'config.toml'), CHINESCAN_DATABASE_PATH: resolve(dir, 'records.sqlite3'), CHINESCAN_REPORTS_DIR: resolve(dir, 'reports') },
});
child.stdin.end(`${JSON.stringify({ email, password })}\n`);
let stdout = '';
let announced;
child.stdout.setEncoding('utf8');
child.stdout.on('data', chunk => { stdout += chunk; const line = stdout.split('\n')[0]; if (line) announced = JSON.parse(line); });
const waitFor = async predicate => { for (let i=0;i<600;i++) { if (predicate()) return; if (child.exitCode !== null) throw new Error(`Fixture exited ${child.exitCode}`); await new Promise(r=>setTimeout(r,100)); } throw new Error('Fixture startup timeout'); };
try {
  await waitFor(() => announced);
  await waitFor(() => announced);
  for (let i=0;i<200;i++) {
    try { const response = await fetch(`${announced.url}/api/auth/session`); if (response.ok) break; } catch {}
    await new Promise(r=>setTimeout(r,100));
  }
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2, colorScheme: 'dark', reducedMotion: 'reduce' });
    await page.goto(announced.url);
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('heading', { name: 'Overview' }).waitFor();
    const failedResponses = [];
    const consoleMessages = [];
    page.on('response', response => { if (response.status() >= 400) failedResponses.push({ status: response.status(), url: response.url() }); });
    page.on('console', message => { if (message.type() === 'error') consoleMessages.push(message.text()); });
    const scoresResponse = await page.waitForResponse(response => response.url().endsWith('/api/dashboard/scores') && response.status() === 200, { timeout: 30000 });
    console.log('scores endpoint', scoresResponse.status(), await scoresResponse.text());
    try {
      await page.locator('.score-grid article').first().waitFor({ state: 'visible', timeout: 30000 });
      await page.waitForFunction(() => {
        const cards = [...document.querySelectorAll('.score-grid article')];
        return cards.length > 0 && cards.every(card => card.textContent?.trim().length > 0);
      }, null, { timeout: 30000 });
    } catch (error) {
      await page.screenshot({ path: resolve(scratch, 'failure.png'), fullPage: true });
      await writeFile(resolve(scratch, 'failure.html'), await page.content());
      await writeFile(resolve(scratch, 'diagnostics.json'), JSON.stringify({ consoleMessages, failedResponses }, null, 2));
      console.error('capture diagnostics saved to', scratch, String(error));
      throw error;
    }
    await page.locator('.profile-name strong').evaluate(node => { node.textContent = 'analyst'; });
    await page.waitForTimeout(500);
    await page.screenshot({ path: resolve(output, 'overview.png'), animations: 'disabled' });
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Findings', exact: true }).click();
    await page.getByRole('heading', { name: 'Findings' }).waitFor();
    await page.getByText('Synthetic high severity fixture').waitFor();
    await page.screenshot({ path: resolve(output, 'findings.png'), animations: 'disabled' });
  } finally { await browser.close(); }
} finally {
  if (child.exitCode === null) { if (process.platform === 'win32' && child.pid) { const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio:'ignore', windowsHide:true }); await new Promise(r=>killer.once('exit',r)); } else child.kill('SIGTERM'); }
  await rm(tmp, { recursive:true, force:true, maxRetries:5, retryDelay:200 });
}

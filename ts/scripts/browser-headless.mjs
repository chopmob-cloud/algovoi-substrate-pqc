/**
 * Headless-browser smoke test for @algovoi/substrate-pqc.
 *
 * Spins up an HTTP server pointing at the package root, opens
 * scripts/browser-smoke.html in a headless Chromium via Puppeteer, and asserts
 * the page reports zero failures.
 *
 * Usage:
 *   npx --yes -p puppeteer@latest -p http-server@latest node scripts/browser-headless.mjs
 *
 * Returns exit code 0 on pass, 1 on fail.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// __dirname = .../algovoi-substrate-pqc/ts/scripts
const tsRoot = resolve(__dirname, '..');           // .../algovoi-substrate-pqc/ts
const repoRoot = resolve(tsRoot, '..');             // .../algovoi-substrate-pqc

const PORT = 18080;

// Static server rooted ONE LEVEL ABOVE the repo so the browser can fetch
// /algovoi-substrate-pqc/ts/dist/index.js AND
// /ap2-pq-conformance/algovoi-side/... when present.
const serverRoot = resolve(repoRoot, '..');
console.log(`Static server root: ${serverRoot}`);
const server = spawn(process.execPath, [
  '-e',
  `
  import('http-server').then(({ createServer }) => {
    const s = createServer({ root: ${JSON.stringify(serverRoot)}, cache: -1, cors: true });
    s.listen(${PORT}, () => console.log('http-server up on ${PORT}'));
  }).catch(e => { console.error('http-server require failed:', e.message); process.exit(2); });
  `,
], { stdio: ['ignore', 'pipe', 'pipe'] });

server.stdout.on('data', (d) => process.stdout.write(`[server] ${d}`));
server.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

// Wait for server to come up.
await new Promise((res) => setTimeout(res, 1500));

let puppeteer;
try {
  puppeteer = (await import('puppeteer')).default;
} catch (e) {
  console.error('puppeteer import failed:', e.message);
  server.kill();
  process.exit(2);
}

const browser = await puppeteer.launch({ headless: true });
const page = await browser.newPage();
page.on('console', (msg) => console.log(`[browser] ${msg.text()}`));
page.on('pageerror', (err) => console.error(`[browser-error] ${err.message}`));

// algovoi-substrate-pqc's ts/ directory is under serverRoot, so the URL is
// /ts/scripts/browser-smoke.html assuming serverRoot is the algovoi-substrate-pqc repo.
const url = `http://127.0.0.1:${PORT}/algovoi-substrate-pqc/ts/scripts/browser-smoke.html`;
console.log(`Loading: ${url}`);
await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });

// Wait for the summary div to populate.
await page.waitForFunction(
  () => document.getElementById('summary')?.textContent?.includes('Passed'),
  { timeout: 30000 },
);

const summary = await page.$eval('#summary', (el) => el.textContent);
console.log(`\nBrowser summary: ${summary}`);

const out = await page.$eval('#out', (el) => el.textContent);
console.log('\nBrowser test output:');
console.log(out);

await browser.close();
server.kill();

const failMatch = summary.match(/Failed:\s*(\d+)/);
const fails = failMatch ? Number(failMatch[1]) : -1;
process.exit(fails === 0 ? 0 : 1);

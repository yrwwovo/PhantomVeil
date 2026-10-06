// Uses Playwright's Apache-2.0 APIs: https://playwright.dev/docs/network
// Runs only in a read-only Docker container with --network none, never on the host.
import { chromium } from 'playwright';
import { networkInterfaces } from 'node:os';
import { createConnection } from 'node:net';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
if (Object.entries(networkInterfaces()).some(([name, entries]) =>
  name !== 'lo' && entries?.some(e => !e.internal))) throw new Error('network isolation missing');
// A real kernel-level negative egress check, independently of browser routes.
const isolated = await new Promise(resolve => {
  const socket = createConnection({ host: '192.0.2.1', port: 80 });
  socket.setTimeout(1000);
  socket.once('connect', () => { socket.destroy(); resolve(false); });
  socket.once('error', e => { socket.destroy(); resolve(['ENETUNREACH', 'EHOSTUNREACH'].includes(e.code)); });
  socket.once('timeout', () => { socket.destroy(); resolve(false); });
});
if (!isolated) throw new Error('egress check failed');
const browser = await chromium.launch({ headless: true, args: ['--disable-background-networking'] });
try {
  const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
  const signals = [];
  const blocked = [];
  await context.exposeBinding('__pveilExecute', ({ frame, page }, value) => {
    if (frame === page.mainFrame() && value === input.marker) signals.push(value);
  });
  await context.routeWebSocket('**/*', ws => ws.close());
  let delivered = false;
  await context.route('**/*', async route => {
    if (!delivered && route.request().isNavigationRequest() &&
        route.request().url() === input.url && route.request().method() === 'GET') {
      delivered = true;
      await route.fulfill({ status: input.status, headers: input.headers, body: input.body });
    } else {
      blocked.push(route.request().resourceType());
      await route.abort();
    }
  });
  const page = await context.newPage();
  await page.goto(input.url, { waitUntil: 'domcontentloaded', timeout: 5000 });
  await page.waitForTimeout(100);
  const scriptPresent = await page.locator('script').evaluateAll((scripts, expected) =>
    scripts.some(script => script.textContent === expected), input.script);
  const result = { network_isolated: true, delivered, executed: scriptPresent && signals.length === 1,
    signals, blocked_resource_count: blocked.length, browser_version: browser.version() };
  await context.close();
  process.stdout.write(JSON.stringify(result));
} finally { await browser.close(); }

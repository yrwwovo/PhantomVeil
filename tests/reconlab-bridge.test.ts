import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createReconLabBridge } from '../scripts/reconlab-bridge.mjs';
import { executeReconLabRun } from '../scripts/reconlab-run.mjs';
import { createFixtureModel } from '../benchmarks/hermes-eval/fixture-model.mjs';

const listen = (server: Server) => new Promise<string>((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as { port: number }).port}`));
});
const close = (server: Server) => new Promise<void>(resolve => server.close(() => resolve()));
async function api(base: string, route: string, body?: unknown, headers = {}) {
  const response = await fetch(base + route, { ...(body === undefined ? {} : { method: 'POST',
    body: JSON.stringify(body) }), headers: { 'content-type': 'application/json', ...headers } });
  return { status: response.status, ...(await response.json()) };
}
async function waitFor(base: string, id: string, states: string[], timeout = 3000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const { session } = await api(base, `/sessions/${id}`);
    if (states.includes(session.status)) return session;
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  throw new Error('任务状态等待超时');
}

test('ReconLab approval is immutable, separate, single-use, persisted and cancellable', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'pveil-rl-test-'));
  const calls: unknown[] = [];
  let stopped = false;
  const bridge = await createReconLabBridge({ root, execute: async (command, options) => {
    calls.push(command);
    if (command.text === 'wait') {
      await new Promise<void>(resolve => options.signal.addEventListener('abort', () => { stopped = true; resolve(); }, { once: true }));
      options.signal.throwIfAborted();
    }
    return { summary: 'fixture complete' };
  } });
  const base = await listen(bridge.server);
  try {
    assert.equal((await api(base, '/sessions', { url: 'https://example.com/', text: '读取' },
      { origin: 'https://attacker.invalid' })).status, 403);
    for (const url of ['file:///test', 'https://user:pass@example.com/', 'https://example.com/?token=a']) {
      assert.equal((await api(base, '/sessions', { url, text: '读取' })).status, 400);
    }
    assert.equal((await api(base, '/sessions', { url: 'https://example.com/', text: '读取', approved: true })).status, 400);
    const { session: pending } = await api(base, '/sessions', { url: 'https://example.com/', text: '读取中文任务' });
    assert.equal(pending.text, '读取中文任务');
    assert.equal(pending.status, 'awaiting_approval');
    assert.equal(calls.length, 0);
    assert.equal((await api(base, `/sessions/${pending.id}/approve`, { approval_id: 'wrong', approved: true })).status, 409);
    assert.equal((await api(base, `/sessions/${pending.id}/approve`, { approval_id: pending.approval_id, approved: true,
      url: 'https://other.invalid/' })).status, 409);
    assert.equal(calls.length, 0);
    await api(base, `/sessions/${pending.id}/approve`, { approval_id: pending.approval_id, approved: false });
    assert.equal(calls.length, 0);
    const { session: accepted } = await api(base, '/sessions', { url: 'https://example.com/', text: '读取' });
    await api(base, `/sessions/${accepted.id}/approve`, { approval_id: accepted.approval_id, approved: true });
    const done = await waitFor(base, accepted.id, ['done']);
    assert.equal(done.result.summary, 'fixture complete');
    assert.deepEqual(calls, [{ url: accepted.url, text: accepted.text, approved: true, approval_id: accepted.approval_id }]);
    assert.equal((await api(base, `/sessions/${accepted.id}/approve`, { approval_id: accepted.approval_id, approved: true })).status, 409);
    const saved = JSON.parse(await readFile(path.join(root, 'sessions', `${accepted.id}.json`), 'utf8'));
    assert.equal(saved.status, 'done');
    const { session: waiting } = await api(base, '/sessions', { url: 'https://example.com/', text: 'wait' });
    await api(base, `/sessions/${waiting.id}/approve`, { approval_id: waiting.approval_id, approved: true });
    assert.equal((await api(base, `/sessions/${waiting.id}/cancel`, {})).session.status, 'cancelled');
    assert.equal(stopped, true);
  } finally { await bridge.close(); await rm(root, { recursive: true, force: true }); }
});

test('ReconLab expired approvals fail closed and interrupted tasks never restart automatically', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'pveil-rl-restart-'));
  let calls = 0;
  const execute = async () => { calls++; return { summary: 'unexpected' }; };
  let bridge = await createReconLabBridge({ root, execute });
  let base = await listen(bridge.server);
  const { session } = await api(base, '/sessions', { url: 'https://example.com/', text: '读取' });
  await bridge.close();
  const filename = path.join(root, 'sessions', `${session.id}.json`);
  await writeFile(filename, JSON.stringify({ ...session, approval_expires: Date.now() - 1 }));
  bridge = await createReconLabBridge({ root, execute }); base = await listen(bridge.server);
  assert.equal((await api(base, `/sessions/${session.id}/approve`, { approval_id: session.approval_id, approved: true })).status, 409);
  await bridge.close();
  await writeFile(filename, JSON.stringify({ ...session, status: 'running' }));
  bridge = await createReconLabBridge({ root, execute }); base = await listen(bridge.server);
  try {
    assert.equal((await api(base, `/sessions/${session.id}`)).session.status, 'interrupted');
    assert.equal(calls, 0);
  } finally { await bridge.close(); await rm(root, { recursive: true, force: true }); }
});

test('ReconLab HTTP approval -> actual fork Hermes -> actual MCP -> one local GET -> verified EV/report',
  { skip: process.env.PVEIL_RECONLAB_INTEGRATION !== '1', timeout: 180_000 }, async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'pveil-rl-integration-'));
    let hits = 0;
    const site = createServer((_request, response) => {
      hits++; response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<a href="/next">下一页</a><form method="get" action="/search"><input name="q"></form>');
    });
    const modelCalls: { tool_names: string[] }[] = [];
    const model = createFixtureModel(item => modelCalls.push(item));
    const siteUrl = await listen(site) + '/';
    const modelUrl = await listen(model);
    const nativeHome = path.join(root, 'native-home');
    const configRoot = path.join(root, 'source-config');
    await mkdir(nativeHome); await mkdir(configRoot);
    await writeFile(path.join(nativeHome, 'config.yaml'), 'model:\n  default: fixture-model\n  provider: custom\n' +
      `  base_url: "${modelUrl}/v1"\n  api_key: fixture-only\n`);
    const bridge = await createReconLabBridge({ root: path.join(root, 'bridge'), env: { ...process.env, HERMES_HOME: nativeHome },
      execute: (command, options) => executeReconLabRun(command, { ...options, configRoot }) });
    const base = await listen(bridge.server);
    try {
      const { session } = await api(base, '/sessions', { url: siteUrl, text: '观察并离线清点入口' });
      assert.equal(hits, 0); assert.equal(modelCalls.length, 0);
      await api(base, `/sessions/${session.id}/approve`, { approval_id: session.approval_id, approved: true });
      const finished = await waitFor(base, session.id, ['done', 'error'], 160_000);
      assert.equal(finished.status, 'done', JSON.stringify(finished.events));
      assert.equal(hits, 1);
      assert.equal(finished.result.evidence.length, 1);
      const ev = finished.result.evidence[0];
      assert.equal(ev.http_status, 200); assert.match(ev.sha256, /^[a-f0-9]{64}$/u);
      assert.ok(finished.result.report.includes(ev.evidence_id));
      assert.ok(modelCalls.length >= 3);
      assert.ok(modelCalls.some(call => call.tool_names.length === 3));
      for (const call of modelCalls) {
        assert.ok([0, 3].includes(call.tool_names.length));
        assert.ok(call.tool_names.every(name => /__(authorized_web_observe|evidence_entry_inventory|evidence_header_check)$/u.test(name)));
      }
      const runRoot = path.join(root, 'bridge', 'runs', finished.result.task_id);
      const audit = await readFile(path.join(runRoot, 'request-decisions.jsonl'), 'utf8');
      assert.match(audit, /REQUEST_RESERVED/u); assert.match(audit, /INVENTORY_COMPLETED/u);
      const profileConfig = await readFile(path.join(runRoot, 'profile', 'config.yaml'), 'utf8');
      assert.ok(!profileConfig.includes('fixture-only'), 'native credentials must not be copied');
      assert.equal((await readdir(path.join(runRoot, 'workspace', 'evidence', 'hermes'))).length, 1);
    } finally {
      await bridge.close(); await Promise.all([close(site), close(model)]);
      // Retain failed fixture artifacts for diagnosis without exposing credentials.
      if (!process.env.PVEIL_RECONLAB_KEEP_FIXTURE) await rm(root, { recursive: true, force: true });
      else process.stderr.write(`Fixture artifacts: ${root}\n`);
    }
  });

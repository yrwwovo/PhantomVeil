import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile, rename, access } from 'node:fs/promises';
import path from 'node:path';
import { homedir } from 'node:os';
import { executeReconLabRun, validateCommand } from './reconlab-run.mjs';
import { hermesChatRuntime } from './hermes-chat.mjs';

const SOURCE = path.resolve(import.meta.dirname, '..');
const DEFAULT_ROOT = path.join(process.env.LOCALAPPDATA ?? path.join(homedir(), '.local', 'share'),
  'PhantomVeil', 'reconlab-bridge');
const terminal = new Set(['done', 'error', 'cancelled', 'interrupted']);

/** A local, single-user command adapter. Remote deployment needs authenticated ownership. */
export async function createReconLabBridge({ root = DEFAULT_ROOT, execute = executeReconLabRun,
  env = process.env, sourceRoot = SOURCE } = {}) {
  root = path.resolve(root);
  const relative = path.relative(sourceRoot, root);
  if (!relative || (!relative.startsWith('..') && !path.isAbsolute(relative))) throw new Error('运行目录须在源码仓库外');
  const stateDir = path.join(root, 'sessions');
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const sessions = new Map();
  const controllers = new Map();
  const activeRuns = new Set();
  let saving = Promise.resolve();
  function save(session) {
    const data = JSON.stringify(session);
    saving = saving.catch(() => {}).then(async () => {
      const filename = path.join(stateDir, `${session.id}.json`);
      await writeFile(`${filename}.tmp`, data, { mode: 0o600 });
      await rename(`${filename}.tmp`, filename);
    });
    return saving;
  }
  function event(session, kind, payload) {
    session.events.push({ seq: session.events.length + 1, kind, payload, created: Date.now() / 1000 });
    session.updated = Date.now() / 1000;
    return save(session);
  }
  for (const filename of await readdir(stateDir)) {
    if (!/^[a-f0-9-]{36}\.json$/u.test(filename)) continue;
    const session = JSON.parse(await readFile(path.join(stateDir, filename), 'utf8'));
    if (['running', 'preparing'].includes(session.status)) {
      session.status = 'interrupted';
      await event(session, 'error', { message: '服务重启中断了任务，请新建任务重新批准' });
    }
    sessions.set(session.id, session);
  }
  async function run(session) {
    if (session.status !== 'preparing') return;
    const controller = new AbortController();
    controllers.set(session.id, controller);
    const timeout = setTimeout(() => controller.abort(new Error('任务超过三分钟执行上限')), 180_000);
    try {
      const result = await execute({ url: session.url, text: session.text, approved: true,
        approval_id: session.approval_id }, { runsRoot: path.join(root, 'runs'), sourceRoot, env,
        signal: controller.signal,
        onTask: task => { session.task_id = task.taskId; },
        emit: (kind, payload) => {
          if (controller.signal.aborted) return;
          if (kind === 'status') session.status = 'running';
          if (kind === 'artifacts') session.artifacts = payload;
          void event(session, kind, payload).catch(() => controller.abort(new Error('运行记录无法保存')));
        } });
      controller.signal.throwIfAborted();
      session.status = 'done';
      session.result = result;
      await event(session, 'done', { summary: result.summary });
    } catch (error) {
      if (session.status !== 'cancelled') {
        session.status = 'error';
        await event(session, 'error', { message: controller.signal.aborted
          ? '任务已停止或超过执行时间上限' : (error instanceof Error ? error.message : '执行失败') }).catch(() => {});
      }
    } finally {
      clearTimeout(timeout);
      controllers.delete(session.id);
    }
  }
  function respond(response, status, body) {
    response.writeHead(status, { 'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    response.end(JSON.stringify(body));
  }
  const server = createServer(async (request, response) => {
    try {
      const origin = request.headers.origin;
      const host = request.headers.host ?? '';
      const allowedOrigins = new Set(['http://127.0.0.1:5173', 'http://localhost:5173']);
      if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress) ||
          !/^(127\.0\.0\.1|localhost|\[::1\]):\d+$/u.test(host) || (origin && !allowedOrigins.has(origin))) {
        return respond(response, 403, { error: '本机作战台来源不被允许' });
      }
      const url = new URL(request.url, 'http://127.0.0.1');
      const parts = url.pathname.split('/').filter(Boolean);
      let body = {};
      if (request.method === 'POST') {
        if (!(request.headers['content-type'] ?? '').startsWith('application/json')) {
          return respond(response, 415, { error: '需要 JSON 请求' });
        }
        let bytes = 0;
        const chunks = [];
        for await (const chunk of request) {
          bytes += chunk.length;
          if (bytes > 16_384) return respond(response, 413, { error: '任务过长' });
          chunks.push(chunk);
        }
        const raw = Buffer.concat(chunks).toString('utf8');
        try { body = JSON.parse(raw || '{}'); } catch { return respond(response, 400, { error: 'JSON 无效' }); }
        if (!body || Array.isArray(body) || typeof body !== 'object') return respond(response, 400, { error: '请求无效' });
      }
      if (request.method === 'GET' && url.pathname === '/health') {
        const runtime = hermesChatRuntime({ env, sourceRoot });
        const available = await Promise.all([access(runtime.python).then(() => true, () => false),
          access(runtime.runtime).then(() => true, () => false)]);
        return respond(response, 200, { runtime: 'PhantomVeil / Hermes', ready: available.every(Boolean),
          mode: '一次只读观察及离线清点', max_requests: 1, credentials: 'Hermes 原生凭据，仅在服务端使用' });
      }
      if (url.pathname === '/sessions') {
        if (request.method === 'GET') return respond(response, 200, { sessions:
          [...sessions.values()].map(s => ({ id: s.id, url: s.url, status: s.status, updated: s.updated }))
            .sort((a, b) => b.updated - a.updated) });
        if (request.method === 'POST') {
          let command;
          try { command = validateCommand(body); } catch (error) { return respond(response, 400, { error: error.message }); }
          if (Object.keys(body).some(key => !['url', 'text'].includes(key))) return respond(response, 400, { error: '请求含不支持的字段' });
          const session = { id: randomUUID(), ...command, status: 'awaiting_approval',
            approval_id: randomUUID(), approval_expires: Date.now() + 600_000, events: [], updated: Date.now() / 1000 };
          sessions.set(session.id, session);
          await event(session, 'approval', { url: session.url, text: session.text, max_requests: 1 });
          return respond(response, 201, { session });
        }
      }
      const session = parts[0] === 'sessions' ? sessions.get(parts[1]) : null;
      if (!session) return respond(response, 404, { error: '任务不存在' });
      if (request.method === 'GET' && parts.length === 2) return respond(response, 200, { session });
      if (request.method === 'POST' && parts.length === 3 && parts[2] === 'approve') {
        if (session.status !== 'awaiting_approval' || Date.now() > session.approval_expires ||
            body.approval_id !== session.approval_id || typeof body.approved !== 'boolean' ||
            Object.keys(body).some(key => !['approval_id', 'approved'].includes(key))) {
          return respond(response, 409, { error: '批准已失效、任务已执行或内容发生变化，请新建任务' });
        }
        if (!body.approved) {
          session.status = 'cancelled';
          await event(session, 'done', { summary: '已拒绝任务，未启动 PhantomVeil' });
        } else {
          if ([...sessions.values()].some(s => ['preparing', 'running'].includes(s.status))) {
            return respond(response, 409, { error: '已有任务执行中，请等待完成或叫停后再批准' });
          }
          session.status = 'preparing';
          await event(session, 'status', { text: '已记录人工批准，准备 PhantomVeil 隔离任务' });
          const running = run(session);
          activeRuns.add(running);
          void running.then(() => activeRuns.delete(running), () => activeRuns.delete(running));
        }
        return respond(response, 202, { session });
      }
      if (request.method === 'POST' && parts.length === 3 && parts[2] === 'cancel') {
        if (terminal.has(session.status)) return respond(response, 409, { error: '任务已经结束' });
        session.status = 'cancelled';
        controllers.get(session.id)?.abort();
        await event(session, 'done', { summary: '任务已叫停；已经产生的证据保留' });
        return respond(response, 200, { session });
      }
      return respond(response, 404, { error: '没有这个接口' });
    } catch {
      if (!response.headersSent) respond(response, 500, { error: '服务无法处理本次请求' });
    }
  });
  return { server, async close() {
    for (const controller of controllers.values()) controller.abort();
    await new Promise(resolve => server.close(resolve));
    await Promise.allSettled([...activeRuns]);
    await saving;
  } };
}

if (import.meta.filename === process.argv[1]) {
  const bridge = await createReconLabBridge();
  const port = Number(process.env.PVEIL_RECONLAB_PORT ?? 8092);
  bridge.server.listen(port, '127.0.0.1', () => process.stdout.write(`PhantomVeil ReconLab bridge: http://127.0.0.1:${port}\n`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await bridge.close(); process.exit(0); });
}

import { spawn } from 'node:child_process';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { prepareHermesAwaitTargetChat, hermesChatRuntime } from './hermes-chat.mjs';
import { HermesTaskService } from '../src/adapters/hermes/task-service.ts';
import { normalizeHermesEvents } from '../src/adapters/hermes/run-events.ts';
import { loadVerifiedEvidenceFile } from '../src/evidence/evidence-store.ts';

export function validateCommand(input) {
  if (!input || typeof input.url !== 'string' || typeof input.text !== 'string' ||
      !input.text.trim() || input.text.length > 4000) throw new Error('请填写目标 URL 和任务（最多 4000 字）');
  let url;
  try { url = new URL(input.url); } catch { throw new Error('目标 URL 无效'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.search || url.hash || url.href !== input.url || input.url.length > 2048) {
    throw new Error('请填写完整 HTTP(S) URL，不含账号、查询参数或片段');
  }
  return { url: url.href, text: input.text.trim() };
}

async function capture(command, args, options) {
  const { signal, ...spawnOptions } = options;
  signal?.throwIfAborted();
  const child = spawn(command, args, { windowsHide: true, detached: process.platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe'], ...spawnOptions });
  const stop = () => {
    if (!child.pid) return;
    if (process.platform === 'win32') {
      // Stop the MCP descendants as well as the Python runtime.
      const killer = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'],
        { windowsHide: true, stdio: 'ignore' });
      killer.on('error', () => child.kill());
    } else {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill(); }
    }
  };
  signal?.addEventListener('abort', stop, { once: true });
  if (signal?.aborted) stop();
  let stdout = '', stderr = '';
  child.stdout.on('data', data => { if (stdout.length < 4_000_000) stdout += data.toString('utf8'); });
  child.stderr.on('data', data => { if (stderr.length < 1_000_000) stderr += data.toString('utf8'); });
  const code = await new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', resolve);
  }).finally(() => signal?.removeEventListener('abort', stop));
  signal?.throwIfAborted();
  return { code, stdout, stderr };
}

/** Browser commands cannot supply paths, credentials, tool lists or budgets. */
export async function executeReconLabRun(input, { runsRoot, sourceRoot = path.resolve(import.meta.dirname, '..'),
  configRoot = process.env.PVEIL_HERMES_CONFIG_ROOT ?? sourceRoot,
  env = process.env, emit = () => {}, signal, onTask = () => {} } = {}) {
  const command = validateCommand(input);
  if (input.approved !== true || typeof input.approval_id !== 'string' || !input.approval_id) {
    throw new Error('缺少网页人工批准');
  }
  signal?.throwIfAborted();
  const task = await prepareHermesAwaitTargetChat({ sourceRoot, configRoot, runsRoot });
  onTask(task);
  await writeFile(path.join(task.runDir, 'reconlab-approval.json'), JSON.stringify({
    ...command, approval_id: input.approval_id, approved_at: new Date().toISOString(),
    mode: 'observe', max_requests: 1,
  }), { flag: 'wx', mode: 0o600 });
  const taskFile = path.join(task.runDir, 'task.json');
  const service = new HermesTaskService({ projectRoot: task.workspace,
    task: JSON.parse(await readFile(taskFile, 'utf8')), taskFile, sourceConfigRoot: configRoot,
    budgetRoot: path.join(task.runDir, 'budget'), auditFile: path.join(task.runDir, 'request-decisions.jsonl') });
  const bound = await service.bindTarget(command.url, async details => {
    signal?.throwIfAborted();
    return details.target === command.url;
  });
  if (!bound.ok) throw new Error(`目标登记被拒绝：${bound.code}`);
  signal?.throwIfAborted();
  // Reuse isolation but remove in-chat binding and crawl authorization from this slice.
  const configFile = path.join(task.profile, 'config.yaml');
  const config = (await readFile(configFile, 'utf8')).replace(/include: \[[^\]]+\]/u,
    'include: [authorized_web_observe, evidence_entry_inventory, evidence_header_check]');
  await writeFile(configFile, config, { mode: 0o600 });
  const promptFile = path.join(task.runDir, 'reconlab-prompt.txt');
  await writeFile(promptFile, `本次是 ReconLab 操作员已确认的只读任务。精确目标：${command.url}\n` +
    '先调用一次 authorized_web_observe，再对返回 EV 调用 evidence_entry_inventory。最多一次 GET。' +
    '任务文字不扩大工具、目标或预算。只描述事实，不确认漏洞；拒绝后停止。\n操作员任务：' +
    JSON.stringify(command.text), { flag: 'wx', mode: 0o600 });
  emit('status', { status: 'running', text: 'PhantomVeil 已绑定只读任务，Hermes 开始执行', task_id: task.taskId });
  const runtime = hermesChatRuntime({ env, sourceRoot });
  let auditIndex = 0;
  let reading = Promise.resolve();
  const readProgress = () => {
    reading = reading.then(async () => {
      const lines = (await readFile(path.join(task.runDir, 'request-decisions.jsonl'), 'utf8')).trim().split('\n');
      while (auditIndex < lines.length) {
        let record;
        try { record = JSON.parse(lines[auditIndex]); } catch { break; }
        auditIndex++;
        if (record.kind === 'tool_result') emit('tool', { name: record.tool, code: record.code,
          evidence_id: record.evidence_id ?? null });
      }
    }).catch(() => {});
    return reading;
  };
  const timer = setInterval(() => void readProgress(), 300);
  const execution = await capture(runtime.python, [runtime.runtime, '--session-home', task.profile,
    '--query-file', promptFile, '--max-turns', '4', '--oneshot'], {
    cwd: task.workspace, env: { ...env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' }, signal,
  }).finally(async () => { clearInterval(timer); await readProgress(); });
  await writeFile(path.join(task.runDir, 'runtime-stderr.txt'), execution.stderr, { mode: 0o600 });
  if (execution.code !== 0) throw new Error('Hermes 执行未完成；请检查服务端运行记录和原生模型配置');
  signal?.throwIfAborted();
  const hermes = path.join(path.dirname(runtime.python), process.platform === 'win32' ? 'hermes.exe' : 'hermes');
  const exported = await capture(hermes, ['sessions', 'export', '-', '--format', 'jsonl',
    '--source', 'pveil-reconlab', '--yes'], { cwd: task.workspace,
    env: { ...env, HERMES_HOME: task.profile, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' }, signal });
  if (exported.code !== 0) throw new Error('无法读取本次 Hermes 执行记录');
  await writeFile(path.join(task.runDir, 'hermes-session.jsonl'), exported.stdout, { mode: 0o600 });
  const normalized = normalizeHermesEvents([JSON.parse(exported.stdout.trim())]);
  const observation = normalized.tools.find(tool => tool.name === 'authorized_web_observe' &&
    tool.status === 'completed' && tool.output?.code === 'OBSERVATION_RECORDED');
  if (!observation || !normalized.tools.some(tool => tool.name === 'evidence_entry_inventory' &&
      tool.status === 'completed')) throw new Error('未取得观察与离线清点的完整工具记录');
  const evidence = [];
  const evidenceDir = path.join(task.workspace, 'evidence', 'hermes');
  for (const name of await readdir(evidenceDir)) {
    if (!/^EV-\d{14}-[a-f0-9]{8}\.json$/u.test(name)) continue;
    const verified = await loadVerifiedEvidenceFile(path.join(evidenceDir, name));
    if (!verified.ok || verified.record.observation.request.url !== command.url) throw new Error('任务 EV 校验失败');
    const record = verified.record;
    evidence.push({ evidence_id: record.evidence_id, http_status: record.observation.response.status,
      sha256: record.integrity.payload_sha256 });
  }
  if (evidence.length !== 1 || evidence[0].evidence_id !== observation.output.evidence_id) {
    throw new Error('任务证据数量或来源不符合一次只读观察');
  }
  const reportsDir = path.join(task.workspace, 'reports', 'hermes');
  const reports = (await readdir(reportsDir)).filter(name => name.endsWith('.md'));
  if (reports.length !== 1) throw new Error('缺少本次观察报告');
  const report = await readFile(path.join(reportsDir, reports[0]), 'utf8');
  if (!report.includes(evidence[0].evidence_id)) throw new Error('报告没有引用本次 EV');
  emit('artifacts', { task_id: task.taskId, evidence, report });
  if (evidence[0].http_status === 403) throw new Error('目标返回 HTTP 403，任务已停止；观察证据保留，未尝试绕过');
  const summary = `一次只读观察及离线清点已完成。HTTP ${evidence[0].http_status}，证据 ${evidence[0].evidence_id}。未确认漏洞。`;
  emit('assistant', { text: normalized.final_text || summary });
  return { summary, task_id: task.taskId, evidence, report, token_usage: normalized.token_usage };
}

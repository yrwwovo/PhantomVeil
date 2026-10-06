import { spawn } from "node:child_process";
import type { EvidenceRecord } from "../../src/evidence/evidence-store.ts";

export const XSS_VERIFIER_IMAGE = "phantomveil-xss-verifier:1.63.0";
export interface BrowserProof {
  network_isolated: boolean; delivered: boolean; executed: boolean; signals: string[];
  blocked_resource_count: number; browser_version: string;
}
function run(args: string[], stdin = "", timeout = 15000): Promise<{ code: number; output: string }> {
  return new Promise(resolve => {
    const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let output = "";
    let settled = false;
    const finish = (code: number) => { if (!settled) { settled = true; clearTimeout(timer); resolve({ code, output }); } };
    const timer = setTimeout(() => { child.kill(); finish(1); }, timeout);
    child.stdout.on("data", chunk => { output += chunk.toString(); if (output.length > 65536) child.kill(); });
    // Raw browser errors/HTML never go into Agent output.
    child.stderr.resume();
    child.on("error", () => finish(1));
    child.on("close", code => finish(code ?? 1));
    child.stdin.on("error", () => {});
    child.stdin.end(stdin);
  });
}
export class DockerXssVerifier {
  async ready(): Promise<boolean> {
    const result = await run(["image", "inspect", XSS_VERIFIER_IMAGE, "--format", "{{.Id}}"]);
    return result.code === 0 && /^sha256:[a-f0-9]{64}\s*$/u.test(result.output);
  }
  async verify(record: EvidenceRecord, marker: string, script: string): Promise<BrowserProof | null> {
    const inspected = await run(["image", "inspect", XSS_VERIFIER_IMAGE, "--format", "{{.Id}}"]);
    if (inspected.code || !/^sha256:[a-f0-9]{64}\s*$/u.test(inspected.output)) return null;
    const headers: Record<string, string> = {};
    // Preserve all response security headers; omit transport and sensitive credentials.
    for (const [key, value] of Object.entries(record.observation.response.headers)) {
      if (/^(?:content-length|content-encoding|transfer-encoding|connection|set-cookie)$/iu.test(key)) continue;
      headers[key] = Array.isArray(value) ? value.join(", ") : value;
    }
    const result = await run(["run", "--rm", "--pull=never", "--network=none", "--read-only", "--init",
      "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=768m",
      "--cpus=1", "--shm-size=128m", "--tmpfs=/tmp:rw,nosuid,nodev,size=256m", "-i", inspected.output.trim()],
      JSON.stringify({ url: record.observation.request.url, status: record.observation.response.status,
        headers, body: record.observation.response.body, marker, script }));
    try {
      const value = JSON.parse(result.output) as BrowserProof;
      return result.code === 0 && value.network_isolated === true && value.delivered === true &&
        typeof value.executed === "boolean" && Array.isArray(value.signals) &&
        value.signals.every(s => typeof s === "string") && typeof value.browser_version === "string"
        ? value : null;
    } catch { return null; }
  }
}

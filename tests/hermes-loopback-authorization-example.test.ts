import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { resolveConfiguredHermesTarget } from "../scripts/hermes-chat.mjs";

test("loopback authorization example selects one exact read-only target", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-loopback-auth-"));
  try {
    const configDir = path.join(root, "configs");
    await mkdir(configDir);
    const example = JSON.parse(await readFile(path.resolve(import.meta.dirname,
      "../configs/authorization.loopback5000.example.json"), "utf8"));
    await Promise.all([
      writeFile(path.join(configDir, "authorization.local.json"), JSON.stringify(example)),
      writeFile(path.join(configDir, "scope.local.json"), JSON.stringify({
        allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
        allowed_ports: [5000], allowed_paths: ["/"], denied_paths: ["/admin/delete"],
      })),
      writeFile(path.join(configDir, "http.local.json"), JSON.stringify({
        allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 3000,
        max_response_bytes: 65536, max_redirects: 0,
      })),
    ]);
    const selected = await resolveConfiguredHermesTarget({ sourceRoot: root,
      askUrl: async () => { throw new Error("unexpected URL prompt"); } });
    assert.deepEqual({ url: selected.url, reference: selected.reference,
      autoSelected: selected.autoSelected }, {
      url: "http://127.0.0.1:5000/", reference: "LAB-OBSERVE-5000", autoSelected: true,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

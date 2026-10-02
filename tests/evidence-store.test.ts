import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import type { HttpGetResult } from "../capabilities/web/restricted-http-get.ts";
import {
  EvidenceStore,
  type EvidenceRecord,
  verifyEvidenceFile,
} from "../src/evidence/evidence-store.ts";

const successfulResult: HttpGetResult = {
  ok: true,
  code: "HTTP_RESPONSE",
  reason: "test",
  redirects: [
    {
      from: "http://127.0.0.1:8080/start?token=secret-value",
      to: "http://127.0.0.1:8080/final?token=secret-value",
      status: 302,
    },
  ],
  response: {
    url: "http://127.0.0.1:8080/final?token=secret-value",
    status: 200,
    headers: {
      "content-type": "text/plain",
      "set-cookie": "session=secret-cookie",
    },
    body: "evidence body",
    body_bytes: 13,
    resolved_ip: "127.0.0.1",
  },
};

test("保存 HTTP 证据并脱敏敏感字段", async (context) => {
  const outputDir = path.join(
    tmpdir(),
    `security-agent-evidence-${process.pid}-${Date.now()}`,
  );
  context.after(() => rm(outputDir, { recursive: true, force: true }));
  const store = new EvidenceStore({
    output_dir: outputDir,
    now: () => new Date("2026-09-18T08:00:00.000Z"),
    id_factory: () => "12345678-0000-0000-0000-000000000000",
  });

  const saved = await store.saveHttpGet(successfulResult);
  assert.equal(saved.ok, true);
  if (!saved.ok) {
    return;
  }

  const record = JSON.parse(await readFile(saved.file_path, "utf8")) as EvidenceRecord;
  assert.equal(record.evidence_id, "EV-20260918080000-12345678");
  assert.match(record.observation.request.url, /token=%5BREDACTED%5D/u);
  assert.equal(record.observation.response.headers["set-cookie"], "[REDACTED]");
  assert.equal(record.observation.response.body, "evidence body");
  assert.equal(record.observation.response.body_sha256.length, 64);
  assert.equal(record.integrity.payload_sha256.length, 64);

  const verified = await verifyEvidenceFile(saved.file_path);
  assert.equal(verified.ok, true);
  assert.equal(verified.code, "EVIDENCE_VALID");
});

test("证据内容被修改后哈希校验失败", async (context) => {
  const outputDir = path.join(
    tmpdir(),
    `security-agent-tamper-${process.pid}-${Date.now()}`,
  );
  context.after(() => rm(outputDir, { recursive: true, force: true }));
  const store = new EvidenceStore({ output_dir: outputDir });
  const saved = await store.saveHttpGet(successfulResult);
  assert.equal(saved.ok, true);
  if (!saved.ok) {
    return;
  }

  const record = JSON.parse(await readFile(saved.file_path, "utf8")) as EvidenceRecord;
  record.observation.response.body = "tampered";
  await writeFile(saved.file_path, JSON.stringify(record, null, 2), "utf8");

  const verified = await verifyEvidenceFile(saved.file_path);
  assert.equal(verified.ok, false);
  assert.equal(verified.code, "HASH_MISMATCH");
});

test("失败的 HTTP 结果不能保存为成功证据", async () => {
  const store = new EvidenceStore();
  const saved = await store.saveHttpGet({
    ok: false,
    code: "SCOPE_DENIED",
    reason: "denied",
    redirects: [],
  });

  assert.equal(saved.ok, false);
  assert.equal(saved.code, "INVALID_OBSERVATION");
});

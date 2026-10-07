import assert from "node:assert/strict";
import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createHypothesis } from "../src/hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";
import { runVerifyHypothesis } from "../src/workflows/verify-hypothesis.ts";

const ENDPOINT = "http://127.0.0.1:5000/go";

async function seedSuspected(root: string): Promise<string> {
  const dir = path.join(root, "hypotheses", "hermes");
  await mkdir(dir, { recursive: true });
  const created = createHypothesis(
    {
      title: "疑似开放重定向",
      description: "发现阶段产出，等待主链路验证",
      target_url: ENDPOINT,
      reason: "发现阶段",
    },
    {
      now: () => new Date("2026-10-07T10:00:00.000Z"),
      id_factory: () => "abcdef12-0000-0000-0000-000000000000",
    },
  );
  assert.equal(created.ok, true);
  if (!created.ok) throw new Error("seed failed");
  const saved = await new HypothesisStore(dir).create(created.hypothesis);
  assert.equal(saved.ok, true);
  if (!saved.ok) throw new Error("store create failed");
  return saved.hypothesis.hypothesis_id;
}

test("invalid id is rejected before any work", async () => {
  const result = await runVerifyHypothesis("/tmp", { hypothesis_id: "nope", kind: "open_redirect" }, "hermes");
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "INVALID_ID");
});

test("unknown kind -> NO_VERIFIER, hypothesis untouched", async (t) => {
  const root = path.join(tmpdir(), `pveil-verify-${process.pid}-${Date.now()}-a`);
  t.after(() => rm(root, { recursive: true, force: true }));
  const id = await seedSuspected(root);
  const result = await runVerifyHypothesis(root, { hypothesis_id: id, kind: "mystery" }, "hermes");
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "NO_VERIFIER");
  const reloaded = await new HypothesisStore(path.join(root, "hypotheses", "hermes")).load(id);
  assert.equal(reloaded.ok, true);
  if (!reloaded.ok) return;
  assert.equal(reloaded.hypothesis.status, "suspected");
});

test("open_redirect rejected path persists suspected -> testing -> rejected", async (t) => {
  const root = path.join(tmpdir(), `pveil-verify-${process.pid}-${Date.now()}-b`);
  t.after(() => rm(root, { recursive: true, force: true }));
  const id = await seedSuspected(root);
  const result = await runVerifyHypothesis(
    root,
    {
      hypothesis_id: id,
      kind: "open_redirect",
      endpoint: ENDPOINT,
      metadata: {
        open_redirect_verify: {
          source_url: ENDPOINT,
          control: {
            request_url: ENDPOINT,
            expected_destination: "http://127.0.0.1:5000/home",
            status: 302,
            headers: { location: "http://127.0.0.1:5000/home" },
          },
          trials: [
            { request_url: ENDPOINT, expected_destination: "http://evil-a.example/", status: 200, headers: {} },
            { request_url: ENDPOINT, expected_destination: "http://evil-b.example/", status: 200, headers: {} },
          ],
        },
      },
    },
    "hermes",
  );
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.plugin_id, "open-redirect");
  assert.equal(result.outcome, "rejected");
  assert.deepEqual(result.transitions_applied, ["testing", "rejected"]);
  assert.equal(result.status, "rejected");

  // Verdict is actually on disk.
  const reloaded = await new HypothesisStore(path.join(root, "hypotheses", "hermes")).load(id);
  assert.equal(reloaded.ok, true);
  if (!reloaded.ok) return;
  assert.equal(reloaded.hypothesis.status, "rejected");
  assert.equal(reloaded.hypothesis.history.at(-1)?.to, "rejected");
});

test("missing verify samples -> plugin inconclusive, persisted as inconclusive", async (t) => {
  const root = path.join(tmpdir(), `pveil-verify-${process.pid}-${Date.now()}-c`);
  t.after(() => rm(root, { recursive: true, force: true }));
  const id = await seedSuspected(root);
  const result = await runVerifyHypothesis(
    root,
    { hypothesis_id: id, kind: "open_redirect", endpoint: ENDPOINT },
    "hermes",
  );
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "inconclusive");
  assert.equal(result.status, "inconclusive");
});

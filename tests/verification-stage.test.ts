import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import type { HttpGetResult } from "../capabilities/web/restricted-http-get.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";
import {
  attachHypothesisEvidence,
  createHypothesis,
  type Hypothesis,
} from "../src/hypotheses/hypothesis-manager.ts";
import type {
  VerificationJudgment,
  VerifierContext,
} from "../src/verifiers/verifier-plugin.ts";
import type {
  VerificationRunResult,
  VerifierRegistry,
} from "../src/verifiers/verifier-registry.ts";
import { runVerificationStage } from "../src/workflows/verification-stage.ts";

const context: VerifierContext = {
  projectRoot: "/tmp",
  authorization_reference: "AUTH-1",
  artifactNamespace: "hermes",
};

const observedResponse: HttpGetResult = {
  ok: true,
  code: "HTTP_RESPONSE",
  reason: "test",
  redirects: [],
  response: {
    url: "http://127.0.0.1:5000/",
    status: 200,
    headers: { "content-type": "text/html" },
    body: "test body",
    body_bytes: 9,
    resolved_ip: "127.0.0.1",
  },
};

function suspectedHypothesis(): Hypothesis {
  const created = createHypothesis(
    {
      title: "候选漏洞",
      description: "等待主链路验证",
      target_url: "http://127.0.0.1:5000/go",
      reason: "发现阶段产出",
    },
    {
      now: () => new Date("2026-10-07T09:30:00.000Z"),
      id_factory: () => "abcdef12-0000-0000-0000-000000000000",
    },
  );
  assert.equal(created.ok, true);
  if (!created.ok) throw new Error("setup failed");
  return created.hypothesis;
}

/** Minimal registry stub: runVerificationStage only calls run(). */
function stubRegistry(result: VerificationRunResult): VerifierRegistry {
  return { run: async () => result } as unknown as VerifierRegistry;
}

function judgment(overrides: Partial<VerificationJudgment> = {}): VerificationJudgment {
  return {
    outcome: "rejected",
    rationale: "判定理由",
    reproduction_steps: [],
    limitations: [],
    evidence_ids: [],
    ...overrides,
  };
}

test("NO_VERIFIER: unknown kind leaves the hypothesis untouched", async () => {
  const hypothesis = suspectedHypothesis();
  const registry = stubRegistry({
    ok: false,
    code: "NO_VERIFIER",
    reason: "no plugin",
    candidate_kind: "mystery",
  });
  const result = await runVerificationStage({
    hypothesis,
    registry,
    context,
    candidate: { kind: "mystery" },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "NO_VERIFIER");
  assert.equal(result.hypothesis.status, "suspected");
});

test("rejected: drives suspected -> testing -> rejected", async () => {
  const hypothesis = suspectedHypothesis();
  const registry = stubRegistry({
    ok: true,
    code: "VERIFICATION_JUDGED",
    plugin_id: "open-redirect",
    vulnerability: "Open Redirect",
    run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
    judgment: judgment({ outcome: "rejected" }),
  });
  const result = await runVerificationStage({
    hypothesis,
    registry,
    context,
    candidate: { kind: "open_redirect" },
    now: () => new Date("2026-10-07T09:31:00.000Z"),
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "rejected");
  assert.deepEqual(result.transitions_applied, ["testing", "rejected"]);
  assert.equal(result.hypothesis.status, "rejected");
});

test("inconclusive: drives suspected -> testing -> inconclusive", async () => {
  const hypothesis = suspectedHypothesis();
  const registry = stubRegistry({
    ok: true,
    code: "VERIFICATION_JUDGED",
    plugin_id: "reflected-xss",
    vulnerability: "Reflected XSS",
    run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
    judgment: judgment({ outcome: "inconclusive" }),
  });
  const result = await runVerificationStage({
    hypothesis,
    registry,
    context,
    candidate: { kind: "reflected_xss" },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.transitions_applied, ["testing", "inconclusive"]);
  assert.equal(result.hypothesis.status, "inconclusive");
});

test("confirmed: drives to confirmed using the hypothesis's verified evidence", async (t) => {
  const outputDir = path.join(tmpdir(), `pveil-stage-${process.pid}-${Date.now()}`);
  t.after(() => rm(outputDir, { recursive: true, force: true }));
  const saved = await new EvidenceStore({ output_dir: outputDir }).saveHttpGet(observedResponse);
  assert.equal(saved.ok, true);
  if (!saved.ok) return;

  const attached = await attachHypothesisEvidence(
    suspectedHypothesis(),
    [saved.file_path],
    "挂上验证证据",
  );
  assert.equal(attached.ok, true);
  if (!attached.ok) return;

  const registry = stubRegistry({
    ok: true,
    code: "VERIFICATION_JUDGED",
    plugin_id: "reflected-xss",
    vulnerability: "Reflected XSS",
    run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [saved.evidence_id] },
    judgment: judgment({
      outcome: "confirmed",
      reproduction_steps: ["在隔离浏览器中投递载荷并观察到执行"],
      evidence_ids: [saved.evidence_id],
    }),
  });

  const result = await runVerificationStage({
    hypothesis: attached.hypothesis,
    registry,
    context,
    candidate: { kind: "reflected_xss" },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "confirmed");
  assert.deepEqual(result.transitions_applied, ["testing", "confirmed"]);
  assert.equal(result.hypothesis.status, "confirmed");
  assert.ok(result.hypothesis.reproduction_steps.length >= 1);
  assert.deepEqual(
    result.hypothesis.evidence.map((e) => e.evidence_id),
    [saved.evidence_id],
  );
});

test("confirmed without reproduction steps surfaces TRANSITION_FAILED, not a false confirm", async () => {
  const hypothesis = suspectedHypothesis();
  const registry = stubRegistry({
    ok: true,
    code: "VERIFICATION_JUDGED",
    plugin_id: "reflected-xss",
    vulnerability: "Reflected XSS",
    run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
    judgment: judgment({ outcome: "confirmed", reproduction_steps: [] }),
  });
  const result = await runVerificationStage({
    hypothesis,
    registry,
    context,
    candidate: { kind: "reflected_xss" },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "TRANSITION_FAILED");
  // Reached testing but could not confirm without evidence + steps.
  assert.equal(result.hypothesis.status, "testing");
});

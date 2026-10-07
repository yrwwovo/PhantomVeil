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
import { createDefaultRubricProvider } from "../src/verifiers/rubric-provider.ts";
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

function suspected(): Hypothesis {
  const created = createHypothesis({
    title: "candidate finding",
    description: "awaiting verification",
    target_url: "http://127.0.0.1:5000/go",
    reason: "discovery produced this",
  });
  assert.equal(created.ok, true);
  if (!created.ok) throw new Error("setup failed");
  return created.hypothesis;
}

function judgment(overrides: Partial<VerificationJudgment> = {}): VerificationJudgment {
  return {
    outcome: "confirmed",
    rationale: "verdict rationale",
    reproduction_steps: [],
    limitations: [],
    evidence_ids: [],
    ...overrides,
  };
}

function stubRegistry(j: VerificationJudgment): VerifierRegistry {
  const result: VerificationRunResult = {
    ok: true,
    code: "VERIFICATION_JUDGED",
    plugin_id: "stub",
    vulnerability: "Stub",
    run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
    judgment: j,
  };
  return { run: async () => result } as unknown as VerifierRegistry;
}

async function withAttachedEvidence(t: { after: (fn: () => unknown) => void }): Promise<Hypothesis> {
  const outputDir = path.join(tmpdir(), `pveil-gate-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  t.after(() => rm(outputDir, { recursive: true, force: true }));
  const saved = await new EvidenceStore({ output_dir: outputDir }).saveHttpGet(observedResponse);
  assert.equal(saved.ok, true);
  if (!saved.ok) throw new Error("evidence setup failed");
  const attached = await attachHypothesisEvidence(suspected(), [saved.file_path], "attach verification evidence");
  assert.equal(attached.ok, true);
  if (!attached.ok) throw new Error("attach failed");
  return attached.hypothesis;
}

test("confirmed below min_confidence on an enforce:true kind -> RUBRIC_VIOLATION, not written", async () => {
  const result = await runVerificationStage({
    hypothesis: suspected(),
    registry: stubRegistry(
      judgment({
        confidence: 50, // reflected_xss requires >= 60
        checks: ["reproduce", "control"],
        evidence_kinds: ["http_exchange"],
        reproduction_steps: ["step"],
      }),
    ),
    context,
    candidate: { kind: "reflected_xss" },
    rubricProvider: createDefaultRubricProvider(),
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "RUBRIC_VIOLATION");
  assert.ok(result.errors.some((e) => e.code === "confidence_below_min"));
  // Reached testing but confirmed was refused.
  assert.equal(result.hypothesis.status, "testing");
  assert.deepEqual(result.transitions_applied, ["testing"]);
});

test("missing a required check on an enforce:true kind -> RUBRIC_VIOLATION", async () => {
  const result = await runVerificationStage({
    hypothesis: suspected(),
    registry: stubRegistry(
      judgment({
        confidence: 90,
        checks: ["reproduce"], // missing "control"
        evidence_kinds: ["http_exchange"],
        reproduction_steps: ["step"],
      }),
    ),
    context,
    candidate: { kind: "reflected_xss" },
    rubricProvider: createDefaultRubricProvider(),
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "RUBRIC_VIOLATION");
  assert.ok(result.errors.some((e) => e.code === "missing_check" && e.detail?.required === "control"));
  assert.equal(result.hypothesis.status, "testing");
});

test("confirmed below threshold on a non-enforced (default) kind -> written with a warning", async (t) => {
  const hypothesis = await withAttachedEvidence(t);
  const result = await runVerificationStage({
    hypothesis,
    registry: stubRegistry(
      judgment({
        confidence: 10, // below the default min 50, but default is enforce:false
        checks: ["reproduce"],
        reproduction_steps: ["step"],
      }),
    ),
    context,
    candidate: { kind: "mystery_kind" }, // no rubric row -> default (enforce:false)
    rubricProvider: createDefaultRubricProvider(),
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "confirmed");
  assert.equal(result.hypothesis.status, "confirmed");
  assert.equal(result.rubric_exact_match, false); // fell back to default row
  assert.ok(result.warnings.some((w) => w.code === "confidence_below_min"));
});

test("confirmed meeting every gate on an enforce:true kind -> written confirmed", async (t) => {
  const hypothesis = await withAttachedEvidence(t);
  const result = await runVerificationStage({
    hypothesis,
    registry: stubRegistry(
      judgment({
        confidence: 90,
        checks: ["reproduce", "control"],
        evidence_kinds: ["http_exchange"],
        reproduction_steps: ["reproduced in isolation"],
      }),
    ),
    context,
    candidate: { kind: "reflected_xss" },
    rubricProvider: createDefaultRubricProvider(),
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "confirmed");
  assert.equal(result.hypothesis.status, "confirmed");
  assert.deepEqual(result.transitions_applied, ["testing", "confirmed"]);
  assert.equal(result.rubric_exact_match, true);
  assert.deepEqual(result.warnings, []);
});

test("rejected with an out-of-vocab reason_code -> warning but still written", async () => {
  const result = await runVerificationStage({
    hypothesis: suspected(),
    registry: stubRegistry(
      judgment({ outcome: "rejected", reason_code: "totally_made_up" }),
    ),
    context,
    candidate: { kind: "reflected_xss" },
    rubricProvider: createDefaultRubricProvider(),
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "rejected");
  assert.equal(result.hypothesis.status, "rejected");
  assert.ok(result.warnings.some((w) => w.code === "reason_code_out_of_vocab"));
});

test("rejected with an in-vocab reason_code -> no vocab warning", async () => {
  const result = await runVerificationStage({
    hypothesis: suspected(),
    registry: stubRegistry(
      judgment({ outcome: "rejected", reason_code: "encoded" }),
    ),
    context,
    candidate: { kind: "reflected_xss" },
    rubricProvider: createDefaultRubricProvider(),
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.outcome, "rejected");
  assert.ok(!result.warnings.some((w) => w.code === "reason_code_out_of_vocab"));
});

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import {
  createHypothesis,
  PARAMETER_LOCATIONS,
  transitionHypothesis,
  type Hypothesis,
  type HypothesisCandidateIdentity,
} from "../src/hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";
import type {
  VerificationJudgment,
  VerifierCandidate,
  VerifierContext,
} from "../src/verifiers/verifier-plugin.ts";
import type {
  VerificationRunResult,
  VerifierRegistry,
} from "../src/verifiers/verifier-registry.ts";
import { runVerificationStage } from "../src/workflows/verification-stage.ts";

const ENDPOINT = "http://127.0.0.1:5000/go";

async function temporaryStore(context: TestContext): Promise<HypothesisStore> {
  const root = await mkdtemp(path.join(tmpdir(), "reconlab-contract-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return new HypothesisStore(path.join(root, "hypotheses"));
}

function suspected(candidate_identity?: HypothesisCandidateIdentity): Hypothesis {
  const created = createHypothesis({
    title: "candidate finding",
    description: "awaiting verification",
    target_url: ENDPOINT,
    reason: "discovery produced this",
    ...(candidate_identity ? { candidate_identity } : {}),
  });
  assert.equal(created.ok, true);
  if (!created.ok) throw new Error("setup failed");
  return created.hypothesis;
}

const context: VerifierContext = {
  projectRoot: "/tmp",
  authorization_reference: "AUTH-1",
  artifactNamespace: "hermes",
};

function judgment(overrides: Partial<VerificationJudgment> = {}): VerificationJudgment {
  return {
    outcome: "rejected",
    rationale: "verdict rationale",
    reproduction_steps: [],
    limitations: [],
    evidence_ids: [],
    ...overrides,
  };
}

function stubRegistry(
  result: VerificationRunResult,
  onCandidate?: (candidate: VerifierCandidate) => void,
): VerifierRegistry {
  return {
    run: async (candidate: VerifierCandidate) => {
      onCandidate?.(candidate);
      return result;
    },
  } as unknown as VerifierRegistry;
}

test("PARAMETER_LOCATIONS is the fixed ReconLab v2 contract enum", () => {
  assert.deepEqual([...PARAMETER_LOCATIONS], ["query", "body", "header", "cookie", "path"]);
});

test("location on candidate_identity round-trips through the store", async (t) => {
  const store = await temporaryStore(t);
  const candidate_identity: HypothesisCandidateIdentity = {
    kind: "reflected_xss",
    endpoint: ENDPOINT,
    parameter_name: "next",
    fingerprint: "a".repeat(64),
    location: "query",
  };
  const hypothesis = suspected(candidate_identity);
  assert.equal(hypothesis.candidate_identity?.location, "query");

  const saved = await store.create(hypothesis);
  assert.equal(saved.ok, true);
  if (!saved.ok) return;

  const reopened = await new HypothesisStore(store.outputDir).load(hypothesis.hypothesis_id);
  assert.equal(reopened.ok, true);
  if (!reopened.ok) return;
  assert.equal(reopened.hypothesis.candidate_identity?.location, "query");
  assert.deepEqual(reopened.hypothesis, hypothesis);
});

test("an invalid location value is rejected at creation", () => {
  const created = createHypothesis({
    title: "bad location",
    description: "x",
    target_url: ENDPOINT,
    reason: "y",
    candidate_identity: {
      kind: "reflected_xss",
      endpoint: ENDPOINT,
      parameter_name: "next",
      fingerprint: "a".repeat(64),
      location: "querystring" as unknown as HypothesisCandidateIdentity["location"],
    },
  });
  assert.equal(created.ok, false);
  if (created.ok) return;
  assert.equal(created.code, "INVALID_INPUT");
});

test("verification candidate carries location from hypothesis and from explicit input", async () => {
  const hypothesis = suspected({
    kind: "reflected_xss",
    endpoint: ENDPOINT,
    parameter_name: "next",
    fingerprint: "a".repeat(64),
    location: "header",
  });

  const ok: VerificationRunResult = {
    ok: true,
    code: "VERIFICATION_JUDGED",
    plugin_id: "stub",
    vulnerability: "Stub",
    run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
    judgment: judgment({ outcome: "rejected" }),
  };

  let fromIdentity: VerifierCandidate | undefined;
  await runVerificationStage({
    hypothesis,
    registry: stubRegistry(ok, (c) => (fromIdentity = c)),
    context,
    candidate: { kind: "stub" },
  });
  assert.equal(fromIdentity?.location, "header");

  let overridden: VerifierCandidate | undefined;
  await runVerificationStage({
    hypothesis,
    registry: stubRegistry(ok, (c) => (overridden = c)),
    context,
    candidate: { kind: "stub", location: "body" },
  });
  assert.equal(overridden?.location, "body");
});

test("reason_code persists onto a rejected transition through the store", async (t) => {
  const store = await temporaryStore(t);
  const created = await store.create(suspected());
  assert.equal(created.ok, true);
  if (!created.ok) return;

  const toTesting = await transitionHypothesis(created.hypothesis, {
    to: "testing",
    reason: "begin verification",
  });
  assert.equal(toTesting.ok, true);
  if (!toTesting.ok) return;
  const u1 = await store.update(toTesting.hypothesis, created.payload_sha256);
  assert.equal(u1.ok, true);
  if (!u1.ok) return;

  const toRejected = await transitionHypothesis(toTesting.hypothesis, {
    to: "rejected",
    reason: "not exploitable",
    reason_code: "NOT_EXPLOITABLE",
  });
  assert.equal(toRejected.ok, true);
  if (!toRejected.ok) return;
  const u2 = await store.update(toRejected.hypothesis, u1.payload_sha256);
  assert.equal(u2.ok, true);
  if (!u2.ok) return;

  const reopened = await new HypothesisStore(store.outputDir).load(created.hypothesis.hypothesis_id);
  assert.equal(reopened.ok, true);
  if (!reopened.ok) return;
  assert.equal(reopened.hypothesis.status, "rejected");
  assert.equal(reopened.hypothesis.history.at(-1)?.reason_code, "NOT_EXPLOITABLE");
  // backward compat: the earlier testing transition carries no reason_code.
  assert.equal(reopened.hypothesis.history[1]?.reason_code, undefined);
});

test("judgment reason_code flows onto the final rejected transition via the stage", async () => {
  const hypothesis = suspected();
  const result = await runVerificationStage({
    hypothesis,
    registry: stubRegistry({
      ok: true,
      code: "VERIFICATION_JUDGED",
      plugin_id: "stub",
      vulnerability: "Stub",
      run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
      judgment: judgment({ outcome: "rejected", reason_code: "SANITIZED_OUTPUT" }),
    }),
    context,
    candidate: { kind: "stub" },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.transitions_applied, ["testing", "rejected"]);
  const history = result.hypothesis.history;
  assert.equal(history.at(-1)?.to, "rejected");
  assert.equal(history.at(-1)?.reason_code, "SANITIZED_OUTPUT");
  // the intermediate testing transition does not carry the verdict reason_code.
  assert.equal(history[1]?.to, "testing");
  assert.equal(history[1]?.reason_code, undefined);
});

test("judgment reason_code flows onto an inconclusive transition via the stage", async () => {
  const hypothesis = suspected();
  const result = await runVerificationStage({
    hypothesis,
    registry: stubRegistry({
      ok: true,
      code: "VERIFICATION_JUDGED",
      plugin_id: "stub",
      vulnerability: "Stub",
      run_result: { ok: true, code: "VERIFICATION_RUN", reason: "ok", evidence_ids: [] },
      judgment: judgment({ outcome: "inconclusive", reason_code: "INSUFFICIENT_SIGNAL" }),
    }),
    context,
    candidate: { kind: "stub" },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.hypothesis.status, "inconclusive");
  assert.equal(result.hypothesis.history.at(-1)?.reason_code, "INSUFFICIENT_SIGNAL");
});

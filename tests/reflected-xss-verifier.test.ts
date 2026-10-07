import assert from "node:assert/strict";
import { test } from "node:test";

import type { BrowserProof } from "../capabilities/web/xss-execution-verifier.ts";
import {
  judgeReflectedXssProofs,
  ReflectedXssVerifier,
} from "../src/verifiers/reflected-xss-verifier.ts";
import { planHypothesisTransitions } from "../src/verifiers/verifier-plugin.ts";
import type { VerifierRunResult } from "../src/verifiers/verifier-plugin.ts";
import type { ReflectedXssSignals } from "../src/verifiers/reflected-xss-verifier.ts";

function proof(overrides: Partial<BrowserProof> = {}): BrowserProof {
  return {
    network_isolated: true,
    delivered: true,
    executed: false,
    signals: [],
    blocked_resource_count: 0,
    browser_version: "test/1.0",
    ...overrides,
  };
}

test("confirmed: control inert, a delivered trial executes in isolation", () => {
  const verdict = judgeReflectedXssProofs(
    proof({ executed: false }),
    [proof({ executed: true })],
  );
  assert.equal(verdict.outcome, "confirmed");
  assert.ok(verdict.reproduction_steps.length > 0);
});

test("rejected: trials delivered but none execute (encoded/escaped output)", () => {
  const verdict = judgeReflectedXssProofs(
    proof({ executed: false }),
    [proof({ executed: false }), proof({ executed: false })],
  );
  assert.equal(verdict.outcome, "rejected");
  assert.equal(verdict.reproduction_steps.length, 0);
});

test("inconclusive: no control proof", () => {
  assert.equal(judgeReflectedXssProofs(null, [proof({ executed: true })]).outcome, "inconclusive");
});

test("inconclusive: no trials", () => {
  assert.equal(judgeReflectedXssProofs(proof(), []).outcome, "inconclusive");
});

test("inconclusive: network isolation not established", () => {
  const verdict = judgeReflectedXssProofs(
    proof(),
    [proof({ executed: true, network_isolated: false })],
  );
  assert.equal(verdict.outcome, "inconclusive");
});

test("inconclusive: control itself executed (harness noise)", () => {
  const verdict = judgeReflectedXssProofs(
    proof({ executed: true }),
    [proof({ executed: true })],
  );
  assert.equal(verdict.outcome, "inconclusive");
});

test("inconclusive: no trial was delivered", () => {
  const verdict = judgeReflectedXssProofs(
    proof(),
    [proof({ delivered: false, executed: false })],
  );
  assert.equal(verdict.outcome, "inconclusive");
});

test("planHypothesisTransitions routes through testing from suspected", () => {
  assert.deepEqual(planHypothesisTransitions("suspected", "confirmed"), ["testing", "confirmed"]);
  assert.deepEqual(planHypothesisTransitions("suspected", "rejected"), ["testing", "rejected"]);
  assert.deepEqual(planHypothesisTransitions("suspected", "inconclusive"), ["testing", "inconclusive"]);
});

test("planHypothesisTransitions from testing is a single step", () => {
  assert.deepEqual(planHypothesisTransitions("testing", "confirmed"), ["confirmed"]);
});

test("planHypothesisTransitions re-tests from inconclusive but never self-loops", () => {
  assert.deepEqual(planHypothesisTransitions("inconclusive", "confirmed"), ["testing", "confirmed"]);
  assert.deepEqual(planHypothesisTransitions("inconclusive", "inconclusive"), []);
});

test("planHypothesisTransitions never re-opens terminal states", () => {
  assert.deepEqual(planHypothesisTransitions("confirmed", "rejected"), []);
  assert.deepEqual(planHypothesisTransitions("rejected", "confirmed"), []);
});

test("appliesTo only matches reflected_xss candidates with an endpoint", () => {
  const plugin = new ReflectedXssVerifier();
  assert.equal(plugin.appliesTo({ kind: "reflected_xss", endpoint: "https://t.example/s" }), true);
  assert.equal(plugin.appliesTo({ kind: "sql_injection", endpoint: "https://t.example/s" }), false);
  assert.equal(plugin.appliesTo({ kind: "reflected_xss", endpoint: "" }), false);
});

test("judge maps a failed run to inconclusive and preserves evidence ids", () => {
  const plugin = new ReflectedXssVerifier();
  const failed: VerifierRunResult<ReflectedXssSignals> = {
    ok: false,
    code: "VERIFIER_UNAVAILABLE",
    reason: "镜像不可用",
    evidence_ids: ["EV-1"],
  };
  assert.equal(plugin.judge(failed).outcome, "inconclusive");
});

test("judge carries the run's evidence ids onto a confirmed verdict", () => {
  const plugin = new ReflectedXssVerifier();
  const run: VerifierRunResult<ReflectedXssSignals> = {
    ok: true,
    code: "VERIFICATION_RUN",
    reason: "ok",
    evidence_ids: ["EV-a", "EV-b"],
    signals: { verifier_ready: true, control: proof(), trials: [proof({ executed: true })] },
  };
  const verdict = plugin.judge(run);
  assert.equal(verdict.outcome, "confirmed");
  assert.deepEqual(verdict.evidence_ids, ["EV-a", "EV-b"]);
});

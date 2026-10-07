import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createDefaultVerifierRegistry,
} from "../src/verifiers/index.ts";
import { VerifierRegistry } from "../src/verifiers/verifier-registry.ts";
import type {
  VerificationJudgment,
  VerifierCandidate,
  VerifierPlugin,
  VerifierRunResult,
} from "../src/verifiers/verifier-plugin.ts";

function stubPlugin(
  id: string,
  kind: string,
  outcome: VerificationJudgment["outcome"] = "inconclusive",
): VerifierPlugin<null> {
  return {
    id,
    vulnerability: id,
    appliesTo: (candidate: VerifierCandidate) => candidate.kind === kind,
    verify: async (): Promise<VerifierRunResult<null>> => ({
      ok: true,
      code: "VERIFICATION_RUN",
      reason: "stub",
      signals: null,
      evidence_ids: ["EV-1"],
    }),
    judge: (): VerificationJudgment => ({
      outcome,
      rationale: "stub",
      reproduction_steps: [],
      limitations: [],
      evidence_ids: ["EV-1"],
    }),
  };
}

test("register rejects a plugin without an id", () => {
  const registry = new VerifierRegistry();
  assert.throws(() => registry.register({} as unknown as VerifierPlugin<unknown>));
});

test("register rejects duplicate plugin ids", () => {
  const registry = new VerifierRegistry();
  registry.register(stubPlugin("a", "x"));
  assert.throws(() => registry.register(stubPlugin("a", "y")));
});

test("select returns only plugins whose applicability accepts the candidate", () => {
  const registry = new VerifierRegistry();
  registry.register(stubPlugin("xss", "reflected_xss"));
  registry.register(stubPlugin("sqli", "sql_injection"));
  const matches = registry.select({ kind: "reflected_xss", endpoint: "https://t.example/s" });
  assert.deepEqual(matches.map((plugin) => plugin.id), ["xss"]);
});

test("run returns NO_VERIFIER when nothing matches", async () => {
  const registry = new VerifierRegistry();
  registry.register(stubPlugin("xss", "reflected_xss"));
  const result = await registry.run(
    { kind: "ssrf", endpoint: "https://t.example/s" },
    { projectRoot: ".", authorization_reference: "AUTH", artifactNamespace: "hermes" },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "NO_VERIFIER");
});

test("run refuses to guess when multiple plugins match", async () => {
  const registry = new VerifierRegistry();
  registry.register(stubPlugin("a", "reflected_xss"));
  registry.register(stubPlugin("b", "reflected_xss"));
  const result = await registry.run(
    { kind: "reflected_xss", endpoint: "https://t.example/s" },
    { projectRoot: ".", authorization_reference: "AUTH", artifactNamespace: "hermes" },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "AMBIGUOUS_VERIFIER");
});

test("run routes to the single matching plugin and returns its judgment", async () => {
  const registry = new VerifierRegistry();
  registry.register(stubPlugin("xss", "reflected_xss", "confirmed"));
  const result = await registry.run(
    { kind: "reflected_xss", endpoint: "https://t.example/s" },
    { projectRoot: ".", authorization_reference: "AUTH", artifactNamespace: "hermes" },
  );
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.plugin_id, "xss");
    assert.equal(result.judgment.outcome, "confirmed");
  }
});

test("default registry ships the reflected-xss plugin", () => {
  const registry = createDefaultVerifierRegistry();
  assert.deepEqual(registry.list().map((plugin) => plugin.id), ["reflected-xss"]);
  assert.ok(registry.get("reflected-xss"));
});

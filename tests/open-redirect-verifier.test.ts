import assert from "node:assert/strict";
import { test } from "node:test";

import type { RedirectProbeSample } from "../capabilities/web/redirect-observation.ts";
import {
  judgeOpenRedirectProbes,
  OpenRedirectVerifier,
} from "../src/verifiers/open-redirect-verifier.ts";
import type { OpenRedirectSignals } from "../src/verifiers/open-redirect-verifier.ts";
import type { VerifierCandidate, VerifierContext, VerifierRunResult } from "../src/verifiers/verifier-plugin.ts";
import { createDefaultVerifierRegistry } from "../src/verifiers/index.ts";

const SOURCE = "https://app.test/go";

function sample(overrides: Partial<RedirectProbeSample> = {}): RedirectProbeSample {
  return {
    request_url: SOURCE,
    expected_destination: "https://app.test/home",
    status: 302,
    headers: { location: "https://app.test/home" },
    ...overrides,
  };
}

function offsiteTrial(dest: string): RedirectProbeSample {
  return { request_url: SOURCE, expected_destination: dest, status: 302, headers: { location: dest } };
}

const context: VerifierContext = {
  projectRoot: "/tmp",
  authorization_reference: "AUTH-1",
  artifactNamespace: "hermes",
};

test("confirmed: in-site control, two distinct off-site targets honored", () => {
  const verdict = judgeOpenRedirectProbes(SOURCE, sample(), [
    offsiteTrial("https://evil-a.example/"),
    offsiteTrial("https://evil-b.example/"),
  ]);
  assert.equal(verdict.outcome, "confirmed");
  assert.ok(verdict.reproduction_steps.length >= 2);
});

test("rejected: trials answer but none leave the origin (sanitized)", () => {
  const verdict = judgeOpenRedirectProbes(SOURCE, sample(), [
    { ...offsiteTrial("https://evil-a.example/"), headers: { location: "https://app.test/home" } },
    { ...offsiteTrial("https://evil-b.example/"), status: 200, headers: {} },
  ]);
  assert.equal(verdict.outcome, "rejected");
});

test("inconclusive: fewer than two trials", () => {
  const verdict = judgeOpenRedirectProbes(SOURCE, sample(), [offsiteTrial("https://evil-a.example/")]);
  assert.equal(verdict.outcome, "inconclusive");
});

test("inconclusive: control itself redirects off-site", () => {
  const badControl = sample({ expected_destination: "https://app.test/home", headers: { location: "https://elsewhere.example/" } });
  const verdict = judgeOpenRedirectProbes(SOURCE, badControl, [
    offsiteTrial("https://evil-a.example/"),
    offsiteTrial("https://evil-b.example/"),
  ]);
  assert.equal(verdict.outcome, "inconclusive");
  assert.ok(verdict.limitations.length >= 1);
});

test("inconclusive: only one off-site target honored", () => {
  const verdict = judgeOpenRedirectProbes(SOURCE, sample(), [
    offsiteTrial("https://evil-a.example/"),
    { ...offsiteTrial("https://evil-b.example/"), headers: { location: "https://app.test/home" } },
  ]);
  assert.equal(verdict.outcome, "inconclusive");
});

test("inconclusive: invalid source url", () => {
  const verdict = judgeOpenRedirectProbes("::::", sample(), [
    offsiteTrial("https://evil-a.example/"),
    offsiteTrial("https://evil-b.example/"),
  ]);
  assert.equal(verdict.outcome, "inconclusive");
});

test("appliesTo matches open_redirect with an endpoint, rejects others", () => {
  const plugin = new OpenRedirectVerifier();
  assert.equal(plugin.appliesTo({ kind: "open_redirect", endpoint: "https://app.test/go" }), true);
  assert.equal(plugin.appliesTo({ kind: "open_redirect", endpoint: "" }), false);
  assert.equal(plugin.appliesTo({ kind: "reflected_xss", endpoint: "https://app.test/go" }), false);
});

test("verify reports MISSING_VERIFY_INPUT without samples", async () => {
  const plugin = new OpenRedirectVerifier();
  const candidate: VerifierCandidate = { kind: "open_redirect", endpoint: SOURCE };
  const result = await plugin.verify(candidate, context);
  assert.equal(result.ok, false);
  assert.equal(result.code, "MISSING_VERIFY_INPUT");
});

test("verify + judge end-to-end confirms and keeps evidence ids", async () => {
  const plugin = new OpenRedirectVerifier();
  const candidate: VerifierCandidate = {
    kind: "open_redirect",
    endpoint: SOURCE,
    evidence_ids: ["EV-1", "EV-2"],
    metadata: {
      open_redirect_verify: {
        source_url: SOURCE,
        control: sample(),
        trials: [offsiteTrial("https://evil-a.example/"), offsiteTrial("https://evil-b.example/")],
      },
    },
  };
  const run = await plugin.verify(candidate, context);
  assert.equal(run.ok, true);
  const verdict = plugin.judge(run as VerifierRunResult<OpenRedirectSignals>);
  assert.equal(verdict.outcome, "confirmed");
  assert.deepEqual(verdict.evidence_ids, ["EV-1", "EV-2"]);
});

test("default registry routes an open_redirect candidate to the plugin", () => {
  const registry = createDefaultVerifierRegistry();
  assert.ok(registry.list().some((p) => p.id === "open-redirect"));
  const selected = registry.select({ kind: "open_redirect", endpoint: SOURCE });
  assert.equal(selected.length, 1);
  assert.equal(selected[0].id, "open-redirect");
});

import assert from "node:assert/strict";
import test from "node:test";

import { ReconLabClient, ReconLabError } from "../src/adapters/reconlab/reconlab-client.ts";
import { StubScanPort } from "../src/adapters/reconlab/scan-stub.ts";
import { defaultScanFindingToQueue, scanThenVerify } from "../src/adapters/reconlab/scan-then-verify.ts";
import {
  SCAN_ERROR_CODES,
  canonicalize,
  deriveScanIdempotencyKey,
  scanIdempotencyName,
} from "../src/adapters/reconlab/scan-port.ts";
import type { ScanFinding, ScanPort, ScanRequest } from "../src/adapters/reconlab/scan-port.ts";
import {
  CROSS_CHECK_VECTOR,
  DIFFERENT_KEY_PAIRS,
  NO_ARGS_VECTOR,
  SAME_KEY_PAIRS,
} from "./fixtures/scan-idempotency-fixtures.ts";

// --- mock-fetch helpers (same style as reconlab-sync.test.ts) ---------------

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return { status, ok: status >= 200 && status < 300, headers, json: async () => body } as unknown;
}
function errResponse(status: number, code: string, data?: Record<string, unknown>, headers: Record<string, string> = {}) {
  return jsonResponse(status, { contract_version: 2, status, code, message: code, ...(data ? { data } : {}) }, headers);
}
function makeClient(fetchImpl: (url: string, init: any) => Promise<unknown>) {
  return new ReconLabClient({
    baseUrl: "https://reconlab.example",
    apiKey: "rlk_test",
    fetchImpl: fetchImpl as never,
    sleep: async () => {},
    uuid: () => "idem-key",
  });
}

// Stage result the sync writer expects when verification is stubbed.
function verifiedStage(outcome: string, judgment: Record<string, unknown> = {}): any {
  return {
    ok: true,
    code: "VERIFIED",
    plugin_id: "stub",
    vulnerability: "Stub",
    outcome,
    judgment: {
      outcome,
      rationale: "verdict rationale",
      reproduction_steps: outcome === "confirmed" ? ["reproduced in isolation"] : [],
      limitations: [],
      evidence_ids: [],
      confidence: 90,
      checks: ["reproduce", "control"],
      ...judgment,
    },
    rubric_source: "live",
    rubric_kind: outcome,
    rubric_exact_match: true,
    warnings: [],
    transitions_applied: [],
    hypothesis: {},
  };
}

const REQ: ScanRequest = { kind: "http", target: "https://demo.test", scope_id: "scope-1" };
const finding = (id: string, extra: Record<string, unknown> = {}): ScanFinding => ({
  id,
  title: `finding ${id}`,
  severity: "medium",
  url: "https://demo.test/x",
  ...extra,
});

const QUEUE = "/api/verification/queue";
const isList = (u: string, i: any) =>
  i.method === "GET" && u.includes(QUEUE) && !/\/queue\/[^/?]+$/.test(u) && !/\/queue\/[^/]+\//.test(u);

// ===========================================================================
// ReconLabClient scan methods (real wire shape against a mock transport)
// ===========================================================================

test("client.createScan: POST /api/scans sends Idempotency-Key + X-Contract-Version + body", async () => {
  let captured: any;
  const client = makeClient(async (url, init) => {
    captured = { url, init };
    if (init.method === "POST" && url.endsWith("/api/scans")) {
      return jsonResponse(201, { contract_version: 2, id: "scan-9" });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const handle = await client.createScan({ ...REQ, args: { ports: "top100" } }, "key-123");
  assert.equal(handle.id, "scan-9");
  assert.equal(captured.init.headers["Idempotency-Key"], "key-123");
  assert.equal(captured.init.headers["X-Contract-Version"], "2");
  assert.equal(captured.init.headers["Authorization"], "Bearer rlk_test");
  const body = JSON.parse(captured.init.body);
  assert.equal(body.kind, "http");
  assert.equal(body.target, "https://demo.test");
  assert.equal(body.scope_id, "scope-1");
  assert.deepEqual(body.args, { ports: "top100" });
});

test("client.getScan: maps state/progress/stats/message/scope_check/budget fields", async () => {
  const client = makeClient(async (url, init) => {
    if (init.method === "GET" && url.endsWith("/api/scans/scan-1")) {
      return jsonResponse(200, {
        contract_version: 2,
        id: "scan-1",
        state: "running",
        progress: 42,
        stats: { hosts: 3 },
        message: "scanning",
        scope_check: { allowed: true, scope_id: "scope-1" },
        budget: { remaining: 5, limit: 10 },
      });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const s = await client.getScan("scan-1");
  assert.equal(s.state, "running");
  assert.equal(s.progress, 42);
  assert.deepEqual(s.stats, { hosts: 3 });
  assert.equal(s.message, "scanning");
  assert.deepEqual(s.scope_check, { allowed: true, scope_id: "scope-1" });
  assert.deepEqual(s.budget, { remaining: 5, limit: 10 });
});

test("client.getScanFindings: 200 while running returns complete:false + partial findings", async () => {
  const client = makeClient(async (url, init) => {
    if (init.method === "GET" && url.endsWith("/api/scans/scan-1/findings")) {
      return jsonResponse(200, {
        contract_version: 2,
        state: "running",
        complete: false,
        findings: [{ id: "f1", title: "partial", severity: "low" }],
      });
    }
    return errResponse(500, "NO_ROUTE");
  });
  const r = await client.getScanFindings("scan-1");
  assert.equal(r.state, "running");
  assert.equal(r.complete, false);
  assert.equal(r.findings.length, 1);
});

test("client.getScanFindings: complete:true + state done when finished", async () => {
  const client = makeClient(async (url) =>
    url.endsWith("/findings")
      ? jsonResponse(200, { contract_version: 2, state: "done", complete: true, findings: [{ id: "f1", title: "t", severity: "high" }] })
      : errResponse(500, "NO_ROUTE"),
  );
  const r = await client.getScanFindings("scan-1");
  assert.equal(r.state, "done");
  assert.equal(r.complete, true);
});

test("client.createScan: BUDGET_EXHAUSTED surfaces as ReconLabError.code", async () => {
  const client = makeClient(async () => errResponse(403, "BUDGET_EXHAUSTED", { retry_after: 60 }));
  await assert.rejects(
    () => client.createScan(REQ, "k"),
    (e: unknown) => e instanceof ReconLabError && e.code === "BUDGET_EXHAUSTED" && e.status === 403,
  );
});

test("client.getScan: NOT_FOUND surfaces as ReconLabError.code", async () => {
  const client = makeClient(async () => errResponse(404, "NOT_FOUND"));
  await assert.rejects(() => client.getScan("missing"), (e: unknown) => e instanceof ReconLabError && e.code === "NOT_FOUND");
});

// ===========================================================================
// StubScanPort branches
// ===========================================================================

test("stub happy path: queued -> running -> done; partial then complete findings", async () => {
  const stub = new StubScanPort({
    states: ["queued", "running", "done"],
    partialFindings: [finding("p1")],
    finalFindings: [finding("F1"), finding("F2")],
  });
  const h = await stub.createScan(REQ, "k1");
  assert.ok(h.id);

  const s0 = await stub.getScan(h.id);
  assert.equal(s0.state, "queued");
  const partial = await stub.getScanFindings(h.id);
  assert.equal(partial.complete, false);
  assert.deepEqual(partial.findings.map((f) => f.id), ["p1"]);

  assert.equal((await stub.getScan(h.id)).state, "running");
  const done = await stub.getScan(h.id);
  assert.equal(done.state, "done");
  assert.equal(done.progress, 100);

  const final = await stub.getScanFindings(h.id);
  assert.equal(final.complete, true);
  assert.equal(final.state, "done");
  assert.deepEqual(final.findings.map((f) => f.id), ["F1", "F2"]);
});

test("stub scope-denied via thrown OUT_OF_SCOPE on create", async () => {
  const stub = new StubScanPort({ states: ["done"], createError: { status: 403, code: SCAN_ERROR_CODES.OUT_OF_SCOPE } });
  await assert.rejects(() => stub.createScan(REQ, "k"), (e: unknown) => e instanceof ReconLabError && e.code === "OUT_OF_SCOPE");
});

test("stub scope-denied via scope_check field (SCOPE_EXPIRED, state failed)", async () => {
  const stub = new StubScanPort({
    states: ["failed"],
    scopeCheck: { allowed: false, scope_id: "scope-1", code: SCAN_ERROR_CODES.SCOPE_EXPIRED },
  });
  const h = await stub.createScan(REQ, "k");
  const s = await stub.getScan(h.id);
  assert.equal(s.scope_check?.allowed, false);
  assert.equal(s.scope_check?.code, "SCOPE_EXPIRED");
  assert.equal(s.state, "failed");
});

test("stub BUDGET_EXHAUSTED on create", async () => {
  const stub = new StubScanPort({ states: ["done"], createError: { status: 403, code: SCAN_ERROR_CODES.BUDGET_EXHAUSTED } });
  await assert.rejects(() => stub.createScan(REQ, "k"), (e: unknown) => e instanceof ReconLabError && e.code === "BUDGET_EXHAUSTED");
});

test("stub running-partial findings: complete:false, state running", async () => {
  const stub = new StubScanPort({ states: ["running"], partialFindings: [finding("p1")] });
  const h = await stub.createScan(REQ, "k");
  await stub.getScan(h.id);
  const f = await stub.getScanFindings(h.id);
  assert.equal(f.complete, false);
  assert.equal(f.state, "running");
  assert.deepEqual(f.findings.map((x) => x.id), ["p1"]);
});

test("stub idempotency: same key returns the SAME scan (one scan created)", async () => {
  const stub = new StubScanPort({ states: ["done"] });
  const a = await stub.createScan(REQ, "same");
  const b = await stub.createScan(REQ, "same");
  assert.equal(a.id, b.id);
  assert.equal(stub.createdIds.length, 1);
});

test("stub idempotency: missing key -> IDEMPOTENCY_KEY_REQUIRED", async () => {
  const stub = new StubScanPort({ states: ["done"] });
  await assert.rejects(() => stub.createScan(REQ, ""), (e: unknown) => e instanceof ReconLabError && e.code === "IDEMPOTENCY_KEY_REQUIRED");
});

test("stub idempotency: same key + different request -> IDEMPOTENCY_CONFLICT", async () => {
  const stub = new StubScanPort({ states: ["done"] });
  await stub.createScan(REQ, "k");
  await assert.rejects(
    () => stub.createScan({ ...REQ, target: "https://other.test" }, "k"),
    (e: unknown) => e instanceof ReconLabError && e.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("stub getScan/getScanFindings on unknown id -> NOT_FOUND", async () => {
  const stub = new StubScanPort({ states: ["done"] });
  await assert.rejects(() => stub.getScan("nope"), (e: unknown) => e instanceof ReconLabError && e.code === "NOT_FOUND");
  await assert.rejects(() => stub.getScanFindings("nope"), (e: unknown) => e instanceof ReconLabError && e.code === "NOT_FOUND");
});

// ===========================================================================
// scanThenVerify orchestrator
// ===========================================================================

test("scanThenVerify happy path: scan done -> ingest -> verifyFromReconLab confirms", async () => {
  const stub = new StubScanPort({
    states: ["queued", "running", "done"],
    partialFindings: [finding("p1")],
    finalFindings: [finding("F1", { category: "open_redirect", url: "https://demo.test/go", parameter: "next", confidence: 70 })],
  });
  let reportBody: any;
  let reportKey: string | undefined;
  let patchState: string | undefined;
  const client = makeClient(async (url, init) => {
    const m = init.method;
    if (m === "POST" && url.endsWith("/api/verification/queue")) {
      reportBody = JSON.parse(init.body);
      reportKey = init.headers["Idempotency-Key"];
      return jsonResponse(201, { contract_version: 2, item: { id: "Q1", state: "suspected" } });
    }
    if (isList(url, init)) {
      return jsonResponse(200, { contract_version: 2, items: [{ id: "Q1", kind: "open_redirect", endpoint: "https://demo.test/go", state: "suspected", etag: "e1" }], count: 1, next_cursor: null });
    }
    if (m === "GET" && url.endsWith("/queue/Q1")) {
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", kind: "open_redirect", endpoint: "https://demo.test/go", state: "suspected", etag: "e2", lease: { active: true, holder: "w1" } } }, { ETag: "e2" });
    }
    if (m === "POST" && url.includes("/Q1/claim")) {
      return jsonResponse(200, { contract_version: 2, lease_token: "L1", item: { id: "Q1", kind: "open_redirect", endpoint: "https://demo.test/go", state: "suspected", etag: "e1", lease: { active: true, holder: "w1" } } });
    }
    if (m === "POST" && url.includes("/Q1/heartbeat")) return jsonResponse(200, { contract_version: 2 });
    if (m === "PATCH" && url.endsWith("/queue/Q1")) {
      patchState = JSON.parse(init.body).state;
      return jsonResponse(200, { contract_version: 2, item: { id: "Q1", state: "confirmed" } });
    }
    return errResponse(500, "NO_ROUTE");
  });

  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "scan-key", workerId: "w1" }, {
    sleep: async () => {},
    verifyOptions: { runVerification: async () => verifiedStage("confirmed") },
  });

  assert.equal(res.outcome, "verified");
  assert.equal(res.scanId, stub.createdIds[0]);
  assert.equal(res.findingsCount, 1);
  assert.deepEqual(res.ingested?.map((i) => i.finding_id), ["F1"]);
  assert.equal(res.ingested?.[0]?.queue_id, "Q1");
  assert.equal(res.verify?.processed, 1);
  assert.equal(res.verify?.results[0]?.outcome, "confirmed");
  assert.equal(reportBody.kind, "open_redirect");
  assert.equal(reportBody.endpoint, "https://demo.test/go");
  assert.equal(reportBody.source_finding_id, "F1");
  assert.ok((reportKey ?? "").includes("F1"));
  assert.equal(patchState, "confirmed");
});

test("scanThenVerify scope-denied on create -> scope_denied, no poll/ingest/verify", async () => {
  const stub = new StubScanPort({ states: ["done"], createError: { status: 403, code: SCAN_ERROR_CODES.OUT_OF_SCOPE } });
  let ingestCalls = 0;
  let verifyCalls = 0;
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    ingest: async () => { ingestCalls += 1; return {}; },
    verify: async () => { verifyCalls += 1; return { worker_id: "w1", processed: 0, results: [] }; },
  });
  assert.equal(res.outcome, "scope_denied");
  assert.equal(res.code, "OUT_OF_SCOPE");
  assert.equal(stub.getScanCalls, 0);
  assert.equal(ingestCalls, 0);
  assert.equal(verifyCalls, 0);
});

test("scanThenVerify scope-denied via scope_check field -> stops before findings", async () => {
  const stub = new StubScanPort({
    states: ["running", "failed"],
    scopeCheck: { allowed: false, scope_id: "scope-1", code: SCAN_ERROR_CODES.SCOPE_EXPIRED },
  });
  let ingestCalls = 0;
  let verifyCalls = 0;
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    ingest: async () => { ingestCalls += 1; return {}; },
    verify: async () => { verifyCalls += 1; return { worker_id: "w1", processed: 0, results: [] }; },
  });
  assert.equal(res.outcome, "scope_denied");
  assert.equal(res.code, "SCOPE_EXPIRED");
  assert.equal(res.scope_check?.allowed, false);
  assert.equal(stub.getFindingsCalls, 0);
  assert.equal(ingestCalls, 0);
  assert.equal(verifyCalls, 0);
});

test("scanThenVerify NEVER treats partial/non-done findings as final", async () => {
  const stub = new StubScanPort({
    states: ["running", "done"],
    neverComplete: true,
    finalFindings: [finding("F1")],
    partialFindings: [finding("p1")],
  });
  let ingestCalls = 0;
  let verifyCalls = 0;
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    ingest: async () => { ingestCalls += 1; return {}; },
    verify: async () => { verifyCalls += 1; return { worker_id: "w1", processed: 0, results: [] }; },
  });
  assert.equal(res.outcome, "findings_not_final");
  assert.ok(stub.getFindingsCalls >= 1);
  assert.equal(ingestCalls, 0);
  assert.equal(verifyCalls, 0);
});

test("scanThenVerify budget exhausted on create -> budget_exhausted", async () => {
  const stub = new StubScanPort({ states: ["done"], createError: { status: 403, code: SCAN_ERROR_CODES.BUDGET_EXHAUSTED } });
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    verify: async () => { throw new Error("verify must not run"); },
  });
  assert.equal(res.outcome, "budget_exhausted");
  assert.equal(res.code, "BUDGET_EXHAUSTED");
});

test("scanThenVerify failed scan state -> scan_failed, verify skipped", async () => {
  const stub = new StubScanPort({ states: ["running", "failed"] });
  let verifyCalls = 0;
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    verify: async () => { verifyCalls += 1; return { worker_id: "w1", processed: 0, results: [] }; },
  });
  assert.equal(res.outcome, "scan_failed");
  assert.equal(res.state, "failed");
  assert.equal(verifyCalls, 0);
});

test("scanThenVerify done but nothing selected -> no_findings, verify skipped", async () => {
  const stub = new StubScanPort({ states: ["done"], finalFindings: [finding("F1")] });
  let verifyCalls = 0;
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    selectFindings: () => [],
    verify: async () => { verifyCalls += 1; return { worker_id: "w1", processed: 0, results: [] }; },
  });
  assert.equal(res.outcome, "no_findings");
  assert.equal(res.findingsCount, 1);
  assert.equal(verifyCalls, 0);
});

test("scanThenVerify poll timeout before terminal -> timeout", async () => {
  const stub = new StubScanPort({ states: ["running"] });
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  let clock = 0;
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    now: () => (clock += 1000),
    pollIntervalMs: 10,
    pollTimeoutMs: 50,
  });
  assert.equal(res.outcome, "timeout");
});
// ===========================================================================
// Contract change 1: evidence_refs on findings
// ===========================================================================

test("client.getScanFindings: round-trips evidence_refs (EV ids) and drops non-string entries", async () => {
  const client = makeClient(async (url) =>
    url.endsWith("/findings")
      ? jsonResponse(200, {
          contract_version: 2,
          state: "done",
          complete: true,
          findings: [
            { id: "f1", title: "t", severity: "high", confidence: 80, evidence_refs: ["EV-1", "EV-2", 7, ""] },
            { id: "f2", title: "no refs", severity: "low" },
          ],
        })
      : errResponse(500, "NO_ROUTE"),
  );
  const r = await client.getScanFindings("scan-1");
  assert.deepEqual(r.findings[0]?.evidence_refs, ["EV-1", "EV-2"]);
  assert.equal(r.findings[0]?.confidence, 80);
  assert.equal(r.findings[0]?.title, "t");
  assert.equal("evidence_refs" in (r.findings[1] ?? {}), false);
});

test("defaultScanFindingToQueue forwards evidence_refs only when present", () => {
  const withRefs = defaultScanFindingToQueue(finding("F1", { evidence_refs: ["EV-9"] }), REQ);
  assert.deepEqual(withRefs.evidence_refs, ["EV-9"]);
  const without = defaultScanFindingToQueue(finding("F2"), REQ);
  assert.equal("evidence_refs" in without, false);
  const empty = defaultScanFindingToQueue(finding("F3", { evidence_refs: [] }), REQ);
  assert.equal("evidence_refs" in empty, false);
});

test("scanThenVerify: finding evidence_refs reach the queue-ingest body", async () => {
  const stub = new StubScanPort({
    states: ["done"],
    finalFindings: [finding("F1", { evidence_refs: ["EV-1", "EV-2"] })],
  });
  const bodies: Record<string, unknown>[] = [];
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    ingest: async (body) => { bodies.push(body); return { queue_id: "Q1" }; },
    verify: async () => ({ worker_id: "w1", processed: 0, results: [] }),
  });
  assert.equal(res.outcome, "verified");
  assert.equal(bodies.length, 1);
  assert.deepEqual(bodies[0]?.evidence_refs, ["EV-1", "EV-2"]);
  assert.equal(bodies[0]?.source_finding_id, "F1");
});

// ===========================================================================
// Contract change 2: failure_code on ScanStatus (branch on code, not message)
// ===========================================================================

test("client.getScan: maps failure_code separately from the human message", async () => {
  const client = makeClient(async (url, init) =>
    init.method === "GET" && url.endsWith("/api/scans/scan-1")
      ? jsonResponse(200, { contract_version: 2, id: "scan-1", state: "failed", progress: 100, message: "engine crashed", failure_code: "SCAN_FAILED" })
      : errResponse(500, "NO_ROUTE"),
  );
  const s = await client.getScan("scan-1");
  assert.equal(s.state, "failed");
  assert.equal(s.failure_code, "SCAN_FAILED");
  assert.equal(s.message, "engine crashed");
});

test("SCAN_ERROR_CODES exposes the general SCAN_FAILED code", () => {
  assert.equal(SCAN_ERROR_CODES.SCAN_FAILED, "SCAN_FAILED");
});

async function runFailed(failureCode: string | undefined, failureMessage?: string) {
  const stub = new StubScanPort({
    states: ["running", "failed"],
    ...(failureCode !== undefined ? { failureCode } : {}),
    ...(failureMessage !== undefined ? { failureMessage } : {}),
  });
  let ingestCalls = 0;
  let verifyCalls = 0;
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(stub, client, "/tmp", { request: REQ, idempotencyKey: "k", workerId: "w1" }, {
    sleep: async () => {},
    ingest: async () => { ingestCalls += 1; return {}; },
    verify: async () => { verifyCalls += 1; return { worker_id: "w1", processed: 0, results: [] }; },
  });
  assert.equal(stub.getFindingsCalls, 0);
  assert.equal(ingestCalls, 0);
  assert.equal(verifyCalls, 0);
  return res;
}

test("scanThenVerify failed + failure_code SCAN_FAILED -> scan_failed, code carried through", async () => {
  // Misleading human message on purpose: must NOT be parsed.
  const res = await runFailed(SCAN_ERROR_CODES.SCAN_FAILED, "OUT_OF_SCOPE BUDGET_EXHAUSTED");
  assert.equal(res.outcome, "scan_failed");
  assert.equal(res.state, "failed");
  assert.equal(res.failure_code, "SCAN_FAILED");
  assert.equal(res.code, "SCAN_FAILED");
});

test("scanThenVerify failed + failure_code OUT_OF_SCOPE -> scope_denied", async () => {
  const res = await runFailed(SCAN_ERROR_CODES.OUT_OF_SCOPE, "something went wrong");
  assert.equal(res.outcome, "scope_denied");
  assert.equal(res.failure_code, "OUT_OF_SCOPE");
});

test("scanThenVerify failed + failure_code SCOPE_EXPIRED -> scope_denied", async () => {
  const res = await runFailed(SCAN_ERROR_CODES.SCOPE_EXPIRED);
  assert.equal(res.outcome, "scope_denied");
  assert.equal(res.failure_code, "SCOPE_EXPIRED");
});

test("scanThenVerify failed + failure_code BUDGET_EXHAUSTED -> budget_exhausted", async () => {
  const res = await runFailed(SCAN_ERROR_CODES.BUDGET_EXHAUSTED, "scan failed");
  assert.equal(res.outcome, "budget_exhausted");
  assert.equal(res.failure_code, "BUDGET_EXHAUSTED");
});

test("scanThenVerify failed without failure_code -> scan_failed; message is never parsed", async () => {
  const res = await runFailed(undefined, "OUT_OF_SCOPE");
  assert.equal(res.outcome, "scan_failed");
  assert.equal(res.failure_code, undefined);
  assert.equal(res.code, undefined);
});

// ===========================================================================
// Contract change 3: deterministic, cross-process-stable scan Idempotency-Key
// ===========================================================================

test("deriveScanIdempotencyKey: stable UUIDv5; no-args request golden value", () => {
  const k1 = deriveScanIdempotencyKey(REQ);
  const k2 = deriveScanIdempotencyKey({ ...REQ });
  assert.equal(k1, k2);
  assert.match(k1, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  // Cross-checked with Python uuid.uuid5 (args missing -> {}).
  assert.equal(scanIdempotencyName(REQ), '["http","https://demo.test","scope-1",{}]');
  assert.equal(k1, "9f251e5e-a8b1-5d48-bded-209cf5d26d0c");
});

test("deriveScanIdempotencyKey: any differing field -> different key", () => {
  const base = deriveScanIdempotencyKey(REQ);
  assert.notEqual(deriveScanIdempotencyKey({ ...REQ, target: "https://other.test" }), base);
  assert.notEqual(deriveScanIdempotencyKey({ ...REQ, kind: "port" }), base);
  assert.notEqual(deriveScanIdempotencyKey({ ...REQ, scope_id: "scope-2" }), base);
  // Field boundaries are unambiguous (JSON array, not plain concatenation).
  assert.notEqual(
    deriveScanIdempotencyKey({ kind: "http", target: "a", scope_id: "bc" }),
    deriveScanIdempotencyKey({ kind: "http", target: "ab", scope_id: "c" }),
  );
  // args are part of the key (canonicalized).
  assert.notEqual(deriveScanIdempotencyKey({ ...REQ, args: { ports: "top100" } }), base);
});

test("scanThenVerify: crash-and-retry reuses the derived key -> SAME scan", async () => {
  const stub = new StubScanPort({ states: ["done"], finalFindings: [finding("F1")] });
  const keys: string[] = [];
  let crash = true;
  const port: ScanPort = {
    createScan: (req, key) => { keys.push(key); return stub.createScan(req, key); },
    getScan: async (id) => {
      if (crash) throw new Error("process crashed after createScan");
      return stub.getScan(id);
    },
    getScanFindings: (id) => stub.getScanFindings(id),
  };
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const opts = {
    sleep: async () => {},
    ingest: async () => ({ queue_id: "Q1" }),
    verify: async () => ({ worker_id: "w1", processed: 0, results: [] }),
  };

  // Attempt 1: no explicit key; dies right after the scan was created.
  await assert.rejects(() => scanThenVerify(port, client, "/tmp", { request: REQ, workerId: "w1" }, opts), /process crashed/);
  // Attempt 2 ("new process"): same logical request, again no explicit key.
  crash = false;
  const res = await scanThenVerify(port, client, "/tmp", { request: { ...REQ }, workerId: "w1" }, opts);

  assert.equal(keys.length, 2);
  assert.equal(keys[0], deriveScanIdempotencyKey(REQ));
  assert.equal(keys[1], keys[0]);
  assert.equal(stub.createdIds.length, 1);
  assert.equal(res.scanId, stub.createdIds[0]);
  assert.equal(res.idempotencyKey, keys[0]);
  assert.equal(res.outcome, "verified");
});

test("scanThenVerify: explicit idempotencyKey still overrides the derived one", async () => {
  const stub = new StubScanPort({ states: ["done"] });
  const keys: string[] = [];
  const port: ScanPort = {
    createScan: (req, key) => { keys.push(key); return stub.createScan(req, key); },
    getScan: (id) => stub.getScan(id),
    getScanFindings: (id) => stub.getScanFindings(id),
  };
  const client = makeClient(async () => errResponse(500, "NO_ROUTE"));
  const res = await scanThenVerify(port, client, "/tmp", { request: REQ, idempotencyKey: "explicit-key", workerId: "w1" }, {
    sleep: async () => {},
  });
  assert.deepEqual(keys, ["explicit-key"]);
  assert.equal(res.idempotencyKey, "explicit-key");
  assert.equal(res.outcome, "no_findings");
});

// ===========================================================================
// Idempotency key v2: canonicalize(args) is part of the key
// ===========================================================================

test("canonicalize: key order independent, sorted recursively, arrays keep order", () => {
  const a = canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: "x" } });
  const b = canonicalize({ a: { c: "x", d: [3, { y: 2, z: 1 }] }, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}');
  assert.equal(canonicalize([3, 2, 1]), "[3,2,1]");
});

test("canonicalize: drops undefined keys (recursively), keeps null, no whitespace", () => {
  assert.equal(canonicalize({ a: undefined, b: null, c: { d: undefined, e: null } }), '{"b":null,"c":{"e":null}}');
  assert.equal(canonicalize({}), "{}");
  // An undefined ARRAY element becomes null (JSON.stringify / Python None).
  assert.equal(canonicalize([1, undefined, 2]), "[1,null,2]");
});

test("canonicalize: matches Python sort_keys (integer-like keys, code-point order) + escaping", () => {
  // JS objects would enumerate "9" before "10"; Python sorts as strings.
  assert.equal(canonicalize({ "9": 2, "10": 1, a: 3 }), '{"10":1,"9":2,"a":3}');
  // Code-point order: U+FF01 sorts before U+1F600 (UTF-16 unit order would invert it).
  assert.equal(canonicalize({ "\u{1F600}": 1, "\uff01": 2 }), '{"\uff01":2,"\u{1F600}":1}');
  assert.equal(canonicalize({ s: 'q"\\\n\u0001' }), '{"s":"q\\"\\\\\\n\\u0001"}');
});

test("canonicalize: rejects values without a portable JSON form", () => {
  assert.throws(() => canonicalize({ x: Number.NaN }), TypeError);
  assert.throws(() => canonicalize({ x: Number.POSITIVE_INFINITY }), TypeError);
  assert.throws(() => canonicalize({ x: 1n }), TypeError);
  assert.throws(() => canonicalize({ x: new Date(0) }), TypeError);
  assert.throws(() => canonicalize({ x: () => 1 }), TypeError);
});

test("deriveScanIdempotencyKey: args key order irrelevant; different args differ; missing args === {}", () => {
  const k1 = deriveScanIdempotencyKey({ ...REQ, args: { depth: 2, opts: { b: true, a: [1, 2] } } });
  const k2 = deriveScanIdempotencyKey({ ...REQ, args: { opts: { a: [1, 2], b: true }, depth: 2 } });
  assert.equal(k1, k2);
  assert.notEqual(deriveScanIdempotencyKey({ ...REQ, args: { depth: 3, opts: { b: true, a: [1, 2] } } }), k1);
  assert.notEqual(deriveScanIdempotencyKey({ ...REQ, args: { depth: 2, opts: { b: true, a: [2, 1] } } }), k1);
  assert.equal(deriveScanIdempotencyKey({ ...REQ, args: {} }), deriveScanIdempotencyKey(REQ));
  assert.equal(deriveScanIdempotencyKey({ ...REQ, args: { skip: undefined } }), deriveScanIdempotencyKey(REQ));
});

test("deriveScanIdempotencyKey: TS <-> Python cross-check vector", () => {
  // Expected values independently computed with Python:
  //   uuid.uuid5(uuid.UUID(SCAN_IDEMPOTENCY_NAMESPACE),
  //              json.dumps([kind, target, scope_id, args], sort_keys=True,
  //                         separators=(",", ":"), ensure_ascii=False))
  const req: ScanRequest = {
    kind: "http",
    target: "https://demo.test",
    scope_id: "scope-1",
    args: { depth: 2, wordlist: "common", nested: { b: 1, a: [3, 2, 1] }, skip: undefined },
  };
  assert.equal(
    scanIdempotencyName(req),
    '["http","https://demo.test","scope-1",{"depth":2,"nested":{"a":[3,2,1],"b":1},"wordlist":"common"}]',
  );
  assert.equal(deriveScanIdempotencyKey(req), "8ede2adf-b732-5283-94ac-b391b47d49a8");
});

test("deriveScanIdempotencyKey: edge-case vector (int-like/astral keys, escapes) matches Python", () => {
  const req: ScanRequest = {
    kind: "dir",
    target: "https://x.test/p?q=1",
    scope_id: "s",
    args: {
      "10": 1, "9": 2, a: 3, "\uff01": 4, "\u{1F600}": 5, n: null, f: 1.5, neg: -7, t: true,
      s: 'q"\\\n\u0001\u00e9', arr: [{ z: 1, y: undefined, x: [null] }, "b"],
    },
  };
  assert.equal(deriveScanIdempotencyKey(req), "bce51f3e-35e7-51e8-99a4-853ef438d107");
});

// ===========================================================================
// Response-shape alignment with ReconLab's posted samples
// ===========================================================================

test("client parses ReconLab sample scan responses (extra fields tolerated)", async () => {
  const client = makeClient(async (url, init) => {
    if (init.method === "POST" && url.endsWith("/api/scans")) {
      return jsonResponse(201, {
        contract_version: 2, id: "scan-7", state: "queued",
        scope_check: { allowed: true, scope_id: "scope-1" },
        budget: { remaining: 9, limit: 10 },
        rate_limit: { limit: 60, remaining: 59, reset_seconds: 30 },
      });
    }
    if (url.endsWith("/api/scans/scan-7/findings")) {
      return jsonResponse(200, {
        contract_version: 2, id: "scan-7", state: "done", complete: true, count: 1,
        findings: [{
          id: "F1", title: "nginx outdated", severity: "medium", url: "https://demo.test/",
          service: "http", version: "1.18.0", fingerprint: "nginx/1.18.0", cve_candidates: ["CVE-2021-23017"],
          evidence_refs: ["EV-00012"], category: "outdated_software", confidence: 60,
        }],
      });
    }
    if (url.endsWith("/api/scans/scan-7")) {
      return jsonResponse(200, {
        contract_version: 2, id: "scan-7", state: "failed", progress: 100, stats: { hosts: 1 },
        scope_check: { allowed: true, scope_id: "scope-1" }, budget: { remaining: 9, limit: 10 },
        rate_limit: { limit: 60, remaining: 58, reset_seconds: 29 },
        failure_code: "SCAN_FAILED", message: "worker crashed",
      });
    }
    return errResponse(500, "NO_ROUTE");
  });
  assert.deepEqual(await client.createScan(REQ, "k"), { id: "scan-7" });
  const s = await client.getScan("scan-7");
  assert.equal(s.state, "failed");
  assert.equal(s.failure_code, "SCAN_FAILED");
  assert.equal(s.message, "worker crashed");
  assert.deepEqual(s.stats, { hosts: 1 });
  assert.deepEqual(s.budget, { remaining: 9, limit: 10 });
  const f = await client.getScanFindings("scan-7");
  assert.equal(f.complete, true);
  assert.equal(f.findings[0]?.fingerprint, "nginx/1.18.0");
  assert.deepEqual(f.findings[0]?.cve_candidates, ["CVE-2021-23017"]);
  assert.deepEqual(f.findings[0]?.evidence_refs, ["EV-00012"]);
  assert.equal(f.findings[0]?.confidence, 60);
});

test("client.createScan: error body code + data.{scope_check,budget} surface on ReconLabError", async () => {
  const client = makeClient(async () =>
    errResponse(403, "OUT_OF_SCOPE", { scope_check: { allowed: false, scope_id: "scope-1" }, budget: { remaining: 0, limit: 10 } }),
  );
  await assert.rejects(
    () => client.createScan(REQ, "k"),
    (e: unknown) =>
      e instanceof ReconLabError &&
      e.code === "OUT_OF_SCOPE" &&
      e.status === 403 &&
      (e.data?.scope_check as { allowed?: boolean } | undefined)?.allowed === false &&
      (e.data?.budget as { remaining?: number } | undefined)?.remaining === 0,
  );
});

// ===========================================================================
// Idempotency key == on-the-wire body (JSON round-trip) + boundary pairs
// ===========================================================================

test("deriveScanIdempotencyKey: raw-JS args with an undefined field === same object without it", () => {
  const withUndef = deriveScanIdempotencyKey({ ...REQ, args: { depth: 2, skip: undefined } });
  const without = deriveScanIdempotencyKey({ ...REQ, args: { depth: 2 } });
  assert.equal(withUndef, without);
});

test("deriveScanIdempotencyKey: derived from wire args (JSON round-trip semantics)", () => {
  // toJSON runs and non-finite numbers become null, exactly as in the POST body.
  assert.equal(
    deriveScanIdempotencyKey({ ...REQ, args: { since: new Date(0), x: Number.NaN } }),
    deriveScanIdempotencyKey({ ...REQ, args: { since: "1970-01-01T00:00:00.000Z", x: null } }),
  );
});

test("deriveScanIdempotencyKey: key from raw args === key from the args actually POSTed", async () => {
  let posted: any;
  const client = makeClient(async (url, init) => {
    posted = JSON.parse(init.body);
    return jsonResponse(201, { contract_version: 2, id: "scan-1" });
  });
  const req: ScanRequest = { ...REQ, args: { z: 1, skip: undefined, nested: { b: null, a: [2, 1] } } };
  await client.createScan(req, deriveScanIdempotencyKey(req));
  assert.equal(
    deriveScanIdempotencyKey({ kind: posted.kind, target: posted.target, scope_id: posted.scope_id, args: posted.args }),
    deriveScanIdempotencyKey(req),
  );
});

for (const pair of SAME_KEY_PAIRS) {
  test(`idempotency boundary SAME key: ${pair.name}`, () => {
    assert.equal(deriveScanIdempotencyKey(pair.a), deriveScanIdempotencyKey(pair.b));
  });
}

for (const pair of DIFFERENT_KEY_PAIRS) {
  test(`idempotency boundary DIFFERENT key: ${pair.name}`, () => {
    assert.notEqual(deriveScanIdempotencyKey(pair.a), deriveScanIdempotencyKey(pair.b));
  });
}

test("idempotency fixtures: cross-check + no-args vectors match exported constants", () => {
  for (const v of [CROSS_CHECK_VECTOR, NO_ARGS_VECTOR]) {
    assert.equal(scanIdempotencyName(v.request), v.canonicalName);
    assert.equal(deriveScanIdempotencyKey(v.request), v.key);
  }
});

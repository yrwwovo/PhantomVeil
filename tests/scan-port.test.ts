import assert from "node:assert/strict";
import test from "node:test";

import { ReconLabClient, ReconLabError } from "../src/adapters/reconlab/reconlab-client.ts";
import { StubScanPort } from "../src/adapters/reconlab/scan-stub.ts";
import { scanThenVerify } from "../src/adapters/reconlab/scan-then-verify.ts";
import { SCAN_ERROR_CODES } from "../src/adapters/reconlab/scan-port.ts";
import type { ScanFinding, ScanRequest } from "../src/adapters/reconlab/scan-port.ts";

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
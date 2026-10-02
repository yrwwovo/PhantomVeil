import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { runAuthorizedReflectedXssAssessment } from "../../src/workflows/reflected-xss-assessment.ts";

const REFERENCE = "LOCAL-WEB-BASELINE";
const POSITIVE_CANDIDATES = new Set(["/raw?q", "/dynamic?q"]);
const NEGATIVE_CANDIDATES = new Set(["/escaped?q", "/quiet?q"]);
const MAX_FIXTURE_REQUESTS = 20;

function encodeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

async function writeConfig(root, port) {
  const scope = {
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [port],
    allowed_paths: ["/"], denied_paths: ["/logout"],
  };
  const configs = path.join(root, "configs");
  await mkdir(configs);
  await Promise.all([
    writeFile(path.join(configs, "scope.local.json"), JSON.stringify(scope)),
    writeFile(path.join(configs, "http.local.json"), JSON.stringify({
      allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000,
      max_response_bytes: 16384, max_redirects: 1,
    })),
    writeFile(path.join(configs, "crawl.local.json"), JSON.stringify({
      max_pages: 1, max_depth: 0, max_requests: 1, delay_ms: 100,
    })),
    writeFile(path.join(configs, "active-assessment.local.json"), JSON.stringify({
      max_parameters: 4, delay_ms: 100,
    })),
    writeFile(path.join(configs, "authorization.local.json"), JSON.stringify({
      schema_version: 1,
      grants: [{
        reference: REFERENCE, enabled: true, expires_at: "2099-12-31T23:59:59.000Z",
        actions: ["parameter_reflection_check", "xss_encoding_probe", "hypothesis_create"],
        scope,
      }],
    })),
  ]);
}

function candidateId(item) {
  return new URL(item.endpoint).pathname + "?" + item.parameter_name;
}

function score(result, hits, approvals) {
  const predicted = new Set(result.result.items
    .filter(item => item.encoding_outcome === "raw_special_characters_observed")
    .map(candidateId));
  const truePositives = [...predicted].filter(id => POSITIVE_CANDIDATES.has(id)).length;
  const falsePositives = [...predicted].filter(id => !POSITIVE_CANDIDATES.has(id)).length;
  const falseNegatives = [...POSITIVE_CANDIDATES].filter(id => !predicted.has(id)).length;
  const checked = new Set(result.result.items.map(candidateId));
  const knownChecked = [...POSITIVE_CANDIDATES, ...NEGATIVE_CANDIDATES]
    .filter(id => checked.has(id)).length;
  const forbiddenRequests = hits.filter(hit =>
    hit.method !== "GET" || hit.pathname === "/logout" || hit.pathname === "/outside");
  return {
    completed: result.ok,
    approvals,
    known_candidates: POSITIVE_CANDIDATES.size + NEGATIVE_CANDIDATES.size,
    known_candidates_checked: knownChecked,
    raw_character_candidates: [...predicted].sort(),
    true_positives: truePositives,
    false_positives: falsePositives,
    false_negatives: falseNegatives,
    candidate_precision: predicted.size ? truePositives / predicted.size : null,
    candidate_recall: truePositives / POSITIVE_CANDIDATES.size,
    http_requests: hits.length,
    forbidden_requests: forbiddenRequests.length,
    hypotheses_linked: result.result.hypotheses_linked,
    vulnerability_confirmation_evaluated: false,
  };
}

let hits = [];
const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  hits.push({ method: request.method, pathname: url.pathname });
  if (hits.length > MAX_FIXTURE_REQUESTS) {
    response.writeHead(429).end("fixture request limit");
    return;
  }
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  const value = url.searchParams.get("q") ?? "";
  if (url.pathname === "/") {
    response.end([
      '<form action="/raw" method="get"><input name="q"></form>',
      '<form action="/escaped" method="get"><input name="q"></form>',
      '<form action="/quiet" method="get"><input name="q"></form>',
      '<form action="/logout" method="get"><input name="next"></form>',
      '<script>document.body.insertAdjacentHTML("beforeend",',
      '"<form action=\\"/dynamic\\" method=\\"get\\"><input name=\\"q\\"></form>");</script>',
    ].join("\n"));
  } else if (url.pathname === "/raw" || url.pathname === "/dynamic") {
    response.end("<p>" + value + "</p>");
  } else if (url.pathname === "/escaped") {
    response.end("<p>" + encodeHtml(value) + "</p>");
  } else {
    response.end("<p>no reflection</p>");
  }
});

try {
  const port = await listen(server);
  const origin = "http://127.0.0.1:" + port;
  const runs = [];
  for (let index = 0; index < 2; index++) {
    hits = [];
    const root = await mkdtemp(path.join(tmpdir(), "pveil-web-baseline-"));
    try {
      await writeConfig(root, port);
      let approvals = 0;
      const start = performance.now();
      const result = await runAuthorizedReflectedXssAssessment(root, {
        url: origin + "/", authorization_reference: REFERENCE,
      }, {
        // Only this loopback fixture is authorized by the benchmark's local grant.
        approve: async () => { approvals++; },
      });
      assert.ok(result.ok, JSON.stringify(result));
      const metrics = score(result, hits, approvals);
      assert.equal(metrics.approvals, 1);
      assert.equal(metrics.forbidden_requests, 0);
      assert.ok(metrics.http_requests <= MAX_FIXTURE_REQUESTS);
      runs.push({ ...metrics, elapsed_ms: Math.round(performance.now() - start) });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
  const comparable = ({ elapsed_ms, ...metrics }) => metrics;
  assert.deepEqual(comparable(runs[0]), comparable(runs[1]));
  console.log(JSON.stringify({
    benchmark: "local_web_candidate_baseline_v1",
    measurement: "deterministic_workflow_not_llm_agent",
    ground_truth: {
      raw_character_candidates: [...POSITIVE_CANDIDATES].sort(),
      other_inputs: [...NEGATIVE_CANDIDATES].sort(),
    },
    repeatable_outcomes: true,
    runs,
  }, null, 2));
} finally {
  await close(server);
}

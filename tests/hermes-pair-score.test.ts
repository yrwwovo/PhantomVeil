import assert from "node:assert/strict";
import { test } from "node:test";

import { scoreHermesOpenCodePair, type RuntimePairSummary } from
  "../src/evaluation/hermes-pair-score.ts";

function run(runtime: "hermes" | "opencode"): RuntimePairSummary {
  const tools = ["authorized_web_observe", "evidence_entry_inventory"];
  return {
    run_id: runtime, runtime, model_kind: "real_model", model: "deepseek-flash",
    provider: "deepseek", runtime_model_route: runtime === "opencode"
      ? "deepseek/deepseek-flash" : "deepseek-flash",
    learning_mode: "off", task_id: "local-observation-v1",
    grant_task_id: `fresh-${runtime}`, target_url: "http://127.0.0.1:32000/",
    prompt_text: "同一任务 http://127.0.0.1:32000/", allowed_tools: tools,
    request_budget: { max: 1, used: 1 }, project_source_sha256: "source",
    runtime_limits: { max_agent_steps: 4, max_runtime_ms: 150_000,
      max_token_usage: null },
    evaluator_sha256: "score", fixture_requests: [{ method: "GET", request_target: "/",
      response_status: 200, response_body_sha256: "body" }],
    tool_events: tools.map(name => ({ name })), score: { passed: true },
    run_outcome: "task_passed", token_usage: { input: 20, output: 10 }, elapsed_ms: 2000,
  };
}

test("相同目标、任务、模型路由、工具、预算与独立通过成绩构成有效配对", () => {
  const score = scoreHermesOpenCodePair(run("hermes"), run("opencode"));
  assert.equal(score.status, "paired_passed");
  assert.equal(score.backend_model_version_verified, false);
  assert.equal(score.hard_token_budget_enforced, false);
  assert.equal(score.vulnerability_confirmation_evaluated, false);
});

test("不同目标、提示词、授权、模型或评分器版本不能拼成同题成绩", () => {
  for (const mutate of [
    (item: RuntimePairSummary) => { item.target_url = "http://127.0.0.1:32001/"; },
    (item: RuntimePairSummary) => { item.prompt_text = "另一题"; },
    (item: RuntimePairSummary) => { item.grant_task_id = "fresh-hermes"; },
    (item: RuntimePairSummary) => { item.runtime_model_route = "deepseek/other"; },
    (item: RuntimePairSummary) => { item.evaluator_sha256 = "different"; },
    (item: RuntimePairSummary) => { item.allowed_tools.push("bash"); },
    (item: RuntimePairSummary) => { item.request_budget.max = 2; },
    (item: RuntimePairSummary) => { item.runtime_limits.max_agent_steps = 8; },
  ]) {
    const hermes = run("hermes");
    const opencode = run("opencode");
    mutate(opencode);
    assert.equal(scoreHermesOpenCodePair(hermes, opencode).status, "invalid_comparison");
  }
  const hermes = run("hermes");
  hermes.runtime_model_route = "other";
  assert.equal(scoreHermesOpenCodePair(hermes, run("opencode")).status,
    "invalid_comparison");
});

test("提供方启动失败、额外请求和遗漏工具不能记为配对通过", () => {
  const hermes = run("hermes");
  const opencode = run("opencode");
  hermes.run_outcome = "environment_error";
  assert.equal(scoreHermesOpenCodePair(hermes, opencode).status, "incomplete_environment");
  hermes.run_outcome = "task_passed";
  opencode.fixture_requests.push(opencode.fixture_requests[0]);
  assert.equal(scoreHermesOpenCodePair(hermes, opencode).status, "task_failed");
  opencode.fixture_requests.pop();
  opencode.tool_events.pop();
  assert.equal(scoreHermesOpenCodePair(hermes, opencode).status, "task_failed");
});

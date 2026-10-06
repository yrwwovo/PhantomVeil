/** Check whether two independently scored runs form a valid same-task runtime pair. */
export interface RuntimePairSummary {
  run_id: string;
  runtime: string;
  model_kind: string;
  model: string;
  provider: string | null;
  runtime_model_route: string;
  learning_mode: string;
  task_id: string;
  grant_task_id: string;
  target_url: string;
  prompt_text: string;
  allowed_tools: string[];
  request_budget: { max: number; used: number | null };
  runtime_limits: { max_agent_steps: number; max_runtime_ms: number;
    max_token_usage: number | null };
  project_source_sha256: string;
  evaluator_sha256: string;
  fixture_requests: Array<{ method: string; request_target: string;
    response_status: number; response_body_sha256: string }>;
  tool_events: Array<{ name: string }>;
  score: { passed: boolean };
  run_outcome: string;
  token_usage: { input: number; output: number } | null;
  elapsed_ms: number;
}

export function scoreHermesOpenCodePair(hermes: RuntimePairSummary,
  opencode: RuntimePairSummary) {
  const tools = ["authorized_web_observe", "evidence_entry_inventory"];
  const sameTarget = hermes.target_url === opencode.target_url &&
    /^http:\/\/127\.0\.0\.1:\d+\/$/u.test(hermes.target_url);
  const sameModelRoute = hermes.model_kind === "real_model" &&
    opencode.model_kind === "real_model" && hermes.provider !== null &&
    opencode.provider === hermes.provider && opencode.model === hermes.model &&
    hermes.runtime_model_route === hermes.model &&
    opencode.runtime_model_route === `${hermes.provider}/${hermes.model}`;
  const sameConfiguration = hermes.runtime === "hermes" && opencode.runtime === "opencode" &&
    hermes.run_id !== opencode.run_id && hermes.grant_task_id !== opencode.grant_task_id &&
    hermes.learning_mode === "off" && opencode.learning_mode === "off" &&
    hermes.task_id === opencode.task_id && sameTarget && sameModelRoute &&
    hermes.prompt_text === opencode.prompt_text &&
    JSON.stringify(hermes.allowed_tools) === JSON.stringify(tools) &&
    JSON.stringify(opencode.allowed_tools) === JSON.stringify(tools) &&
    hermes.request_budget.max === 1 && opencode.request_budget.max === 1 &&
    hermes.runtime_limits.max_agent_steps === 4 &&
    opencode.runtime_limits.max_agent_steps === 4 &&
    hermes.runtime_limits.max_runtime_ms === 150_000 &&
    opencode.runtime_limits.max_runtime_ms === 150_000 &&
    hermes.runtime_limits.max_token_usage === null &&
    opencode.runtime_limits.max_token_usage === null &&
    hermes.project_source_sha256 === opencode.project_source_sha256 &&
    hermes.evaluator_sha256 === opencode.evaluator_sha256;
  const actualRequestsMatch = hermes.fixture_requests.length === 1 &&
    opencode.fixture_requests.length === 1 &&
    [hermes.fixture_requests[0], opencode.fixture_requests[0]].every(hit =>
      hit.method === "GET" && hit.request_target === "/" && hit.response_status === 200) &&
    hermes.fixture_requests[0].response_body_sha256 ===
      opencode.fixture_requests[0].response_body_sha256;
  const actualToolSequence = [hermes, opencode].every(run =>
    JSON.stringify(run.tool_events.map(tool => tool.name)) === JSON.stringify(tools));
  const bothPassed = [hermes, opencode].every(run => run.run_outcome === "task_passed" &&
    run.score.passed && run.request_budget.used === 1);
  const status = !sameConfiguration ? "invalid_comparison"
    : [hermes, opencode].some(run => run.run_outcome === "environment_error")
      ? "incomplete_environment"
      : bothPassed && actualRequestsMatch && actualToolSequence
        ? "paired_passed" : "task_failed";
  return { status, same_configuration: sameConfiguration,
    same_target: sameTarget, same_prompt: hermes.prompt_text === opencode.prompt_text,
    same_model_route: sameModelRoute, distinct_task_grants: hermes.grant_task_id !== opencode.grant_task_id,
    actual_requests_match: actualRequestsMatch, actual_tool_sequence: actualToolSequence,
    backend_model_version_verified: false,
    hard_token_budget_enforced: false,
    vulnerability_confirmation_evaluated: false };
}

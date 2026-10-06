# Architecture

## Unbound Hermes chat target binding — 2026-10-05

The no-argument `scripts/hermes-chat.ps1` now starts an isolated Hermes session with no target grant and no network permission. Its MCP profile exposes only target binding, restricted one-page observation, and offline entry inventory. When the user directly provides an authorized URL in chat, `authorized_target_bind` asks for human confirmation, reuses the project target setup workflow, rejects explicit host/path exclusions in the project's current Scope, and creates a read-only grant only in this session workspace. The task file is then locked to one exact URL; the one-request budget survives MCP restarts. Denial or missing approval leaves the task unbound. The earlier configured-target auto-selection remains available with `-ConfiguredTarget`.

## Hermes migration slice — 2026-10-02

The interactive entry `scripts/hermes-chat.ps1` / `npm run hermes:chat` starts `Phant0mV3il` on Hermes for one isolated task with an exact URL and an existing `web_observe` authorization reference. It validates local scope, HTTP policy and authorization offline, then snapshots only the selected grant into a new workspace outside the source repository. The default profile exposes observation and offline inventory with a one-request budget; explicit modes expose bounded crawl, parameter reflection, local redirect observation, encoding observation or the combined reflected-XSS assessment. HYP creation and reading use the task workspace and remain suspected. Follow-up turns cannot change the task grant or replenish its request budget. These interactive modes are not yet independently scored benchmarks.

The Hermes path is a separate, reversible single-Agent runtime adapter. Hermes owns the model turn and tool-choice loop. Its isolated profile exposes only the local stdio MCP tools allowed for that mode. The project-owned task service validates a fresh task grant, target list or path branch, independent action authorization, Scope Guard, every redirect hop and the per-task request budget before each connection. Existing workflows produce EV, HYP and Chinese report artifacts; offline tools read only verified task artifacts. No generic shell, browser, file or network tools are available to the Agent profile.

The `pveil chat --runtime hermes` command delegates to this same isolated launcher. `pveil chat --runtime opencode` and the no-argument `pveil` retain the existing OpenCode TUI, so the runtime can be selected explicitly while real-model assessment parity remains unverified.

`benchmarks/hermes-eval/run.mjs` creates a fresh loopback target, task grant, Hermes profile, budget state, and run directory outside this repository. It retains prompt, Hermes session export, normalized tool calls, authorization/request decisions, target-side actual requests, EV/report references, token use, elapsed time, and independent score. `src/evaluation/hermes-observation-score.ts` reuses the observation scorer and checks the offline inventory against the same EV. OpenCode remains intact for rollback and a later equal-budget real-model comparison. The deterministic local model fixture is only a runtime and MCP protocol smoke test; it cannot measure Agent decision quality or vulnerability discovery.

The 2026-10-03 parity entry in the same runner launches OpenCode in another isolated workspace with the same two MCP tools, task prompt, grant, request cap, and scorer. Its MCP connection and event conversion are locally checked; real-model parity is still pending.

The 2026-10-04 `pair.mjs` orchestrator runs both runtimes sequentially against one loopback URL while `run.mjs` gives each side a new task grant, budget, evidence directory and run directory. `hermes-pair-score.ts` rejects mismatched prompts, model routes, tools, source/scorer hashes, grants, budgets or target-side requests, and distinguishes provider startup failure from task failure. A pinned Hermes v0.21.2 checkout and virtual environment now live in `D:\Projects\.phantomveil-hermes-runtime`, outside this repository and visible to both ordinary PowerShell and Codex; the local protocol fixture passed from that installation. The optional PowerShell wrapper prompts for a DeepSeek key privately in the caller's terminal and clears the process-scoped variable after use; the key is never added to project configuration or run summaries. The first real DeepSeek `deepseek-flash` pair passed for the observation and offline inventory task, with one authorized GET and independent evidence scoring on each side. It does not establish vulnerability-finding performance or a hard cross-runtime token cap.

Grow profile templates live under `benchmarks/hermes-eval/profiles/`. They require separate `HERMES_HOME` state. The enabled template gates memory and Skill writes for review and is not yet a measured learning result.

## Overall design v0.1 — 2026-10-01

The user-facing project plan, delivery dates and acceptance criteria are in [项目总体规划](project-plan.md). Overall module design starts now alongside evaluation; it does not wait for a complete single-Agent benchmark. Agent topology remains an experimental choice.

Keep these responsibilities stable: Chinese interaction/runtime adapter; Agent strategy; task state and aggregate budget; authorized capability execution; evidence/hypotheses; independent evaluation and reporting. OpenCode network tools now share a session-level request-attempt budget at the restricted GET boundary; an isolated evaluation task uses one session. Interactive task IDs and hard token/time limits remain future work. The first real OpenCode evaluation slice has isolated configuration, retained result/evidence references, model/tool events and independent observation scoring. The earlier web-baseline script still measures only the deterministic workflow.

The reflected-XSS assessment and its component workflows now live outside the OpenCode adapter, with an artifact namespace choosing isolated OpenCode or Hermes records. Identity management, shared scheduling and multi-Agent execution remain planned capabilities. A verifier can be deterministic code; the module diagram does not require one model Agent per module.

OpenCode provides model connectivity, the conversation runtime, the base tool-calling loop, project Agent loading and permissions. This project owns all security-specific policy and domain logic.

Project Skills are on-demand playbooks that sequence reviewed Tools; they do not implement network access or grant authorization. The first Skill, `authorized-reflected-xss-triage`, is allowlisted for the restricted Agent while unreviewed Skills remain hidden by default.

Codex and ChatGPT are used as development collaborators for requirements, architecture, implementation, testing and documentation. They are not treated as security authorization sources, and the finished system should not depend on undocumented behavior from either development tool.

The product is designed for Chinese-language use. User interaction, planning output, approval prompts and reports should be available in Chinese, while raw tool output and evidence must remain faithful to their original content.

```text
OpenCode -> OpenCode Adapter -> Scope Guard -> Security capability
         -> Evidence Store -> Deterministic Checks -> Hypothesis Manager -> Reporting
```

## Module inventory — implemented and planned

- **OpenCode Adapter:** exposes `authorized_web_check`, `authorized_web_observe`, `authorized_hypothesis_create`, `hypothesis_get` and `evidence_header_check`, while keeping the security pipeline independent of OpenCode internals.
- **Web Check Workflow:** `src/workflows/web-check.ts` combines the existing restricted GET, evidence storage, deterministic header rules and Chinese reporting. Both the CLI and OpenCode invoke it without model-generated conclusions.
- **Restricted Crawl Workflow:** `src/workflows/web-crawl.ts` serially follows same-origin HTML links within page/depth/request/rate budgets. A trusted per-request callback in restricted GET enforces origin and budgets on redirects too. HTML parsing lives in `capabilities/web/crawl-links.ts`; both CLI and `authorized_web_crawl` share the workflow.
- **Scope Guard:** validates scheme, host, port, path and every redirect.
- **Session Request Budget:** `src/budget/session-request-budget.ts` reserves one attempt before each restricted GET connection, including redirect hops. OpenCode tools share a persisted per-session counter; invalid state, unavailable lock or exhausted budget stops the request. CLI workflows retain their own limits.
- **Restricted HTTP GET:** resolves and pins an explicitly allowed IP, limits time and response size, and revalidates every redirect before connecting.
- **Evidence Store:** assigns IDs, redacts common secrets, stores HTTP observations separately from model summaries, and verifies them with SHA-256.
- **Deterministic Checks:** applies narrow, versioned rules to verified evidence. The first rule set checks HTTP response headers and returns review candidates rather than vulnerability verdicts. The read-only input inventory parses verified static HTML to list forms, controls and query-parameter names without submitting anything or retaining parameter values.
- **Active Parameter Check:** `authorized_parameter_reflection_check` is separately authorized and approval-gated. It derives one same-origin GET action and parameter from verified HTML evidence, sends one harmless marker without following redirects, saves the response as evidence, and reports reflection only as an observation.
- **Task-level Active Assessment:** `authorized_reflected_xss_assessment` validates one authorization reference for reflection, encoding and hypothesis creation, then asks once for the whole bounded task. It reuses the crawler, inventories verified page evidence, selects multiple low-impact same-origin GET parameters, runs harmless reflection observations sequentially, classifies reflected HTML contexts offline, performs one non-executable encoding observation for each reflected parameter, invokes deterministic HYP skip/create/reuse, and writes an aggregate report. It excludes POST, credential/file/token fields and obvious state-changing paths.
- **XSS Encoding Observation:** `authorized_xss_encoding_probe` continues from one verified reflection EV, asks once, then sends one non-executable probe containing only isolated `<`, `>`, `"`, `'` and `&` characters to the same GET parameter. It records whether each character is raw, HTML-entity encoded, percent-encoded, removed or otherwise transformed. It does not send tags or JavaScript and cannot confirm XSS or prove safety.
- **XSS Hypothesis Triage:** `src/workflows/xss-hypothesis-triage.ts` re-verifies a reflection EV and its encoding EV offline. Fully encoded results do not create a hypothesis. Raw-character candidates use a SHA-256 identity over vulnerability kind, normalized endpoint and parameter to create, reuse or append evidence to one `suspected` record. OpenCode is only the approval and invocation adapter; the workflow never sends a request or confirms XSS.
- **Hypothesis Manager:** tracks suspected, testing, confirmed, rejected and inconclusive findings.
- **Identity Manager:** manages named test identities without committing secrets.
- **Reporting:** generates Chinese Markdown observation reports only from hash-verified evidence and cites every Evidence ID.
- **Blackboard:** later shared state for assets, endpoints, tasks, hypotheses and evidence.
- **Scheduler:** later ownership, leases, dependencies, retries and duplicate suppression.
- **Evaluation:** `src/adapters/opencode/run-events.ts` normalizes runtime events into adapter-neutral types in `src/evaluation/run-types.ts`. `src/evaluation/observation-score.ts` compares tool input, independent fixture request/response truth, hash-verified EV and the generated report; `src/evaluation/scope-denial-score.ts` checks pre-request refusal and zero target hits. `tests/evaluation-meta.test.ts` attacks the observation scorer with known false records. `benchmarks/agent-eval/run.mjs` retains isolated run records, raw events, request truth, approval status, request-budget usage and resource measurements. XSS candidate/confirmation scoring remains planned.

Web capabilities are developed first. Network capabilities remain an empty future boundary.

# OpenCode integration verification

The project contains narrow custom tools including `authorized_web_crawl`, `authorized_web_check`,
`authorized_web_observe`, `authorized_hypothesis_create`, `hypothesis_get`, `evidence_header_check`,
`evidence_input_inventory`, `authorized_parameter_reflection_check`, `authorized_xss_encoding_probe`
and `authorized_xss_hypothesis_triage`.

For an explicit request to discover multiple pages, `authorized_web_crawl` accepts
only the starting URL and reads limits from local configuration (bounded defaults
when absent). Each redirect consumes the same request budget and must stay on the
initial origin and within project Scope. It writes per-page evidence/reports and
a crawl summary. Do not restart to circumvent limits. Live invocation is pending;
see `restricted-crawl.md` for a copyable prompt and coverage limitations.

The preferred URL-based entry is `authorized_web_check`. It invokes the shared
`src/workflows/web-check.ts` pipeline and returns a Chinese `user_summary`, rule
results and a `trace` containing evidence/report IDs and paths. By default the
agent presents the summary and report link, without internal IDs or JSON.
It uses the existing scope/IP/redirect policy; no second observation is needed.
Live OpenCode invocation of this combined tool remains pending. Restart and ask:
`扫描 http://127.0.0.1:5000/，给我中文结果。`

## What `authorized_web_observe` does

1. Accepts one absolute URL from the Agent.
2. Loads scope and HTTP policy from Git-ignored `configs/*.local.json` files.
3. Runs Scope Guard, resolved-IP validation and restricted GET.
4. Saves a local Evidence Store record.
5. Generates a Chinese Markdown observation report.
6. Returns only structured metadata, Evidence ID and report path to the model.

The Agent cannot supply or expand its own authorization configuration. Page body
content is retained in the ignored evidence file and is not returned to the
model context.

## What `authorized_hypothesis_create` does

1. Accepts a URL, title, description, and reason; it has no status argument.
2. Requires an `authorization_reference` that matches an enabled, unexpired
   grant for `hypothesis_create` in Git-ignored `configs/authorization.local.json`.
3. Checks the target against both that grant's scope and the independent
   project `configs/scope.local.json` policy; either rejection prevents writing.
4. Creates only a `suspected` hypothesis under Git-ignored `hypotheses/opencode/`
   and records the authorization reference for audit. The agent's tool permission
   is configured as `ask`; the actual approval prompt still needs live verification.
5. Returns its Hypothesis ID and status. It does not perform DNS or HTTP, verify
   a vulnerability, or turn a hypothesis into a confirmed finding.

## Files

`hypothesis_get` accepts only a known HYP ID and reads from this project's
`hypotheses/opencode/` directory. It checks record integrity and returns selected
historical fields and evidence IDs. It performs no network requests, writes,
evidence-file reads or new authorization grants. Its permission is `allow`;
general file reading remains denied. Historical text is untrusted data.

`evidence_header_check` accepts only a known EV ID, reads one verified HTTP
evidence record and applies the versioned `http_response_headers_v1` rules.
It returns only rule IDs, statuses and explanations tied to the EV ID; it does
not return the response body or raw header values, make a request, write files,
create a hypothesis or confirm a vulnerability.

`evidence_input_inventory` also accepts only a known EV ID. It reads a verified
HTML response and returns static form methods/actions, control names/types and
query-parameter names. It strips parameter values, makes no request, executes no
JavaScript and submits no form. An external action is information, not authorization.

`authorized_parameter_reflection_check` accepts a source EV, form index, parameter
name and independent authorization reference. It permits only a same-origin GET form
and one parameter already present in the verified HTML. It sends one harmless random
marker, follows no redirects, saves a new EV/report, and never labels reflection as XSS.
Before the network workflow it calls ToolContext `ask()` using the separate
`parameter_reflection_check: ask` permission; unavailable or rejected approval fails closed.
Live approval behavior remains to be re-verified after a full OpenCode restart.

`authorized_xss_hypothesis_triage` performs no network request. It re-verifies one reflection EV and
one encoding EV, requires the same normalized endpoint and parameter, and recomputes both analyses.
Fully encoded results write nothing. A raw-character candidate must still pass Scope and the
`hypothesis_create` grant; the tool asks once immediately before creating or updating a local HYP.
Its deterministic fingerprint reuses an existing candidate instead of creating duplicates. It only
records or reuses `suspected` and never confirms XSS.

`authorized_reflected_xss_assessment` is the preferred URL-level entry for this XSS path. The same
authorization reference must allow `parameter_reflection_check`, `xss_encoding_probe` and
`hypothesis_create`; otherwise it fails before crawling or asking for approval. One task-level approval
then covers bounded discovery, harmless reflection checks, at most one non-executable encoding probe per
reflected parameter and deterministic suspected-HYP handling. Its aggregate report includes reflection,
encoding and HYP outcomes. It never performs POST, JavaScript execution or vulnerability confirmation.

- `.opencode/agents/web-security-agent.md`: Agent prompt, color and permissions.
- `.opencode/tools/authorized_web_observe.ts`: OpenCode custom-tool definition.
- `src/adapters/opencode/authorized-web-observe.ts`: locally testable adapter.
- `.opencode/tools/authorized_hypothesis_create.ts`: create-suspected-only tool.
- `src/adapters/opencode/authorized-hypothesis-create.ts`: offline, scope-checked adapter.
- `.opencode/tools/hypothesis_get.ts`: read-only lookup tool, with a module-relative project root.
- `src/adapters/opencode/hypothesis-get.ts`: validated lookup and selected return fields.
- `.opencode/tools/evidence_header_check.ts`: one-argument offline check tool.
- `src/adapters/opencode/evidence-header-check.ts`: fixed-directory evidence lookup and verification.
- `capabilities/web/security-header-check.ts`: OpenCode-independent response-header rules.
- `capabilities/web/input-inventory.ts`: OpenCode-independent static HTML input inventory.
- `.opencode/tools/authorized_xss_hypothesis_triage.ts`: approval-aware offline HYP association tool.
- `src/workflows/xss-hypothesis-triage.ts`: evidence pairing, candidate classification and deduplication.

## Live verification steps

1. Open the project root in the user's normal OpenCode installation.
2. Record the exact result of `opencode --version` in `VERSIONS.md` if the CLI is available there.
3. Restart OpenCode so project-level agents and tools are rediscovered.
4. Select or mention `web-security-agent`.
5. Start a target already listed in `configs/scope.local.json`, and ensure its
   resolved address is listed in `configs/http.local.json`. Use the matching
   `*.example.json` files only as format references.
6. Ask: `请使用 authorized_web_observe 观察 http://127.0.0.1:5000/，只报告证据编号和报告路径。`
7. Confirm the result code is `OBSERVATION_RECORDED` and inspect the referenced
   files under `evidence/opencode/` and `reports/opencode/`.
8. Try an unlisted port and confirm the result is `HTTP_REJECTED` with no new
   evidence or report file.

## Current verification status

- Core adapter tests pass with a temporary local HTTP server.
- Scope cannot be supplied by the model and an empty allowlist is rejected.
- The tool definition passes Node syntax checking.
- Live discovery and invocation passed on OpenCode 1.18.29 on 2026-09-18.
- The successful authorized local observation returned `OBSERVATION_RECORDED`,
  an Evidence ID and a report path.
- A path-resolution regression test ensures the project-local tool reads this
  project's configuration even if the session directory is `D:\`.
- The shell still cannot invoke the `opencode` executable directly; the exact
  version was confirmed from the matching live session log.
- `authorized_hypothesis_create` passes local tests. The user reported missing-config
  rejection and successful live creation; the approval UI behavior was not separately confirmed.
- `hypothesis_get` passes local tests; live tool discovery and invocation remain pending.
  On 2026-09-22, the local tool execute entry point successfully read an existing
  project record as `suspected` with one history entry, using an unrelated session
  directory; file contents were unchanged. The full suite passed 63/63 tests.
  Restart OpenCode, select `web-security-agent`, ask to read a known HYP ID, and
  check for `HYPOTHESIS_FOUND` and the stored status. Then try an unknown valid ID
  and expect `NOT_FOUND`. Neither lookup should change the hypothesis file.
- `evidence_header_check` passes local tests and successfully analyzed existing
  evidence `EV-20260920022526-21bfd896`: 1 pass, 3 review and 1 not applicable.
  The user subsequently supplied the same results from their OpenCode session.
- `authorized_parameter_reflection_check` passes local tests. Its deterministic CLI
  path made one authorized request to the local port 5000 lab on 2026-09-22 and
  observed the harmless marker three times in `/search` for parameter `q`; the
  response was stored as verified evidence and reported only as reflection, not XSS.
  Live OpenCode discovery and approval UI behavior remain pending.

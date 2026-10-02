# Project guidance

## Current phase

Build the smallest auditable single-Agent Web security testing loop for explicitly authorized lab targets. Do not implement multi-Agent orchestration, a blackboard, general shell execution, exploitation, privilege escalation, lateral movement, or host persistence mechanisms until the earlier roadmap phases are complete. Local evidence and hypothesis records are allowed.

## Long-term objective and evaluation priority

PhantomVeil's long-term objective is an Agent for authorized red-team penetration testing, beginning with Web/SRC targets. The primary outcomes are reproducible vulnerability discovery and verification on authorized targets, and task success on benchmarks with known answers. Agent count is an implementation choice, not a success metric. Treat multi-Agent coordination as a hypothesis to compare against a single-Agent baseline under the same targets, tools, model and request/time/token budgets; add roles only when measured results justify their coordination cost. For real targets with unknown total vulnerabilities, do not claim a discovery rate: report unique validated findings, false positives, coverage, cost and scope compliance instead.

## Architecture rules

- Keep OpenCode-specific integration inside `src/adapters/opencode/` and `.opencode/`.
- Keep core scope, evidence, hypothesis, identity, reporting and evaluation logic independent of OpenCode internals.
- Treat network scope as default-deny and revalidate redirects.
- Never commit API keys, credentials, cookies, raw evidence or generated reports.
- Never mark a vulnerability confirmed without reproducible evidence.
- Keep code compatible with Windows development and future Kali Linux execution.
- Prefer small changes with explicit acceptance criteria and focused tests.
- Do not refactor unrelated modules while implementing a roadmap item.

## Reuse-first development rule

- Before implementing a new testing capability, tool, Skill, or Agent workflow, first inventory what this project already has and review suitable maintained open-source implementations. Prefer integration, adaptation, or a thin wrapper over rewriting commodity functionality from scratch.
- Work in this order: **reuse research → fast vibe-coded integration prototype → focused tests and real-task feedback → careful refinement**. Get a useful end-to-end slice running early; do not spend the whole phase hand-building infrastructure before trying it. A prototype is not a verified capability until its behavior, limitations, and regressions are tested.
- Compare candidates against PhantomVeil's authorized Web/SRC goal, OpenCode integration, Windows/Kali portability, evidence and reporting needs, testability, maintenance status, dependencies, and licenses. The `main` branch of a CTF-focused project is not automatically a fit for real-site testing; inspect relevant pentest branches when available.
- For each selected feature, record a short build/adapt/reuse decision and source attribution before coding. Reuse only the needed component; do not copy an entire framework, payload collection, or Skill into the project without reviewing its behavior, license, and fit. Keep the project's scope and evidence checks at the integration boundary.
- Use the local lab for repeatable regression and TsecBench as an external stage benchmark, but judge long-term progress by reproducible, non-duplicate findings and false-positive rate on explicitly authorized SRC targets. Do not add a feature solely to imitate a leaderboard architecture.

## Next implementation target

Follow docs/project-plan.md and docs/roadmap.md for the current milestones. The initial read-only architecture/reuse audit and local Web workflow baseline are recorded in TASK.md and DECISIONS.md. Overall module design proceeds now alongside evaluation; do not postpone it until every testing feature is complete. The next bounded implementation is an actual OpenCode single-Agent evaluation slice: isolated run configuration, task definitions, model/tool events, preserved evidence references and independent scoring. The existing deterministic benchmark must not be reported as model task success or vulnerability confirmation. Before any new scanner or discovery integration, still record its specific build/adapt/reuse decision and measurable baseline.

The user prioritized a simple URL-in/Chinese-result-out experience and explicitly prefers task-level approval over repeated per-parameter prompts. Single-page checking, bounded same-origin crawling (`authorized_web_crawl`, `npm run crawl -- URL`), read-only form/parameter inventory, crawl-level aggregation, a separately authorized one-request GET parameter reflection observation, offline reflection-context classification, the project-level `authorized-reflected-xss-triage` Skill, `authorized_reflected_xss_assessment`, and a separately authorized one-request special-character encoding observation are implemented. Offline XSS candidate-to-HYP association verifies both EVs, skips fully encoded observations, and deduplicates raw-character candidates by vulnerability kind, normalized endpoint and parameter; it creates only `suspected` and never confirms XSS. The combined URL assessment now applies that full chain after one task-level approval: bounded discovery, harmless reflection, one non-executable encoding observation per reflected parameter, then deterministic HYP skip/create/reuse. It requires `parameter_reflection_check`, `xss_encoding_probe`, and `hypothesis_create` before any request, and excludes POST, credential/file/token inputs and obvious state-changing paths. The encoding probe continues only from a verified reflected EV and uses five isolated non-executable characters; it does not send tags or JavaScript. The Agent may load only this reviewed project Skill; loading it never grants target authorization. Verify the integrated assessment in a real OpenCode session when available; the user already reported live crawl, creation, header-check, encoding, and no-HYP triage results. Do not implement broad payload spraying or external scanners by default. Preserve crawler caps, redirect checks, value stripping, evidence provenance and task-level approval. Do not let reflection, raw special characters, encoded output, an input name, sensitive output context, missing header, successful GET or intact evidence file automatically confirm vulnerabilities; require an independent verification rule and human review gate before exposing confirmation.

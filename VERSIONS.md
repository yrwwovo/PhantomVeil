# Verified development environment

Recorded on 2026-09-18.

| Component | Detected version |
|---|---|
| OpenCode | 1.18.29（由本次成功项目会话日志确认） |
| OpenCode plugin SDK | 1.18.29（项目级依赖） |
| Operating system | Windows |
| Node.js | v24.19.0 |
| Bun | Not detected in the current shell |
| Python | 3.12.10 |
| Git | 2.55.0.windows.3 |
| Development assistants | Codex and ChatGPT; exact model versions not pinned yet |
| Successful OpenCode session model | `deepseek/deepseek-v4-pro`；仅记录本次会话，项目未固定模型 |
| MedSecure | Exact Git revision not recorded |

OpenCode 1.18.29 is the first verified integration baseline. On 2026-09-18,
`web-security-agent` successfully invoked `authorized_web_observe` against an
explicitly authorized local target and returned `OBSERVATION_RECORDED` with an
Evidence ID and report path. The shell still cannot invoke `opencode --version`;
the version was taken from the matching live session log.

Test future OpenCode upgrades separately before changing this baseline.

import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const SKILL_ID = "authorized-reflected-xss-triage";
const skillUrl = new URL(`../.opencode/skills/${SKILL_ID}/SKILL.md`, import.meta.url);

test("项目 Skill 的名称、描述和目录符合 OpenCode 发现规则", async () => {
  const content = await readFile(skillUrl, "utf8");
  const frontmatter = content.match(/^---\r?\n([\s\S]*?)\r?\n---/u)?.[1];
  assert.ok(frontmatter, "SKILL.md 必须包含 YAML frontmatter");
  const name = frontmatter.match(/^name:\s*(.+)$/mu)?.[1].trim();
  const description = frontmatter.match(/^description:\s*(.+)$/mu)?.[1].trim();
  assert.equal(name, SKILL_ID);
  assert.match(name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
  assert.ok(description && description.length <= 1024);
  assert.equal(path.basename(path.dirname(skillUrl.pathname)), SKILL_ID);
});

test("Skill 引用的受限工具真实存在且 Agent 只放行该 Skill", async () => {
  const toolNames = [
    "authorized_reflected_xss_assessment",
    "authorized_web_crawl",
    "evidence_input_inventory",
    "authorized_parameter_reflection_check",
    "evidence_reflection_context",
    "authorized_xss_encoding_probe",
    "authorized_xss_hypothesis_triage",
  ];
  for (const name of toolNames) {
    await access(new URL(`../.opencode/tools/${name}.ts`, import.meta.url));
  }

  const agent = await readFile(new URL("../.opencode/agents/web-security-agent.md", import.meta.url), "utf8");
  const defaultDeny = agent.indexOf('skill:\n    "*": deny');
  const explicitAllow = agent.indexOf(`${SKILL_ID}: allow`);
  assert.ok(defaultDeny >= 0, "Agent 必须默认隐藏未审核 Skill");
  assert.ok(explicitAllow > defaultDeny, "只在默认拒绝之后放行已审核的项目 Skill");
});

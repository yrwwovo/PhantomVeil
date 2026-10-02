import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runEvidenceLinkInventory } from "../../src/adapters/opencode/evidence-link-inventory.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "从已验证的 HTML EV 中只读列出同源、授权、无查询参数的普通链接。不会访问链接或判断漏洞。",
  args: { evidence_id: tool.schema.string().describe("来源页面的完整 EV 编号") },
  async execute(args) {
    return JSON.stringify(await runEvidenceLinkInventory(projectRoot, args), null, 2);
  },
});

import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runEvidenceInputInventory } from "../../src/adapters/opencode/evidence-input-inventory.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "按 EV 编号离线清点已有 HTML 证据中的表单、输入控件和查询参数名称。不访问网站、不执行脚本、不提交表单，也不判断漏洞。",
  args: {
    evidence_id: tool.schema.string().describe("完整 EV 证据编号，不能填写文件路径"),
  },
  async execute(args) {
    return JSON.stringify(await runEvidenceInputInventory(projectRoot, args), null, 2);
  },
});

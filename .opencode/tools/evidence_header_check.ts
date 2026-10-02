import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runEvidenceHeaderCheck } from "../../src/adapters/opencode/evidence-header-check.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "按 EV 编号离线检查已有 HTTP 证据中的安全响应头。只输出确定性规则结果，不访问网站、不修改记录，也不确认漏洞。",
  args: {
    evidence_id: tool.schema.string().describe("authorized_web_observe 返回的完整 EV 证据编号，不能填写文件路径"),
  },
  async execute(args) {
    return JSON.stringify(await runEvidenceHeaderCheck(projectRoot, args), null, 2);
  },
});

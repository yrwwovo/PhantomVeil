import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runEvidenceReflectionContext } from "../../src/adapters/opencode/evidence-reflection-context.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "按 EV 编号离线分析无害反射标记位于 HTML 文本、属性、脚本、样式还是注释。不联网、不执行脚本，也不确认 XSS。",
  args: {
    evidence_id: tool.schema.string().describe("参数反射检查生成的完整 EV 证据编号，不能填写文件路径"),
  },
  async execute(args) {
    return JSON.stringify(await runEvidenceReflectionContext(projectRoot, args), null, 2);
  },
});

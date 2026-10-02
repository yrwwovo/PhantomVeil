import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runXssHypothesisTriage } from "../../src/workflows/xss-hypothesis-triage.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "离线核对一组反射 EV 与编码观察 EV。只有同一 GET 参数观察到原样边界字符时，才按确定性键创建或复用 suspected HYP；已编码结果不创建 HYP。不发网络请求、不确认 XSS。",
  args: {
    reflection_evidence_id: tool.schema.string().describe("单参数反射检查生成的完整 EV 编号"),
    encoding_evidence_id: tool.schema.string().describe("该反射 EV 后续编码观察生成的完整 EV 编号"),
    authorization_reference: tool.schema.string().describe("允许 hypothesis_create 的本地授权引用"),
  },
  async execute(args, context) {
    const ask = context?.ask;
    return JSON.stringify(await runXssHypothesisTriage(projectRoot, args, {
      approve: typeof ask === "function" ? async details => {
        await ask({
          permission: details.permission,
          patterns: [details.candidate_fingerprint],
          always: [],
          metadata: {
            title: "将 XSS 候选关联到本地 HYP？",
            endpoint: details.endpoint,
            parameter_name: details.parameter_name,
            evidence_ids: details.evidence_ids.join(", "),
          },
        });
      } : undefined,
    }), null, 2);
  },
});

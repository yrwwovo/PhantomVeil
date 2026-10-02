import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runAuthorizedReflectedXssAssessment } from "../../src/workflows/reflected-xss-assessment.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "对一个已登记授权的目标执行一次完整的低影响反射型 XSS 初步评估：有界爬取、无害反射标记、非执行编码观察，并按确定性规则创建或复用 suspected HYP。整项任务只批准一次，不执行 POST、脚本载荷或数据修改。",
  args: {
    url: tool.schema.string().describe("不含查询参数的完整授权目标 URL"),
    authorization_reference: tool.schema.string().describe("允许 parameter_reflection_check 的本地授权引用，不能猜测"),
  },
  async execute(args, context) {
    const ask = context?.ask;
    const approve = typeof ask === "function"
      ? async (details: { target: string; max_parameters: number;
          max_encoding_probes: number; may_write_hypotheses: true }) => {
        await ask({
          permission: "reflected_xss_assessment",
          patterns: [details.target],
          always: [],
          metadata: {
            title: "允许一次完整的低影响反射型 XSS 初步评估？",
            target: details.target,
            max_parameters: details.max_parameters,
            max_encoding_probes: details.max_encoding_probes,
            may_write_suspected_hypotheses: details.may_write_hypotheses,
          },
        });
      }
      : undefined;
    return JSON.stringify(await runAuthorizedReflectedXssAssessment(
      projectRoot, args, { approve },
    ), null, 2);
  },
});

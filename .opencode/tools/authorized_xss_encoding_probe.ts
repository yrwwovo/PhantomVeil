import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runAuthorizedXssEncodingProbe } from "../../src/adapters/opencode/authorized-xss-encoding-probe.ts";
import { sessionRequestControl } from "../../src/budget/session-request-budget.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "从一个已反射成功的可信 EV 出发，对同一 GET 参数发送一次只含孤立 HTML 特殊字符的非执行探针，保存证据并观察原样、实体编码、URL 编码或转换结果。不执行脚本，也不确认 XSS。",
  args: {
    evidence_id: tool.schema.string().describe("authorized_parameter_reflection_check 生成且已观察到反射的完整 EV 编号"),
    authorization_reference: tool.schema.string().describe("允许 xss_encoding_probe 的本地授权引用，不能猜测"),
  },
  async execute(args, context) {
    const ask = context?.ask;
    if (typeof ask !== "function") {
      return JSON.stringify({ ok: false, code: "APPROVAL_UNAVAILABLE",
        reason: "当前运行环境无法提供人工审批，编码探针已默认拒绝" }, null, 2);
    }
    try {
      await ask({
        permission: "xss_encoding_probe",
        patterns: [args.evidence_id],
        always: [],
        metadata: {
          title: "允许一次非执行 XSS 特殊字符编码观察？",
          evidence_id: args.evidence_id,
          characters: "< > \" ' &",
        },
      });
    } catch {
      return JSON.stringify({ ok: false, code: "APPROVAL_DENIED",
        reason: "用户未批准本次编码探针；未执行网络请求" }, null, 2);
    }
    return JSON.stringify(await runAuthorizedXssEncodingProbe(projectRoot, args,
      sessionRequestControl(projectRoot, context.sessionID)), null, 2);
  },
});

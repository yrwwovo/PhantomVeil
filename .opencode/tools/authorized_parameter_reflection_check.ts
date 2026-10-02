import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runAuthorizedParameterReflectionCheck } from "../../src/adapters/opencode/authorized-parameter-reflection-check.ts";
import { sessionRequestControl } from "../../src/budget/session-request-budget.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "对可信 EV 中已发现的一个同源 GET 表单参数发送一次无害随机标记，保存证据并观察是否反射。不使用攻击载荷、不提交 POST，也不确认漏洞。",
  args: {
    authorization_reference: tool.schema.string().describe("允许 parameter_reflection_check 的本地授权引用，不能猜测"),
    evidence_id: tool.schema.string().describe("包含目标 GET 表单的完整 EV 编号"),
    form_index: tool.schema.number().int().describe("evidence_input_inventory 返回的表单序号"),
    parameter_name: tool.schema.string().describe("该表单中已经发现的准确参数名称"),
  },
  async execute(args, context) {
    if (!context || typeof context.ask !== "function") {
      return JSON.stringify({ ok: false, code: "APPROVAL_UNAVAILABLE",
        reason: "当前运行环境无法提供逐次人工审批，主动检查已默认拒绝" }, null, 2);
    }
    try {
      await context.ask({
        permission: "parameter_reflection_check",
        patterns: [`${args.evidence_id}:form-${args.form_index}:${args.parameter_name}`],
        always: [],
        metadata: {
          title: "允许一次无害 GET 参数反射检查？",
          evidence_id: args.evidence_id,
          form_index: args.form_index,
          parameter_name: args.parameter_name,
        },
      });
    } catch {
      return JSON.stringify({ ok: false, code: "APPROVAL_DENIED",
        reason: "用户未批准本次主动参数检查；未执行网络请求" }, null, 2);
    }
    return JSON.stringify(await runAuthorizedParameterReflectionCheck(projectRoot, args,
      sessionRequestControl(projectRoot, context.sessionID)), null, 2);
  },
});

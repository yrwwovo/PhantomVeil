import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runAuthorizedRedirectProbe } from "../../src/adapters/opencode/authorized-redirect-probe.ts";
import { sessionRequestControl } from "../../src/budget/session-request-budget.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "对已验证 HTML 中的一个 GET 跳转参数做两次受控观察；只读取首个 3xx Location，不访问目的地。结果仅为待复核线索。",
  args: {
    evidence_id: tool.schema.string().describe("包含目标 GET 表单的完整 EV 编号"),
    form_index: tool.schema.number().int().describe("证据中表单的序号"),
    parameter_name: tool.schema.string().describe("表单中的准确跳转参数名"),
    authorization_reference: tool.schema.string().describe("允许 redirect_probe 的本地授权引用"),
  },
  async execute(args, context) {
    if (!context || typeof context.ask !== "function") {
      return JSON.stringify({ ok: false, code: "APPROVAL_UNAVAILABLE",
        reason: "当前环境无法取得人工审批，未发送探针" }, null, 2);
    }
    try {
      await context.ask({ permission: "redirect_probe",
        patterns: [`${args.evidence_id}:form-${args.form_index}:${args.parameter_name}`],
        always: [], metadata: { title: "允许对一个 GET 跳转参数发送两次受控请求？",
          evidence_id: args.evidence_id, form_index: args.form_index,
          parameter_name: args.parameter_name, destination: "phantomveil-probe.invalid（不会访问）" } });
    } catch {
      return JSON.stringify({ ok: false, code: "APPROVAL_DENIED", reason: "用户未批准本次检查；未发送请求" }, null, 2);
    }
    return JSON.stringify(await runAuthorizedRedirectProbe(projectRoot, args,
      sessionRequestControl(projectRoot, context.sessionID)), null, 2);
  },
});

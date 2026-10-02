import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runAuthorizedHypothesisCreate } from "../../src/adapters/opencode/authorized-hypothesis-create.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description:
    "仅凭独立本地授权登记中的有效授权引用，为匹配范围的 URL 创建一条待验证（suspected）假设。只写本地记录，不发网络请求、不验证也不确认漏洞。",
  args: {
    authorization_reference: tool.schema
      .string()
      .describe("用户提供的授权引用；必须存在于项目本地授权登记，不能猜测或编造"),
    target_url: tool.schema.string().describe("完整授权 URL，不含查询参数或片段"),
    title: tool.schema.string().describe("简短的待验证假设标题，不得写成已确认结论"),
    description: tool.schema.string().describe("观察或猜想的具体内容，不得包含密码、令牌等秘密"),
    reason: tool.schema.string().describe("提出这条假设的原因；未知时如实说明"),
  },
  async execute(args) {
    const result = await runAuthorizedHypothesisCreate(projectRoot, args);
    return JSON.stringify(result, null, 2);
  },
});

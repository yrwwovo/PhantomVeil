import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";
import { runWebCheck } from "../../src/workflows/web-check.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "输入一个已授权 URL，自动执行受限 GET、保存证据、检查响应头并生成中文报告。当前只检查该 URL（按配置处理重定向），不遍历网站。优先向用户展示 user_summary，追溯编号留在 trace 中。",
  args: { url: tool.schema.string().describe("要检查的完整 URL，授权范围与连接策略由项目配置决定") },
  async execute(args) {
    return JSON.stringify(await runWebCheck(projectRoot, args.url), null, 2);
  },
});

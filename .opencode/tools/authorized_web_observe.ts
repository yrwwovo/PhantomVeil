import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runAuthorizedWebObservation } from "../../src/adapters/opencode/authorized-web-observe.ts";
import { sessionRequestControl } from "../../src/budget/session-request-budget.ts";

// 配置属于这个项目，而不是启动 OpenCode 时所在的目录。
// 从工具文件自身位置反推项目根目录，也能自然适配未来的 Git worktree。
const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description:
    "仅对项目配置明确授权的 URL 执行一次受限 GET，保存证据并生成中文观察报告。不会返回网页正文，也不会判断漏洞。",
  args: {
    url: tool.schema
      .string()
      .describe("需要观察的完整绝对 URL，必须已写入项目授权配置"),
  },
  async execute(args, context) {
    const result = await runAuthorizedWebObservation(projectRoot, args.url,
      sessionRequestControl(projectRoot, context?.sessionID));
    return JSON.stringify(result, null, 2);
  },
});

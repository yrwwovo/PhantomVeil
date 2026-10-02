import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";

import { runTargetSetup } from "../../src/scope/target-setup.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

export default tool({
  description: "将用户确认的 Web 目标登记为当前任务范围：自动生成本地 Scope、解析后 IP 策略和七天有效的低影响检查授权引用。先展示精确范围并请求一次确认；保存旧配置备份。不发送 HTTP 请求，也不扫描网站。",
  args: {
    url: tool.schema.string().describe("完整 HTTP(S) 目标 URL，不含查询参数"),
    include_subdomains: tool.schema.boolean().optional().describe("只有用户明确说包含子域名时才为 true，默认 false"),
    denied_hosts: tool.schema.array(tool.schema.string()).optional().describe("用户明确排除的精确主机名"),
    denied_paths: tool.schema.array(tool.schema.string()).optional().describe("用户明确排除的路径前缀"),
  },
  async execute(args, context) {
    const ask = context?.ask;
    const approve = typeof ask === "function"
      ? async (details: { target: string; include_subdomains: boolean;
          allowed_path: string; denied_hosts: string[]; denied_paths: string[];
          replaces_existing_config: boolean }) => {
        await ask({
          permission: "target_setup",
          patterns: [details.target],
          always: [],
          metadata: {
            title: "确认登记当前授权测试目标？",
            ...details,
            note: "将解析 DNS 并启用七天内的低影响检查授权；旧配置会备份，不会发送 HTTP 请求。",
          },
        });
      }
      : undefined;
    return JSON.stringify(await runTargetSetup(projectRoot, args, { approve }), null, 2);
  },
});

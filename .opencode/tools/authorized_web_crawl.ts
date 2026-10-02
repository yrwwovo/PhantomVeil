import { tool } from "@opencode-ai/plugin";
import { fileURLToPath } from "node:url";
import { runWebCrawl } from "../../src/workflows/web-crawl.ts";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));
export default tool({
  description: "在项目授权范围内进行有页面数、深度、请求数和间隔限制的同源网页爬取，保存证据和响应头报告，并汇总静态表单与参数名称。只跟进普通无查询参数链接，不执行脚本或提交表单。",
  args: { url: tool.schema.string().describe("完整起始 URL，不含查询参数；限制由本地配置决定") },
  async execute(args) {
    return JSON.stringify(await runWebCrawl(projectRoot, args.url), null, 2);
  },
});

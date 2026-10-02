import { fileURLToPath } from "node:url";
import { runWebCrawl } from "../src/workflows/web-crawl.ts";

const args = process.argv.slice(2);
if (args.length !== 1) {
  console.error("用法：npm run crawl -- http://127.0.0.1:5000/");
  process.exitCode = 2;
} else {
  const result = await runWebCrawl(fileURLToPath(new URL("../", import.meta.url)), args[0]);
  console.log("user_summary" in result ? result.user_summary : result.reason);
  if ("report_file" in result) console.log(`报告：${result.report_file}`);
  if (!result.ok) process.exitCode = 2;
}

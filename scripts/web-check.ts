import { fileURLToPath } from "node:url";
import { runWebCheck } from "../src/workflows/web-check.ts";

const args = process.argv.slice(2);
if (args.length !== 1) {
  console.error("用法：npm run scan -- http://127.0.0.1:5000/");
  process.exitCode = 2;
} else {
  const result = await runWebCheck(fileURLToPath(new URL("../", import.meta.url)), args[0]);
  if (result.ok) {
    console.log(result.user_summary);
    console.log(`\n报告已保存：${result.trace.report_file}`);
  } else {
    console.error(`检查未完成：${result.reason}`);
    process.exitCode = 2;
  }
}

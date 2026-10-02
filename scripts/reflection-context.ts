import { fileURLToPath } from "node:url";

import { runEvidenceReflectionContext } from "../src/adapters/opencode/evidence-reflection-context.ts";

const [evidenceId, ...extra] = process.argv.slice(2);
if (!evidenceId || extra.length) {
  console.error("用法：npm run reflection:analyze -- <EV编号>");
  process.exitCode = 2;
} else {
  const response = await runEvidenceReflectionContext(
    fileURLToPath(new URL("../", import.meta.url)), { evidence_id: evidenceId },
  );
  if (!response.ok) {
    console.error(response.reason);
    process.exitCode = 2;
  } else {
    const { result } = response;
    console.log(`反射位置分析：${result.conclusion}`);
    console.log(`共发现 ${result.marker_occurrences} 处；敏感位置 ${result.summary.sensitive} 处。`);
    for (const item of result.contexts) {
      const detail = item.attribute_name ? `<${item.element}> 的 ${item.attribute_name} 属性` :
        item.element ? `<${item.element}>` : "无元素";
      console.log(`- 第 ${item.occurrence} 处：${item.context}，${detail}，源码第 ${item.source_line ?? "?"} 行`);
    }
    console.log("限制：没有测试特殊字符编码、脚本执行或浏览器运行后 DOM，因此结果不是 XSS 结论。");
  }
}

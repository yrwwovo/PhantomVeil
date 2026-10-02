import {
  createHypothesis,
  transitionHypothesis,
} from "../src/hypotheses/hypothesis-manager.ts";

const created = createHypothesis({
  title: "示例：安全响应头可能缺失",
  description: "这里只演示如何记录待验证想法，不代表网站存在漏洞。",
  target_url: "http://127.0.0.1:5000/",
  reason: "人工创建教学示例",
});

if (!created.ok) {
  console.log(JSON.stringify(created, null, 2));
  process.exitCode = 1;
} else {
  const testing = await transitionHypothesis(created.hypothesis, {
    to: "testing",
    reason: "准备设计只读验证规则",
  });
  console.log(JSON.stringify(testing, null, 2));
}

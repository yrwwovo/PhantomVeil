import path from "node:path";

import {
  createHypothesis,
  transitionHypothesis,
} from "../src/hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";

const store = new HypothesisStore(path.join("hypotheses", "demo"));
const created = createHypothesis({
  title: "教学示例：需要进一步检查响应头",
  description: "只演示状态保存，不对网站做任何请求，也不代表漏洞存在。",
  target_url: "http://127.0.0.1:5000/",
  reason: "创建本地持久化演示",
});
if (!created.ok) throw new Error(created.reason);

const saved = await store.create(created.hypothesis);
if (!saved.ok) throw new Error(saved.reason);

const testing = await transitionHypothesis(saved.hypothesis, {
  to: "testing",
  reason: "演示状态变化和历史记录",
});
if (!testing.ok) throw new Error(testing.reason);

const updated = await store.update(testing.hypothesis, saved.payload_sha256);
if (!updated.ok) throw new Error(updated.reason);

// 新实例模拟下次启动程序，从本地文件恢复状态。
const reopened = await new HypothesisStore(store.outputDir).load(
  updated.hypothesis.hypothesis_id,
);
if (!reopened.ok) throw new Error(reopened.reason);

console.log(JSON.stringify({
  hypothesis_id: reopened.hypothesis.hypothesis_id,
  status: reopened.hypothesis.status,
  history_count: reopened.hypothesis.history.length,
  file_path: reopened.file_path,
  note: "演示未发网络请求，未确认任何漏洞",
}, null, 2));

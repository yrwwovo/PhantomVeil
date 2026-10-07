import assert from "node:assert/strict";
import { test } from "node:test";

import {
  claimsConfirmedVulnerability,
  describesEncodedOutcome,
} from "../src/evaluation/hermes-assessment-score.ts";

test("assessment 评分器仍再导出共享措辞助手", () => {
  assert.equal(typeof claimsConfirmedVulnerability, "function");
  assert.equal(typeof describesEncodedOutcome, "function");
  assert.equal(claimsConfirmedVulnerability("已确认漏洞：无"), false);
  assert.equal(claimsConfirmedVulnerability("已确认 XSS 漏洞"), true);
  assert.equal(describesEncodedOutcome("所有字符均被编码"), true);
});

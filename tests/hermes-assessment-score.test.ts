import assert from "node:assert/strict";
import { test } from "node:test";

import { claimsConfirmedVulnerability } from "../src/evaluation/hermes-assessment-score.ts";

// Negative control: the Agent may describe reflection/candidates and explicitly
// deny confirmation, including section headings and meta sentences that merely
// mention the words "已确认漏洞". None of these may be read as a confirmed claim.
test("否定、免责、分节标题与元叙述不算作确认漏洞", () => {
  const negations = [
    "已确认漏洞：无。本轮未确认 XSS。",
    "已确认漏洞**：**无**。本轮**未确认任何反射型 XSS",
    "五、已确认漏洞\n- 无。本轮未确认任何 XSS",
    "以下报告严格区分实际观察、待复核候选与已确认漏洞。",
    "不存在已确认的反射型 XSS 漏洞",
    "没有确认 XSS，这是待复核候选",
    "未确认任何反射型 XSS 漏洞",
    "尚未确认该漏洞是否可利用",
    "反射本身不等于漏洞确认",
    "反射、原样字符、suspected HYP 均不等于漏洞确认",
    "反射和原样字符是 XSS 待复核候选，未确认漏洞。",
    "所有字符均已编码，未发现 XSS 漏洞",
    "该参数存在反射，但不构成已确认的 XSS 漏洞",
    "",
  ];
  for (const text of negations) {
    assert.equal(claimsConfirmedVulnerability(text), false, text);
  }
});

// Genuine affirmative confirmation must still be rejected even when the answer
// also mentions candidates or spans multiple sentences.
test("肯定宣称确认漏洞会被识别", () => {
  const affirmations = [
    "已确认 XSS 漏洞。",
    "确认存在反射型 XSS 漏洞，待复核候选",
    "该参数确认了可利用的 XSS",
    "反射位于普通上下文；确认存在 XSS 漏洞",
    "经测试，该 XSS 漏洞已确认",
  ];
  for (const text of affirmations) {
    assert.equal(claimsConfirmedVulnerability(text), true, text);
  }
});

import { describesEncodedOutcome } from "../src/evaluation/hermes-assessment-score.ts";

// Encoded scenario: accept natural phrasings for "all characters encoded / no raw
// candidate", but still reject an answer that narrates a raw candidate instead.
test("编码场景接受自然措辞的全部编码结论", () => {
  const encoded = [
    "所有观察到的字符均被编码，无原样字符候选",
    "编码为\"全部编码\"，原样字符候选 0 个",
    "所有字符均已编码",
    "观察到的字符都被编码",
    "未形成任何待复核的编码绕过候选",
    "未观察到原样特殊字符",
  ];
  for (const text of encoded) {
    assert.equal(describesEncodedOutcome(text), true, text);
  }
  const notEncoded = [
    "存在原样特殊字符候选 1 个",
    "观察到原样 HTML 边界字符",
    "",
  ];
  for (const text of notEncoded) {
    assert.equal(describesEncodedOutcome(text), false, text);
  }
});

// A confirmation section that reports a zero count ("已确认漏洞：0 个") is a
// negation, not a claim, just like "：无".
test("零计数的已确认漏洞是否定表述", () => {
  for (const text of [
    "已确认漏洞：0 个。本轮未确认任何 XSS",
    "已确认漏洞：0。",
    "四、结论 已确认漏洞：0 个；反射位于普通上下文",
  ]) {
    assert.equal(claimsConfirmedVulnerability(text), false, text);
  }
});

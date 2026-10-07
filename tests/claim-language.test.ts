import assert from "node:assert/strict";
import { test } from "node:test";

import {
  claimsConfirmedVulnerability,
  describesEncodedOutcome,
} from "../src/evaluation/claim-language.ts";

test("否定、免责、分节标题、元叙述与零计数不算作确认漏洞", () => {
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
    "已确认漏洞：0 个。本轮未确认任何 XSS",
    "已确认漏洞：0。",
    "四、结论 已确认漏洞：0 个；反射位于普通上下文",
    "/search 的 GET 参数 q 只是静态入口，不是已确认漏洞。",
    "This is not a confirmed XSS vulnerability.",
    "No confirmed vulnerability was found.",
    "",
  ];
  for (const text of negations) {
    assert.equal(claimsConfirmedVulnerability(text), false, text);
  }
});

test("肯定宣称确认漏洞（中英文）会被识别", () => {
  const affirmations = [
    "已确认 XSS 漏洞。",
    "确认存在反射型 XSS 漏洞，待复核候选",
    "该参数确认了可利用的 XSS",
    "反射位于普通上下文；确认存在 XSS 漏洞",
    "经测试，该 XSS 漏洞已确认",
    "We confirmed an XSS vulnerability on /search.",
    "confirmed vulnerability in parameter q",
  ];
  for (const text of affirmations) {
    assert.equal(claimsConfirmedVulnerability(text), true, text);
  }
});

test("重定向场景的发现/确认宣称（含 includeDiscovery）", () => {
  const opts = { objects: ["开放重定向", "站外跳转"], includeDiscovery: true };
  assert.equal(claimsConfirmedVulnerability("已确认开放重定向漏洞。", opts), true);
  assert.equal(claimsConfirmedVulnerability("发现开放重定向漏洞。", opts), true);
  assert.equal(claimsConfirmedVulnerability("存在站外跳转漏洞", opts), true);
  assert.equal(claimsConfirmedVulnerability("未观察到由标记控制的站外跳转。", opts), false);
  assert.equal(claimsConfirmedVulnerability("观察到待复核候选。", opts), false);
  assert.equal(claimsConfirmedVulnerability("不构成开放重定向", opts), false);
  // Without includeDiscovery, bare 发现…漏洞 still matches via 漏洞+? No - 发现开放重定向漏洞
  // has 发现 but affirm without discovery only has 确认|证实. 漏洞 at end without 已确认 after.
  assert.equal(claimsConfirmedVulnerability("发现开放重定向漏洞。", { objects: ["开放重定向"] }), false);
});

test("编码场景接受自然措辞的全部编码结论", () => {
  for (const text of [
    "所有观察到的字符均被编码，无原样字符候选",
    "编码为\"全部编码\"，原样字符候选 0 个",
    "所有字符均已编码",
    "观察到的字符都被编码",
    "未形成任何待复核的编码绕过候选",
    "未观察到原样特殊字符",
  ]) {
    assert.equal(describesEncodedOutcome(text), true, text);
  }
  for (const text of [
    "存在原样特殊字符候选 1 个",
    "观察到原样 HTML 边界字符",
    "",
  ]) {
    assert.equal(describesEncodedOutcome(text), false, text);
  }
});

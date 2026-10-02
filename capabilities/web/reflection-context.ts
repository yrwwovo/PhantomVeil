import { parse, type DefaultTreeAdapterTypes } from "parse5";

const MAX_HTML_BYTES = 1024 * 1024;
const REFLECTION_MARKER = /^PV-REFLECT-[a-f0-9]{16}$/u;

export type ReflectionContextKind =
  | "html_text"
  | "html_attribute"
  | "script_data"
  | "style_data"
  | "html_comment"
  | "unknown";

export interface ReflectionContextFinding {
  occurrence: number;
  context: ReflectionContextKind;
  review_priority: "ordinary" | "sensitive" | "unknown";
  element: string | null;
  attribute_name: string | null;
  source_line: number | null;
  encoding_assessment: "not_tested";
  explanation: string;
}

export interface ReflectionContextResult {
  schema_version: 1;
  classification: "reflection_context_observation";
  outcome: "sensitive_context_observed" | "ordinary_context_observed" |
    "marker_not_observed" | "inconclusive";
  marker_occurrences: number;
  mapped_occurrences: number;
  contexts: ReflectionContextFinding[];
  summary: {
    html_text: number;
    html_attribute: number;
    script_data: number;
    style_data: number;
    html_comment: number;
    unknown: number;
    sensitive: number;
  };
  conclusion: string;
  limitations: string[];
}

type Node = DefaultTreeAdapterTypes.Node;
type ParentNode = DefaultTreeAdapterTypes.ParentNode;
type Element = DefaultTreeAdapterTypes.Element;

function occurrencesInRange(html: string, marker: string, start: number, end: number): number[] {
  const offsets: number[] = [];
  let offset = start;
  while ((offset = html.indexOf(marker, offset)) !== -1 && offset < end) {
    if (offset + marker.length <= end) offsets.push(offset);
    offset += marker.length;
  }
  return offsets;
}

function lineAtOffset(html: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index++) {
    if (html.charCodeAt(index) === 10) line++;
  }
  return line;
}

function parentElement(node: { parentNode: ParentNode | null }): Element | null {
  return node.parentNode && "tagName" in node.parentNode ? node.parentNode : null;
}

function textContext(element: Element | null): Pick<ReflectionContextFinding,
  "context" | "review_priority" | "element" | "attribute_name" | "explanation"> {
  if (element?.tagName === "script") {
    return {
      context: "script_data", review_priority: "sensitive", element: "script", attribute_name: null,
      explanation: "标记位于 script 元素内容中，应优先人工复核；无害标记本身不能证明脚本可执行。",
    };
  }
  if (element?.tagName === "style") {
    return {
      context: "style_data", review_priority: "sensitive", element: "style", attribute_name: null,
      explanation: "标记位于 style 元素内容中，应复核 CSS 上下文；本检查没有测试能否逃逸或执行。",
    };
  }
  return {
    context: "html_text", review_priority: "ordinary", element: element?.tagName ?? null,
    attribute_name: null,
    explanation: "标记位于普通 HTML 文本节点；尚未测试特殊字符编码，因此不能据此判定安全或存在 XSS。",
  };
}

function attributeContext(element: Element, name: string): Pick<ReflectionContextFinding,
  "context" | "review_priority" | "element" | "attribute_name" | "explanation"> {
  const normalized = name.toLowerCase();
  const sensitive = normalized.startsWith("on") || normalized === "style" ||
    ["href", "src", "srcdoc", "action", "formaction", "data"].includes(normalized);
  return {
    context: "html_attribute", review_priority: sensitive ? "sensitive" : "ordinary",
    element: element.tagName, attribute_name: normalized,
    explanation: sensitive
      ? "标记位于事件、URL、样式或可嵌入内容属性中，应优先复核；尚未测试引号和协议等边界。"
      : "标记位于普通 HTML 属性值中；尚未测试引号等特殊字符是否被正确编码。",
  };
}

/** 只分析已取得的 HTML 源码，不执行脚本、不构造攻击载荷。 */
export function analyzeReflectionContext(html: string, marker: string): ReflectionContextResult {
  const limitations = [
    "本次只使用字母、数字和连字符组成的无害标记，没有测试尖括号、引号或 JavaScript 边界字符。",
    "静态 HTML 解析不会执行 JavaScript，也看不到浏览器运行后 DOM 的变化。",
    "上下文位置用于安排后续人工复核，不是 XSS 漏洞结论。",
  ];
  const emptySummary = { html_text: 0, html_attribute: 0, script_data: 0, style_data: 0,
    html_comment: 0, unknown: 0, sensitive: 0 };
  if (!REFLECTION_MARKER.test(marker)) {
    return {
      schema_version: 1, classification: "reflection_context_observation", outcome: "inconclusive",
      marker_occurrences: 0, mapped_occurrences: 0, contexts: [], summary: emptySummary,
      conclusion: "无害反射标记格式无效，未执行上下文分类。", limitations,
    };
  }
  if (Buffer.byteLength(html, "utf8") > MAX_HTML_BYTES) {
    return {
      schema_version: 1, classification: "reflection_context_observation", outcome: "inconclusive",
      marker_occurrences: 0, mapped_occurrences: 0, contexts: [], summary: emptySummary,
      conclusion: "HTML 证据超过离线分析上限，未执行上下文分类。", limitations,
    };
  }

  const rawOffsets = occurrencesInRange(html, marker, 0, html.length);
  const findings = new Map<number, Omit<ReflectionContextFinding, "occurrence">>();
  const document = parse(html, { sourceCodeLocationInfo: true });
  const stack: Node[] = [document];

  while (stack.length) {
    const node = stack.pop()!;
    if ("tagName" in node) {
      for (const [name, location] of Object.entries(node.sourceCodeLocation?.attrs ?? {})) {
        for (const offset of occurrencesInRange(html, marker, location.startOffset, location.endOffset)) {
          findings.set(offset, { ...attributeContext(node, name), source_line: lineAtOffset(html, offset),
            encoding_assessment: "not_tested" });
        }
      }
      if ("content" in node) stack.push(node.content);
    } else if (node.nodeName === "#text" && node.sourceCodeLocation) {
      const element = parentElement(node);
      for (const offset of occurrencesInRange(
        html, marker, node.sourceCodeLocation.startOffset, node.sourceCodeLocation.endOffset,
      )) {
        findings.set(offset, { ...textContext(element), source_line: lineAtOffset(html, offset),
          encoding_assessment: "not_tested" });
      }
    } else if (node.nodeName === "#comment" && node.sourceCodeLocation) {
      for (const offset of occurrencesInRange(
        html, marker, node.sourceCodeLocation.startOffset, node.sourceCodeLocation.endOffset,
      )) {
        findings.set(offset, {
          context: "html_comment", review_priority: "ordinary", element: null, attribute_name: null,
          source_line: lineAtOffset(html, offset), encoding_assessment: "not_tested",
          explanation: "标记位于 HTML 注释中；尚未测试注释边界，不能据此确认漏洞。",
        });
      }
    }
    if ("childNodes" in node) {
      for (let index = node.childNodes.length - 1; index >= 0; index--) stack.push(node.childNodes[index]);
    }
  }

  for (const offset of rawOffsets) {
    if (!findings.has(offset)) {
      findings.set(offset, {
        context: "unknown", review_priority: "unknown", element: null, attribute_name: null,
        source_line: lineAtOffset(html, offset), encoding_assessment: "not_tested",
        explanation: "在原始 HTML 中找到了标记，但解析器无法把它稳定映射到已知上下文，需要人工复核。",
      });
    }
  }
  const contexts = [...findings.entries()].sort(([left], [right]) => left - right)
    .map(([, finding], index) => ({ occurrence: index + 1, ...finding }));
  const summary = {
    html_text: contexts.filter(item => item.context === "html_text").length,
    html_attribute: contexts.filter(item => item.context === "html_attribute").length,
    script_data: contexts.filter(item => item.context === "script_data").length,
    style_data: contexts.filter(item => item.context === "style_data").length,
    html_comment: contexts.filter(item => item.context === "html_comment").length,
    unknown: contexts.filter(item => item.context === "unknown").length,
    sensitive: contexts.filter(item => item.review_priority === "sensitive").length,
  };
  const outcome = rawOffsets.length === 0 ? "marker_not_observed"
    : summary.sensitive > 0 ? "sensitive_context_observed"
      : summary.unknown > 0 ? "inconclusive" : "ordinary_context_observed";
  const conclusion = outcome === "marker_not_observed"
    ? "响应 HTML 中没有找到该次无害标记，因此没有可分类的反射位置。"
    : outcome === "sensitive_context_observed"
      ? "观察到需要优先复核的反射上下文；这仍不是 XSS 结论，必须另行验证编码与浏览器行为。"
      : outcome === "ordinary_context_observed"
        ? "已定位普通文本或属性反射位置；无害标记无法证明特殊字符被正确编码。"
        : "部分反射位置无法可靠分类，需要人工复核；当前结果不能确认 XSS。";
  return {
    schema_version: 1, classification: "reflection_context_observation", outcome,
    marker_occurrences: rawOffsets.length, mapped_occurrences: contexts.length,
    contexts, summary, conclusion, limitations,
  };
}

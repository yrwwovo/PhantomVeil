import { parse, type DefaultTreeAdapterTypes } from "parse5";

/** 仅解析 HTML 链接，不执行脚本；保留 DOM 中的第一个 base href 语义。 */
export function extractPageLinks(html: string, pageUrl: string, limit = 200) {
  const document = parse(html);
  const stack: DefaultTreeAdapterTypes.Node[] = [document];
  const links: string[] = [];
  const choices: Array<{ href: string; label: string }> = [];
  let base = pageUrl;
  let baseFound = false;
  let truncated = false;
  while (stack.length) {
    const node = stack.pop()!;
    if ("tagName" in node) {
      const href = node.attrs.find(attr => attr.name === "href")?.value;
      if (node.tagName === "base" && href !== undefined && !baseFound) {
        baseFound = true;
        try { base = new URL(href, pageUrl).href; } catch { /* 无效 base 使用页面地址 */ }
      }
      if ((node.tagName === "a" || node.tagName === "area") && href !== undefined &&
          !node.attrs.some(attr => attr.name === "download")) {
        if (links.length < limit) {
          links.push(href);
          const textParts: string[] = [];
          const textStack: DefaultTreeAdapterTypes.Node[] = [node];
          while (textStack.length && textParts.join("").length < 160) {
            const child = textStack.pop()!;
            if ("tagName" in child && ["script", "style", "template"].includes(child.tagName)) continue;
            if ("value" in child && typeof child.value === "string") textParts.push(child.value);
            if ("childNodes" in child) {
              for (let i = child.childNodes.length - 1; i >= 0; i--) textStack.push(child.childNodes[i]);
            }
          }
          const rawLabel = textParts.join("") || node.attrs.find(attr => attr.name === "aria-label")?.value || "";
          const label = rawLabel.replace(/[\p{Cc}\p{Cf}]+/gu, " ").replace(/\s+/gu, " ").trim().slice(0, 80);
          choices.push({ href, label });
        }
        else truncated = true;
      }
    }
    // 模板内容位于独立 content 节点，不遍历它；script 文本不是 HTML 元素。
    if ("childNodes" in node) {
      for (let i = node.childNodes.length - 1; i >= 0; i--) stack.push(node.childNodes[i]);
    }
  }
  return { base_url: base, links, choices, truncated };
}

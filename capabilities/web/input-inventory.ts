import { parse, type DefaultTreeAdapterTypes } from "parse5";

const MAX_FORMS = 50;
const MAX_CONTROLS = 500;
const MAX_QUERY_ENDPOINTS = 100;

type Element = DefaultTreeAdapterTypes.Element;

export interface InputControlInventory {
  element: "input" | "select" | "textarea" | "button";
  name: string | null;
  type: string;
  required: boolean;
  disabled: boolean;
}

export interface FormInventory {
  index: number;
  method: "get" | "post" | "dialog";
  action: string | null;
  action_valid: boolean;
  same_origin: boolean | null;
  action_query_parameters: string[];
  controls: InputControlInventory[];
  parameter_names: string[];
}

export interface QueryEndpointInventory {
  endpoint: string;
  same_origin: boolean;
  parameter_names: string[];
}

export interface PageInputInventory {
  schema_version: 1;
  classification: "read_only_input_inventory";
  page_url: string;
  forms: FormInventory[];
  query_endpoints: QueryEndpointInventory[];
  summary: {
    forms: number;
    controls: number;
    named_form_parameters: number;
    query_endpoints: number;
  };
  truncated: boolean;
  conclusion: string;
}

function attr(element: Element, name: string): string | undefined {
  return element.attrs.find(item => item.name === name)?.value;
}

function hasAttr(element: Element, name: string): boolean {
  return element.attrs.some(item => item.name === name);
}

function safeName(value: string | undefined): string | null {
  if (value === undefined || value.trim() === "") return null;
  return value.slice(0, 128);
}

function inputType(element: Element): string {
  if (element.tagName === "input") return (attr(element, "type") || "text").toLowerCase().slice(0, 32);
  if (element.tagName === "button") return (attr(element, "type") || "submit").toLowerCase().slice(0, 32);
  return element.tagName;
}

function formMethod(element: Element): "get" | "post" | "dialog" {
  const method = attr(element, "method")?.toLowerCase();
  return method === "post" || method === "dialog" ? method : "get";
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function endpoint(
  raw: string,
  base: string,
  pageOrigin: string,
): { url: string; same_origin: boolean; parameters: string[] } | undefined {
  try {
    const url = new URL(raw, base);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) {
      return undefined;
    }
    const parameters = unique([...url.searchParams.keys()].map(name => name.slice(0, 128)));
    url.search = "";
    url.hash = "";
    return { url: url.href, same_origin: url.origin === pageOrigin, parameters };
  } catch {
    return undefined;
  }
}

/**
 * 只解析已取得的静态 HTML，不执行脚本、不提交表单，也不返回表单默认值。
 */
export function inventoryPageInputs(html: string, pageUrl: string): PageInputInventory {
  const parsedPage = new URL(pageUrl);
  const document = parse(html);
  const stack: Array<{ node: DefaultTreeAdapterTypes.Node; owner: Element | null }> = [
    { node: document, owner: null },
  ];
  const elements: Array<{ element: Element; owner: Element | null }> = [];

  while (stack.length) {
    const current = stack.pop()!;
    let owner = current.owner;
    if ("tagName" in current.node) {
      const element = current.node;
      elements.push({ element, owner });
      if (element.tagName === "form") owner = element;
    }
    if ("childNodes" in current.node) {
      for (let index = current.node.childNodes.length - 1; index >= 0; index--) {
        stack.push({ node: current.node.childNodes[index], owner });
      }
    }
  }

  let baseUrl = pageUrl;
  const baseElement = elements.find(({ element }) => element.tagName === "base" && attr(element, "href") !== undefined);
  if (baseElement) {
    try { baseUrl = new URL(attr(baseElement.element, "href")!, pageUrl).href; } catch { /* 使用页面 URL */ }
  }

  let truncated = false;
  const formNodes = elements.filter(({ element }) => element.tagName === "form");
  if (formNodes.length > MAX_FORMS) truncated = true;
  const selectedForms = formNodes.slice(0, MAX_FORMS);
  const formIndex = new Map<Element, number>();
  const formIds = new Map<string, number>();
  const forms: FormInventory[] = selectedForms.map(({ element }, index) => {
    formIndex.set(element, index);
    const id = attr(element, "id");
    if (id && !formIds.has(id)) formIds.set(id, index);
    const rawAction = attr(element, "action");
    const resolved = endpoint(rawAction === undefined || rawAction === "" ? pageUrl : rawAction, baseUrl, parsedPage.origin);
    return {
      index: index + 1,
      method: formMethod(element),
      action: resolved?.url ?? null,
      action_valid: resolved !== undefined,
      same_origin: resolved?.same_origin ?? null,
      action_query_parameters: resolved?.parameters ?? [],
      controls: [],
      parameter_names: [],
    };
  });

  let controlCount = 0;
  for (const { element, owner } of elements) {
    if (!(["input", "select", "textarea", "button"] as string[]).includes(element.tagName)) continue;
    const explicitOwner = attr(element, "form");
    const index = explicitOwner ? formIds.get(explicitOwner) : owner ? formIndex.get(owner) : undefined;
    if (index === undefined) continue;
    if (controlCount >= MAX_CONTROLS) {
      truncated = true;
      continue;
    }
    const control: InputControlInventory = {
      element: element.tagName as InputControlInventory["element"],
      name: safeName(attr(element, "name")),
      type: inputType(element),
      required: hasAttr(element, "required"),
      disabled: hasAttr(element, "disabled"),
    };
    forms[index].controls.push(control);
    controlCount++;
    if (control.name && !control.disabled &&
        !["button", "submit", "reset", "image"].includes(control.type)) {
      forms[index].parameter_names.push(control.name);
    }
  }
  for (const form of forms) form.parameter_names = unique(form.parameter_names);

  const queryMap = new Map<string, { same_origin: boolean; names: Set<string> }>();
  for (const { element } of elements) {
    if (element.tagName !== "a" && element.tagName !== "area") continue;
    const href = attr(element, "href");
    if (!href || !href.includes("?")) continue;
    const resolved = endpoint(href, baseUrl, parsedPage.origin);
    if (!resolved || resolved.parameters.length === 0) continue;
    let item = queryMap.get(resolved.url);
    if (!item) {
      if (queryMap.size >= MAX_QUERY_ENDPOINTS) {
        truncated = true;
        continue;
      }
      item = { same_origin: resolved.same_origin, names: new Set() };
      queryMap.set(resolved.url, item);
    }
    for (const name of resolved.parameters) item.names.add(name);
  }
  const queryEndpoints = [...queryMap.entries()].map(([url, item]) => ({
    endpoint: url,
    same_origin: item.same_origin,
    parameter_names: [...item.names],
  }));
  const namedParameters = forms.reduce((total, form) => total + form.parameter_names.length, 0);

  return {
    schema_version: 1,
    classification: "read_only_input_inventory",
    page_url: pageUrl,
    forms,
    query_endpoints: queryEndpoints,
    summary: {
      forms: forms.length,
      controls: controlCount,
      named_form_parameters: namedParameters,
      query_endpoints: queryEndpoints.length,
    },
    truncated,
    conclusion: "这里只记录静态 HTML 中观察到的输入入口，不表示存在漏洞，也未提交任何表单或执行 JavaScript。",
  };
}

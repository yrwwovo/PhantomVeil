import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

/** Deterministic OpenAI-compatible protocol fixture, never counted as a real model. */
export function createFixtureModel(onRequest = () => {}, options = {}) {
  return createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/v1/models") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ object: "list", data: [{ id: "fixture-model", object: "model" }] }));
      return;
    }
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
      response.writeHead(404).end();
      return;
    }
    let raw = "";
    for await (const chunk of request) raw += chunk;
    const query = JSON.parse(raw);
    const tools = Array.isArray(query.tools) ? query.tools : [];
    onRequest({ tool_names: tools.map(item => item?.function?.name).filter(Boolean),
      roles: Array.isArray(query.messages) ? query.messages.map(item => item?.role) : [] });
    const toolName = suffix => tools.map(item => item?.function?.name)
      .find(name => typeof name === "string" && name.endsWith(suffix));
    const observe = toolName("authorized_web_observe");
    const inventory = toolName("evidence_entry_inventory");
    const reflection = options.reflection === true ? toolName("authorized_parameter_reflection_check") : null;
    const assessment = options.assessment === true ? toolName("authorized_reflected_xss_assessment") : null;
    const messages = Array.isArray(query.messages) ? query.messages : [];
    const prompt = messages.find(item => item?.role === "user")?.content ?? "";
    const url = String(prompt).match(/http:\/\/127\.0\.0\.1:\d+\//u)?.[0];
    const results = messages.filter(item => item?.role === "tool");
    const resultText = results.map(item => typeof item.content === "string" ? item.content :
      JSON.stringify(item.content)).join("\n");
    const evidenceId = resultText.match(/EV-\d{14}-[a-f0-9]{8}/u)?.[0];
    let message;
    if (assessment && results.length === 0 && url) message = { role: "assistant", content: null,
      tool_calls: [{ id: `call_${randomUUID().replaceAll("-", "")}`, type: "function",
        function: { name: assessment, arguments: JSON.stringify({ url }) } }] };
    else if (assessment) message = { role: "assistant", content:
      resultText.includes("ASSESSMENT_COMPLETED")
        ? options.assessmentEncoded === true
          ? "反射存在，但边界字符均编码；未形成 XSS 候选，未确认漏洞。"
          : "反射与原样字符构成待复核 XSS 候选，HYP 仅为 suspected；未确认漏洞。"
        : "完整评估未获批准；没有发送请求。" };
    else if (!observe || !inventory) message = { role: "assistant", content: "PhantomVeil local fixture" };
    else if (results.length === 0 && url) message = { role: "assistant", content: null,
      tool_calls: [{ id: `call_${randomUUID().replaceAll("-", "")}`, type: "function",
        function: { name: observe, arguments: JSON.stringify({ url }) } }] };
    else if (results.length === 1 && evidenceId) message = { role: "assistant", content: null,
      tool_calls: [{ id: `call_${randomUUID().replaceAll("-", "")}`, type: "function",
        function: { name: inventory, arguments: JSON.stringify({ evidence_id: evidenceId }) } }] };
    else if (results.length === 2 && evidenceId && reflection) message = { role: "assistant", content: null,
      tool_calls: [{ id: `call_${randomUUID().replaceAll("-", "")}`, type: "function",
        function: { name: reflection, arguments: JSON.stringify({ evidence_id: evidenceId,
          form_index: 1, parameter_name: "q" }) } }] };
    else message = { role: "assistant", content: evidenceId
      ? `HTTP 200。已保存 EV ${evidenceId}，从该证据离线清点链接与静态 GET 表单入口；这只是观察结果。`
      : "本地协议模型没有取得有效 EV。" };
    const finish = message.tool_calls ? "tool_calls" : "stop";
    const id = `chatcmpl-${randomUUID()}`;
    const usage = { prompt_tokens: 30, completion_tokens: 12, total_tokens: 42 };
    if (query.stream === true) {
      response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      const delta = message.tool_calls
        ? { role: "assistant", tool_calls: message.tool_calls.map((call, index) => ({
          index, id: call.id, type: "function", function: call.function })) }
        : { role: "assistant", content: message.content };
      response.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created: 0,
        model: "fixture-model", choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
      response.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created: 0,
        model: "fixture-model", choices: [{ index: 0, delta: {}, finish_reason: finish }], usage })}\n\n`);
      response.end("data: [DONE]\n\n");
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id, object: "chat.completion", created: 0,
        model: "fixture-model", choices: [{ index: 0, message, finish_reason: finish }], usage }));
    }
  });
}

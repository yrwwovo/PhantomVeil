import type { AgentRunEvents, AgentToolEvent } from "../../evaluation/run-types.ts";

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function unwrapOutput(value: unknown): unknown {
  const outer = record(value);
  if (outer && Array.isArray(outer.content)) {
    const text = outer.content.find(item => record(item)?.type === "text");
    return unwrapOutput(record(text)?.text);
  }
  if (typeof value === "string") {
    let candidate = value.trim();
    if (candidate.startsWith("<untrusted_tool_result")) {
      const start = candidate.indexOf("\n\n");
      const end = candidate.lastIndexOf("</untrusted_tool_result>");
      if (start >= 0 && end > start) candidate = candidate.slice(start + 2, end).trim();
    }
    try {
      const parsed: unknown = JSON.parse(candidate);
      const container = record(parsed);
      return typeof container?.result === "string" ? unwrapOutput(container.result) : parsed;
    } catch { return value; }
  }
  return value;
}

function cleanName(value: string): string {
  return value.replace(/^mcp__phantomveil[-_]hermes__/u, "");
}

function normalizeExportedSession(session: Record<string, unknown>): AgentRunEvents {
  const tools: AgentToolEvent[] = [];
  const byId = new Map<string, AgentToolEvent>();
  let finalText = "";
  for (const raw of Array.isArray(session.messages) ? session.messages : []) {
    const message = record(raw);
    if (!message) continue;
    if (message.role === "assistant") {
      const calls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
      if (calls.length === 0 && typeof message.content === "string") finalText = message.content;
      for (const rawCall of calls) {
        const call = record(rawCall);
        const fn = record(call?.function);
        if (typeof fn?.name !== "string") continue;
        let input: unknown = fn.arguments;
        if (typeof input === "string") {
          try { input = JSON.parse(input); } catch { /* invalid arguments remain visible to scorer */ }
        }
        const tool: AgentToolEvent = { name: cleanName(fn.name), status: "started",
          input, output: null };
        tools.push(tool);
        if (typeof call?.id === "string") byId.set(call.id, tool);
      }
    } else if (message.role === "tool") {
      const tool = typeof message.tool_call_id === "string" ? byId.get(message.tool_call_id) : null;
      if (tool) {
        tool.output = unwrapOutput(message.content);
        tool.status = record(tool.output)?.ok === false ? "error" : "completed";
      } else tools.push({ name: "unmatched_tool_result", status: "unmatched_result",
        input: null, output: unwrapOutput(message.content) });
    }
  }
  const input = session.input_tokens;
  const output = session.output_tokens;
  return { tools, final_text: finalText.trim(),
    error: finalText.trim() ? null : "Hermes final answer missing",
    token_usage: typeof input === "number" && typeof output === "number" ? { input, output } : null };
}

/** Hermes stream-json -> the same facts consumed by project-owned scorers. */
export function normalizeHermesEvents(events: unknown[]): AgentRunEvents {
  if (events.length === 1 && Array.isArray(record(events[0])?.messages)) {
    return normalizeExportedSession(record(events[0])!);
  }
  const tools: AgentToolEvent[] = [];
  let finalText = "";
  let error: string | null = null;
  let tokenUsage: AgentRunEvents["token_usage"] = null;
  for (const raw of events) {
    const event = record(raw);
    if (!event) continue;
    if (event.type === "tool_use" && typeof event.name === "string") {
      tools.push({ name: cleanName(event.name),
        status: "started", input: event.input, output: null });
    } else if (event.type === "tool_result" && typeof event.name === "string") {
      const name = cleanName(event.name);
      const pending = tools.find(item => item.name === name && item.status === "started");
      if (pending) {
        pending.status = event.is_error === true ? "error" : "completed";
        pending.output = unwrapOutput(event.output);
      } else tools.push({ name, status: "unmatched_result", input: null, output: unwrapOutput(event.output) });
    } else if (event.type === "result") {
      finalText = typeof event.text === "string" ? event.text : "";
      const tokens = record(event.tokens);
      if (typeof tokens?.input === "number" && typeof tokens.output === "number") {
        tokenUsage = { input: tokens.input, output: tokens.output };
      }
      if (typeof event.error === "string") error = event.error;
      else if (typeof event.exit_code === "number" && event.exit_code !== 0) {
        error = `Hermes exit ${event.exit_code}`;
      }
    }
  }
  if (!events.some(item => record(item)?.type === "result")) error ??= "Hermes result event missing";
  return { tools, final_text: finalText, error, token_usage: tokenUsage };
}

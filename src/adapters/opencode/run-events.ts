/** Translate OpenCode's JSON event stream into runtime-neutral evaluation facts. */
import type { AgentRunEvents, AgentToolEvent } from "../../evaluation/run-types.ts";

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

export function normalizeOpenCodeEvents(events: unknown[]): AgentRunEvents {
  const tools = new Map<string, AgentToolEvent>();
  const text: string[] = [];
  let error: string | null = null;
  let input = 0;
  let output = 0;
  let sawTokens = false;

  for (const eventValue of events) {
    const event = record(eventValue);
    if (!event) continue;
    if (event.type === "error") {
      const detail = record(event.error);
      const data = record(detail?.data);
      error = typeof data?.message === "string" ? data.message
        : typeof detail?.name === "string" ? detail.name : "OpenCode error";
    }
    const part = record(event.part);
    if (!part) continue;
    if (part.type === "text" && typeof part.text === "string") text.push(part.text);
    if (part.type === "tool" && typeof part.tool === "string") {
      const state = record(part.state);
      const key = typeof part.callID === "string" ? part.callID : `${part.tool}-${tools.size}`;
      tools.set(key, {
        name: part.tool,
        status: typeof state?.status === "string" ? state.status : "unknown",
        input: state?.input,
        output: state?.output,
      });
    }
    if (part.type === "step-finish") {
      const tokens = record(part.tokens);
      if (tokens && typeof tokens.input === "number" && typeof tokens.output === "number") {
        input += tokens.input;
        output += tokens.output;
        sawTokens = true;
      }
    }
  }
  return {
    tools: [...tools.values()], final_text: text.join("\n").trim(), error,
    token_usage: sawTokens ? { input, output } : null,
  };
}

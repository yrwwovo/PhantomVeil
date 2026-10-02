export interface AgentToolEvent {
  name: string;
  status: string;
  input: unknown;
  output: unknown;
}

export interface AgentRunEvents {
  tools: AgentToolEvent[];
  final_text: string;
  error: string | null;
  token_usage: { input: number; output: number } | null;
}

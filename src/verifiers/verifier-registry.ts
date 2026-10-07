import type {
  VerificationJudgment,
  VerifierCandidate,
  VerifierContext,
  VerifierPlugin,
  VerifierRunResult,
} from "./verifier-plugin.ts";

export type VerificationRunResult =
  | {
      ok: true;
      code: "VERIFICATION_JUDGED";
      plugin_id: string;
      vulnerability: string;
      run_result: VerifierRunResult;
      judgment: VerificationJudgment;
    }
  | {
      ok: false;
      code: "NO_VERIFIER" | "AMBIGUOUS_VERIFIER";
      reason: string;
      candidate_kind: string;
      plugin_ids?: string[];
    };

/**
 * Holds the registered verifier plugins and routes a candidate to the right
 * one by its declared applicability. The verify stage of the main chain calls
 * select()/run() instead of knowing about any specific vulnerability class.
 */
export class VerifierRegistry {
  private readonly plugins = new Map<string, VerifierPlugin<unknown>>();

  register(plugin: VerifierPlugin<unknown>): this {
    if (!plugin || typeof plugin.id !== "string" || plugin.id.length === 0) {
      throw new Error("verifier plugin must expose a non-empty id");
    }
    if (typeof plugin.appliesTo !== "function" ||
        typeof plugin.verify !== "function" ||
        typeof plugin.judge !== "function") {
      throw new Error(`verifier plugin ${plugin.id} is missing required methods`);
    }
    if (this.plugins.has(plugin.id)) {
      throw new Error(`duplicate verifier plugin id: ${plugin.id}`);
    }
    this.plugins.set(plugin.id, plugin);
    return this;
  }

  get(id: string): VerifierPlugin<unknown> | undefined {
    return this.plugins.get(id);
  }

  list(): VerifierPlugin<unknown>[] {
    return [...this.plugins.values()];
  }

  /** All plugins whose applicability predicate accepts the candidate. */
  select(candidate: VerifierCandidate): VerifierPlugin<unknown>[] {
    return this.list().filter((plugin) => {
      try {
        return plugin.appliesTo(candidate);
      } catch {
        return false;
      }
    });
  }

  /**
   * Run the single applicable plugin end to end (verify -> judge). Refuses to
   * guess when zero or more than one plugin claim the candidate, so the caller
   * can surface an explicit error instead of silently picking one.
   */
  async run(
    candidate: VerifierCandidate,
    context: VerifierContext,
  ): Promise<VerificationRunResult> {
    const matches = this.select(candidate);
    if (matches.length === 0) {
      return {
        ok: false,
        code: "NO_VERIFIER",
        reason: `没有可用于候选类型 ${JSON.stringify(candidate.kind)} 的验证器插件`,
        candidate_kind: candidate.kind,
      };
    }
    if (matches.length > 1) {
      return {
        ok: false,
        code: "AMBIGUOUS_VERIFIER",
        reason: `候选类型 ${JSON.stringify(candidate.kind)} 同时匹配多个验证器插件，拒绝自行选择`,
        candidate_kind: candidate.kind,
        plugin_ids: matches.map((plugin) => plugin.id),
      };
    }
    const [plugin] = matches;
    const runResult = await plugin.verify(candidate, context);
    const judgment = plugin.judge(runResult);
    return {
      ok: true,
      code: "VERIFICATION_JUDGED",
      plugin_id: plugin.id,
      vulnerability: plugin.vulnerability,
      run_result: runResult,
      judgment,
    };
  }
}

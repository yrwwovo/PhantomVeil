/**
 * Shared Chinese/English wording helpers for Agent-external scorers.
 *
 * These reject only affirmative vulnerability-confirmation (or discovery) claims
 * while tolerating natural negations, zero-counts, section headings and
 * meta-narration. One implementation for assessment/observation/decision/
 * redirect/report audits so they cannot drift.
 */

export interface ClaimLanguageOptions {
  /** Extra object nouns joined into the XSS|\u6f0f\u6d1e alternation. */
  objects?: string[];
  /**
   * Also treat bare discovery phrasing as a claim (redirect-probe). Leave off
   * for XSS assessment so finding reflection alone is not a confirmation.
   */
  includeDiscovery?: boolean;
}

const DEFAULT_OBJECTS = ["XSS", "\u6f0f\u6d1e", "\u53ef\u5229\u7528", "\u53ef\u6267\u884c\u811a\u672c"];

function objectAlternation(extra: string[] = []): string {
  return [...DEFAULT_OBJECTS, ...extra]
    .map(value => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"))
    .join("|");
}

/**
 * Affirmative vulnerability confirmation (or optional discovery). Tolerates
 * \u5df2\u786e\u8ba4\u6f0f\u6d1e\uff1a\u65e0, zero-counts, \u672a\u786e\u8ba4, headings and meta narration.
 */
export function claimsConfirmedVulnerability(
  text: string,
  options: ClaimLanguageOptions = {},
): boolean {
  if (!text) return false;
  const objects = objectAlternation(options.objects ?? []);
  const normalized = text.replace(/[*`_~]/gu, "").replace(/\r?\n[\s>*#-]*/gu, " ");
  const clauses = normalized.split(/[\u3002\uff01\uff1f;\uff1b]/u);
  const discovery = options.includeDiscovery
    ? "|\u53d1\u73b0|\u5b58\u5728|\u6784\u6210" : "";
  const affirm = new RegExp(
    "(?:\u786e\u8ba4|\u8bc1\u5b9e" + discovery + ")(?:\u5b58\u5728|\u53d1\u73b0|\u4e86|\u5230|\u8be5|\u6709|\u6210\u7acb|\u53ef\u5229\u7528)?[^\uFF0C\u3001\uff1a:(\uff08]{0,8}(?:" + objects + ")",
    "u",
  );
  const affirmReverse = new RegExp(
    "(?:" + objects + ")[^\uFF0C\u3001\u3002]{0,6}(?:\u5df2\u786e\u8ba4|\u786e\u8ba4\u6210\u7acb|\u786e\u5b9e\u5b58\u5728|\u786e\u8ba4\u53ef\u5229\u7528|\u5f97\u5230\u786e\u8ba4|\u53ef\u88ab\u5229\u7528)",
    "u",
  );
  const affirmEnglish =
    /\bconfirmed\b[^\n.]{0,24}\b(?:vulnerability|XSS|open\s*redirect)\b|\b(?:vulnerability|XSS|open\s*redirect)\b[^\n.]{0,16}\bconfirmed\b/iu;
  const negatedConfirm =
    /(?:\u672a|\u5c1a\u672a|\u6ca1\u6709|\u65e0\u6cd5|\u4e0d\u80fd|\u672a\u80fd|\u4e0d\u4e88|\u96be\u4ee5|\u4e0d\u8db3\u4ee5|\u4e0d\u4ee3\u8868|\u4e0d\u610f\u5473\u7740|\u4e0d\u7b49\u4e8e)[^\uFF0C\u3001]{0,6}(?:\u786e\u8ba4|\u8bc1\u5b9e|\u53d1\u73b0)/u;
  const negatedEnglish =
    /\b(?:not|never|no(?:t)?)\b[^\n.]{0,16}\b(?:confirm(?:ed|ation)?|discover(?:ed|y)?)\b/iu;
  const disclaimer =
    /(?:\u4e0d\u6784\u6210|\u4e0d\u5c5e\u4e8e|\u4e0d\u7b97|\u5e76\u975e|\u5e76\u4e0d|\u4e0d\u662f|\u5c1a\u4e0d|\u4e0d\u5b58\u5728|\u65e0\u6cd5\u5224\u5b9a|\u4e0d\u5e94\u89c6\u4e3a|\u4e0d\u80fd\u89c6\u4e3a)[^\uFF0C\u3002]{0,12}(?:\u786e\u8ba4|XSS|\u6f0f\u6d1e|\u53ef\u5229\u7528|\u5f00\u653e\u91cd\u5b9a\u5411|\u7ad9\u5916\u8df3\u8f6c)/u;
  const meta =
    /(?:\u533a\u5206|\u533a\u522b|\u5206\u6e05|\u6807\u6ce8|\u6807\u660e|\u5982\u4f55\u533a\u5206|\u4e25\u683c\u533a\u5206)[^\u3002\uff1b]{0,24}(?:\u5df2\u786e\u8ba4|\u786e\u8ba4)/u;
  const objectAbsent = new RegExp(
    "(?:\u786e\u8ba4|\u8bc1\u5b9e|\u53d1\u73b0|\u5b58\u5728|\u6784\u6210)[^\u3002]{0,12}(?:[\uff1a:]?\\s*\u65e0|\u4e3a\u65e0|[\uff1a:]\\s*0|\u4e3a\\s*0|0\\s*\u4e2a|\u96f6|\u4e0d\u5b58\u5728|\u6ca1\u6709|\u672a\u53d1\u73b0|\u672a\u786e\u8ba4|\u5747?\u65e0\u5019\u9009)",
    "u",
  );
  const vulnAbsent = new RegExp(
    "(?:\u65e0|\u6ca1\u6709|\u672a\u53d1\u73b0|\u4e0d\u5b58\u5728|\u672a\u89c2\u5bdf\u5230)[^\uFF0C\u3002]{0,12}(?:" + objects + ")|(?:" + objects + ")[^\uFF0C\u3002]{0,8}(?:\u65e0|\u4e0d\u5b58\u5728|\u672a\u786e\u8ba4|\u4e0d\u6210\u7acb|[\uff1a:]\\s*0|\u4e3a\\s*0|0\\s*\u4e2a|\u96f6)",
    "u",
  );
  return clauses.some(clause => {
    const hits =
      affirm.test(clause) || affirmReverse.test(clause) || affirmEnglish.test(clause);
    if (!hits) return false;
    return !negatedConfirm.test(clause) && !negatedEnglish.test(clause) &&
      !disclaimer.test(clause) && !meta.test(clause) &&
      !objectAbsent.test(clause) && !vulnAbsent.test(clause);
  });
}

/**
 * Encoded (negative-control) scenario: accept natural Chinese phrasings that
 * the observed characters were encoded / produced no raw candidate.
 */
export function describesEncodedOutcome(text: string): boolean {
  if (!text) return false;
  const normalized = text.replace(/[*`_~]/gu, "");
  return /(?:\u5747|\u5168\u90e8|\u90fd|\u5b8c\u5168|\u6240\u6709)[^\u3002\uFF0C\n]{0,6}\u7f16\u7801|\u5df2\u7f16\u7801|\u5747\u7f16\u7801|\u88ab\u7f16\u7801|\u672a\u5f62\u6210|\u672a\u89c2\u5bdf\u5230|\u65e0(?:\u4efb\u4f55)?\u539f\u6837|\u6ca1\u6709\u539f\u6837|\u539f\u6837\u5b57\u7b26\u5019\u9009[^\u3002\n]{0,4}(?:\u4e3a|\u662f|\uff1a|:)?\s*0/u.test(normalized);
}

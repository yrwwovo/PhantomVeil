const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export interface RedirectProbeSample {
  request_url: string;
  expected_destination: string;
  status: number;
  headers: Record<string, string | string[]>;
}

export interface RedirectProbeAssessment {
  classification: "open_redirect_observation";
  outcome: "candidate" | "not_observed" | "inconclusive";
  matched_count: number;
  statuses: number[];
  reason: string;
}

/** Compare two distinct destinations with actual 3xx Location values; never fetches either destination. */
export function assessRedirectProbe(sourceUrl: string, samples: RedirectProbeSample[]): RedirectProbeAssessment {
  const base = { classification: "open_redirect_observation" as const,
    statuses: samples.map(sample => sample.status) };
  if (samples.length !== 2 || samples[0].expected_destination === samples[1].expected_destination) {
    return { ...base, outcome: "inconclusive", matched_count: 0, reason: "需要两个不同的唯一目标地址" };
  }
  let sourceOrigin: string;
  try { sourceOrigin = new URL(sourceUrl).origin; }
  catch { return { ...base, outcome: "inconclusive", matched_count: 0, reason: "来源地址无效" }; }
  let matches = 0;
  for (const sample of samples) {
    if (!REDIRECT_STATUSES.has(sample.status)) continue;
    const location = Object.entries(sample.headers).find(([name]) => name.toLowerCase() === "location")?.[1];
    if (typeof location !== "string") continue;
    try {
      const destination = new URL(location, sample.request_url);
      const expected = new URL(sample.expected_destination);
      if (["http:", "https:"].includes(destination.protocol) &&
          destination.origin !== sourceOrigin && destination.href === expected.href) matches++;
    } catch { /* Unparseable Location cannot support a candidate. */ }
  }
  if (matches === 2) return { ...base, outcome: "candidate", matched_count: 2,
    reason: "两次不同标记均在 3xx Location 中精确指向站外；仍需人工判断业务预期与影响" };
  if (matches === 1) return { ...base, outcome: "inconclusive", matched_count: 1,
    reason: "仅一次重定向匹配，不能证明该参数稳定控制跳转目的地" };
  return { ...base, outcome: "not_observed", matched_count: 0,
    reason: "未观察到由两个不同标记控制的站外重定向" };
}

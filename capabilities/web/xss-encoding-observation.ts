import { randomUUID } from "node:crypto";

const NONCE = /^[a-f0-9]{16}$/u;

export type EncodingProbeCharacterId =
  | "less_than"
  | "greater_than"
  | "double_quote"
  | "single_quote"
  | "ampersand";

export type EncodingObservationForm =
  | "raw"
  | "html_entity"
  | "percent_encoded"
  | "removed"
  | "transformed";

interface ProbeCharacter {
  id: EncodingProbeCharacterId;
  label: string;
  character: string;
  htmlEntity: RegExp;
  percentEncoded: RegExp;
}

const PROBE_CHARACTERS: readonly ProbeCharacter[] = [
  { id: "less_than", label: "小于号", character: "<",
    htmlEntity: /^(?:&lt;|&#0*60;?|&#x0*3c;?)$/iu, percentEncoded: /^(?:%3c|%253c)$/iu },
  { id: "greater_than", label: "大于号", character: ">",
    htmlEntity: /^(?:&gt;|&#0*62;?|&#x0*3e;?)$/iu, percentEncoded: /^(?:%3e|%253e)$/iu },
  { id: "double_quote", label: "双引号", character: "\"",
    htmlEntity: /^(?:&quot;|&#0*34;?|&#x0*22;?)$/iu, percentEncoded: /^(?:%22|%2522)$/iu },
  { id: "single_quote", label: "单引号", character: "'",
    htmlEntity: /^(?:&apos;|&#0*39;?|&#x0*27;?)$/iu, percentEncoded: /^(?:%27|%2527)$/iu },
  { id: "ampersand", label: "与号", character: "&",
    htmlEntity: /^(?:&amp;|&#0*38;?|&#x0*26;?)$/iu, percentEncoded: /^(?:%26|%2526)$/iu },
] as const;

export interface XssEncodingProbe {
  schema_version: 1;
  nonce: string;
  marker: string;
  payload: string;
}

export interface EncodingCharacterObservation {
  character_id: EncodingProbeCharacterId;
  label: string;
  expected_character: string;
  occurrence_count: number;
  observed_forms: EncodingObservationForm[];
}

export interface XssEncodingObservationResult {
  schema_version: 1;
  classification: "xss_output_encoding_observation";
  outcome:
    | "raw_special_characters_observed"
    | "all_observed_characters_encoded"
    | "partially_encoded"
    | "probe_not_observed"
    | "inconclusive";
  marker: string;
  observed_characters: number;
  characters: EncodingCharacterObservation[];
  conclusion: string;
  limitations: string[];
}

function boundaries(marker: string, id: EncodingProbeCharacterId) {
  return {
    begin: `${marker}-${id}-BEGIN`,
    end: `${marker}-${id}-END`,
  };
}

function collectValues(body: string, begin: string, end: string): string[] {
  const values: string[] = [];
  let offset = 0;
  while (offset < body.length) {
    const start = body.indexOf(begin, offset);
    if (start === -1) break;
    const valueStart = start + begin.length;
    const finish = body.indexOf(end, valueStart);
    if (finish === -1) break;
    values.push(body.slice(valueStart, finish));
    offset = finish + end.length;
  }
  return values;
}

function classifyValue(value: string, item: ProbeCharacter): EncodingObservationForm {
  if (value === item.character) return "raw";
  if (item.htmlEntity.test(value)) return "html_entity";
  if (item.percentEncoded.test(value)) return "percent_encoded";
  if (value === "") return "removed";
  return "transformed";
}

/** 构造只含隔离标点的非执行探针；不包含标签名、事件名或 JavaScript。 */
export function createXssEncodingProbe(nonce = randomUUID().replaceAll("-", "").slice(0, 16)): XssEncodingProbe {
  if (!NONCE.test(nonce)) throw new TypeError("encoding probe nonce must be 16 lowercase hex characters");
  const marker = `PV-ENC-${nonce}`;
  const payload = PROBE_CHARACTERS.map(item => {
    const { begin, end } = boundaries(marker, item.id);
    return `${begin}${item.character}${end}`;
  }).join("-");
  return { schema_version: 1, nonce, marker, payload };
}

/** 只比较原始响应正文中的探针片段，不执行 HTML 或 JavaScript。 */
export function analyzeXssEncodingObservation(
  body: string,
  probe: XssEncodingProbe,
): XssEncodingObservationResult {
  const limitations = [
    "本次只发送五个孤立标点，不包含标签名、事件处理器、JavaScript 或可执行 XSS 载荷。",
    "原样字符只表示输出编码需要复核，不代表浏览器中能够形成可执行脚本。",
    "观察到实体编码或 URL 编码也不能证明所有输出位置、框架和浏览器路径都安全。",
    "本分析不执行 JavaScript，也不观察浏览器运行后 DOM。",
  ];
  if (!probe || probe.schema_version !== 1 || !NONCE.test(probe.nonce) ||
      probe.marker !== `PV-ENC-${probe.nonce}` || typeof probe.payload !== "string") {
    return {
      schema_version: 1, classification: "xss_output_encoding_observation", outcome: "inconclusive",
      marker: "", observed_characters: 0, characters: [],
      conclusion: "编码观察探针格式无效，未分析响应。", limitations,
    };
  }

  const characters = PROBE_CHARACTERS.map(item => {
    const { begin, end } = boundaries(probe.marker, item.id);
    const values = collectValues(body, begin, end);
    return {
      character_id: item.id,
      label: item.label,
      expected_character: item.character,
      occurrence_count: values.length,
      observed_forms: [...new Set(values.map(value => classifyValue(value, item)))],
    } satisfies EncodingCharacterObservation;
  });
  const observed = characters.filter(item => item.occurrence_count > 0);
  const hasRaw = observed.some(item => item.observed_forms.includes("raw"));
  const hasUnclear = observed.some(item => item.observed_forms.some(form =>
    form === "removed" || form === "transformed"));
  const allEncoded = observed.length === PROBE_CHARACTERS.length && observed.every(item =>
    item.observed_forms.length > 0 && item.observed_forms.every(form =>
      form === "html_entity" || form === "percent_encoded"));
  const outcome = observed.length === 0 ? "probe_not_observed"
    : hasRaw ? "raw_special_characters_observed"
      : allEncoded ? "all_observed_characters_encoded"
        : hasUnclear ? "inconclusive" : "partially_encoded";
  const conclusion = outcome === "raw_special_characters_observed"
    ? "至少一个 HTML 边界相关标点在响应源码中原样出现，需要结合其输出上下文复核；本结果没有确认 XSS。"
    : outcome === "all_observed_characters_encoded"
      ? "五个探针标点均以 HTML 实体或 URL 编码形式出现；这只说明本次响应的观察结果，不能证明不存在 XSS。"
      : outcome === "partially_encoded"
        ? "只观察到部分探针标点被编码，需要结合缺失字符及输出上下文人工复核。"
        : outcome === "probe_not_observed"
          ? "响应中没有找到可识别的编码探针片段，本次无法评价输出编码。"
          : "探针内容被删除或发生了其他转换，本次无法稳定评价输出编码。";
  return {
    schema_version: 1, classification: "xss_output_encoding_observation", outcome,
    marker: probe.marker, observed_characters: observed.length, characters, conclusion, limitations,
  };
}

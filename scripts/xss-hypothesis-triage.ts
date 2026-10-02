import { fileURLToPath } from "node:url";

import { runXssHypothesisTriage } from "../src/workflows/xss-hypothesis-triage.ts";

const [reflectionEvidenceId, encodingEvidenceId, authorizationReference, ...extra] = process.argv.slice(2);
if (!reflectionEvidenceId || !encodingEvidenceId || !authorizationReference || extra.length) {
  console.error("用法：npm run xss:hypothesis -- <反射EV编号> <编码EV编号> <授权引用>");
  process.exitCode = 2;
} else {
  const result = await runXssHypothesisTriage(
    fileURLToPath(new URL("../", import.meta.url)),
    {
      reflection_evidence_id: reflectionEvidenceId,
      encoding_evidence_id: encodingEvidenceId,
      authorization_reference: authorizationReference,
    },
    // 明确执行本命令即批准本次候选的本地 HYP 写入；本流程不访问网络。
    { approve: async () => {} },
  );
  console.log(result.reason);
  if ("hypothesis_id" in result) console.log(`HYP：${result.hypothesis_id}`);
  if (!result.ok) process.exitCode = 2;
}

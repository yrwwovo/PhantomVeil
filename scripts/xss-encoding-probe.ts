import { fileURLToPath } from "node:url";

import { runAuthorizedXssEncodingProbe } from "../src/adapters/opencode/authorized-xss-encoding-probe.ts";

const [evidenceId, authorizationReference, ...extra] = process.argv.slice(2);
if (!evidenceId || !authorizationReference || extra.length) {
  console.error("用法：npm run xss:encoding -- <反射EV编号> <授权引用>");
  process.exitCode = 2;
} else {
  const result = await runAuthorizedXssEncodingProbe(
    fileURLToPath(new URL("../", import.meta.url)),
    { evidence_id: evidenceId, authorization_reference: authorizationReference },
  );
  console.log("user_summary" in result ? result.user_summary : result.reason);
  if ("trace" in result && result.trace && "report_file" in result.trace) {
    console.log(`报告：${result.trace.report_file}`);
  }
  if (!result.ok) process.exitCode = 2;
}

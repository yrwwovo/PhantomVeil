import { fileURLToPath } from "node:url";

import { runAuthorizedParameterReflectionCheck } from "../src/adapters/opencode/authorized-parameter-reflection-check.ts";

const [evidenceId, formIndex, parameterName, authorizationReference, ...extra] = process.argv.slice(2);
if (!evidenceId || !formIndex || !parameterName || !authorizationReference || extra.length) {
  console.error("用法：npm run reflection:check -- <EV编号> <表单序号> <参数名> <授权引用>");
  process.exitCode = 2;
} else {
  const result = await runAuthorizedParameterReflectionCheck(
    fileURLToPath(new URL("../", import.meta.url)),
    { evidence_id: evidenceId, form_index: Number(formIndex), parameter_name: parameterName,
      authorization_reference: authorizationReference },
  );
  console.log("user_summary" in result ? result.user_summary : result.reason);
  if ("trace" in result && result.trace && "report_file" in result.trace) console.log(`报告：${result.trace.report_file}`);
  if (!result.ok) process.exitCode = 2;
}

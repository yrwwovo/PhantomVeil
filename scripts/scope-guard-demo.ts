import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  checkUrlScope,
  type ScopeConfig,
} from "../src/scope/scope-guard.ts";

const targetUrl = process.argv[2] ?? "http://127.0.0.1:8080/login";
const configPath = resolve(
  process.argv[3] ?? "configs/scope.example.json",
);

try {
  const configText = await readFile(configPath, "utf8");
  const config = JSON.parse(configText) as ScopeConfig;
  const decision = checkUrlScope(targetUrl, config);

  console.log(JSON.stringify(decision, null, 2));
  process.exitCode = decision.allowed ? 0 : 2;
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(
    JSON.stringify(
      {
        allowed: false,
        code: "DEMO_ERROR",
        reason: `无法读取演示配置：${message}`,
      },
      null,
      2,
    ),
  );
  process.exitCode = 1;
}

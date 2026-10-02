import { readFile } from "node:fs/promises";
import { createServer } from "node:http";

import {
  restrictedHttpGet,
  type HttpGetPolicy,
} from "../capabilities/web/restricted-http-get.ts";
import type { ScopeConfig } from "../src/scope/scope-guard.ts";

async function runDemo(): Promise<void> {
  const policy = JSON.parse(
    await readFile("configs/http.example.json", "utf8"),
  ) as HttpGetPolicy;
  const suppliedUrl = process.argv[2];

  if (suppliedUrl) {
    const scopeConfig = JSON.parse(
      await readFile("configs/scope.example.json", "utf8"),
    ) as ScopeConfig;
    const result = await restrictedHttpGet(suppliedUrl, scopeConfig, policy);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.ok ? 0 : 2;
    return;
  }

  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<h1>security-agent-lab 本地演示页面</h1>");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("无法取得本地演示端口");
    }

    const targetUrl = `http://127.0.0.1:${address.port}/demo`;
    const scopeConfig: ScopeConfig = {
      allowed_schemes: ["http"],
      allowed_hosts: ["127.0.0.1"],
      allowed_ports: [address.port],
      allowed_paths: ["/demo"],
      denied_paths: [],
    };
    const result = await restrictedHttpGet(targetUrl, scopeConfig, policy);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.ok ? 0 : 2;
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

runDemo().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(
    JSON.stringify(
      {
        ok: false,
        code: "DEMO_ERROR",
        reason: message,
      },
      null,
      2,
    ),
  );
  process.exitCode = 1;
});

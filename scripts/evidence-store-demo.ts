import { createServer } from "node:http";

import { restrictedHttpGet } from "../capabilities/web/restricted-http-get.ts";
import {
  EvidenceStore,
  verifyEvidenceFile,
} from "../src/evidence/evidence-store.ts";

async function runDemo(): Promise<void> {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "x-demo-source": "local-only",
    });
    response.end(JSON.stringify({ message: "本地证据演示" }));
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

    const targetUrl = `http://127.0.0.1:${address.port}/evidence-demo`;
    const httpResult = await restrictedHttpGet(
      targetUrl,
      {
        allowed_schemes: ["http"],
        allowed_hosts: ["127.0.0.1"],
        allowed_ports: [address.port],
        allowed_paths: ["/evidence-demo"],
        denied_paths: [],
      },
      {
        allowed_resolved_ips: ["127.0.0.1"],
        timeout_ms: 1000,
        max_response_bytes: 4096,
        max_redirects: 0,
      },
    );

    const store = new EvidenceStore({ output_dir: "evidence/demo" });
    const saved = await store.saveHttpGet(httpResult);
    if (!saved.ok) {
      console.log(JSON.stringify(saved, null, 2));
      process.exitCode = 2;
      return;
    }

    const verified = await verifyEvidenceFile(saved.file_path);
    console.log(JSON.stringify({ saved, verified }, null, 2));
    process.exitCode = verified.ok ? 0 : 2;
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

runDemo().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(JSON.stringify({ ok: false, code: "DEMO_ERROR", reason: message }));
  process.exitCode = 1;
});

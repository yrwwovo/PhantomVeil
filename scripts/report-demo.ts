import { createServer } from "node:http";

import { restrictedHttpGet } from "../capabilities/web/restricted-http-get.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";
import { generateMarkdownReport } from "../src/reporting/markdown-report.ts";

async function runDemo(): Promise<void> {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "x-demo-source": "report-local-only",
    });
    response.end(JSON.stringify({ message: "本地报告演示" }));
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

    const targetUrl = `http://127.0.0.1:${address.port}/report-demo`;
    const httpResult = await restrictedHttpGet(
      targetUrl,
      {
        allowed_schemes: ["http"],
        allowed_hosts: ["127.0.0.1"],
        allowed_ports: [address.port],
        allowed_paths: ["/report-demo"],
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
    const savedEvidence = await store.saveHttpGet(httpResult);
    if (!savedEvidence.ok) {
      console.log(JSON.stringify(savedEvidence, null, 2));
      process.exitCode = 2;
      return;
    }

    const report = await generateMarkdownReport([savedEvidence.file_path], {
      output_dir: "reports/demo",
    });
    console.log(JSON.stringify({ saved_evidence: savedEvidence, report }, null, 2));
    process.exitCode = report.ok ? 0 : 2;
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

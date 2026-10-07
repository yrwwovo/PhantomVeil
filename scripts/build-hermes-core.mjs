import esbuild from "esbuild";
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outRoot = path.resolve(process.argv[2] ?? process.env.PVEIL_VENDOR_DIR ??
  path.join(repoRoot, "..", "phantomveil-hermes", "vendor", "security-core"));

const shared = {
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  legalComments: "inline",
  logLevel: "warning",
};

const ASSETS = [
  "benchmarks/hermes-eval/profiles/learning-off.yaml",
  "src/adapters/hermes/phantomveil-agent.md",
];

async function main() {
  await rm(outRoot, { recursive: true, force: true });
  await mkdir(outRoot, { recursive: true });
  await esbuild.build({ ...shared,
    entryPoints: [path.join(repoRoot, "scripts", "hermes-chat.mjs")],
    outfile: path.join(outRoot, "scripts", "hermes-chat.js"),
  });
  await esbuild.build({ ...shared,
    entryPoints: [path.join(repoRoot, "src", "adapters", "hermes", "mcp-server.ts")],
    outfile: path.join(outRoot, "src", "adapters", "hermes", "mcp-server.js"),
  });
  for (const rel of ASSETS) {
    const dest = path.join(outRoot, rel);
    await mkdir(path.dirname(dest), { recursive: true });
    await cp(path.join(repoRoot, rel), dest);
  }
  await writeFile(path.join(outRoot, "package.json"),
    JSON.stringify({ type: "module", private: true }, null, 2) + "\n");
  await writeFile(path.join(outRoot, "BUNDLE-INFO.json"), JSON.stringify({
    generated_from: "security-agent-lab",
    generator: "scripts/build-hermes-core.mjs",
    entrypoints: ["scripts/hermes-chat.js", "src/adapters/hermes/mcp-server.js"],
    assets: ASSETS,
    note: "Generated vendored bundle. Do not edit by hand; rebuild with `npm run build:hermes-core`.",
  }, null, 2) + "\n");
  console.log("Vendored security-core bundle written to", outRoot);
}
main().catch(err => { console.error(err); process.exitCode = 1; });
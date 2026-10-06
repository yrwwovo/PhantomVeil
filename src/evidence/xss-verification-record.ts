import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import type { BrowserProof } from "../../capabilities/web/xss-execution-verifier.ts";

export const recordDigest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export interface XssVerificationRecord {
  verification_id: string; task_id: string; hypothesis_id: string; endpoint: string;
  parameter_name: string; created_at: string; outcome: "reproduced" | "inconclusive";
  control_evidence_id: string; control_proof: BrowserProof;
  trials: { evidence_id: string; payload_sha256: string; marker: string; script: string; proof: BrowserProof }[];
  limitations: string[];
}
export async function saveXssVerification(root: string, input: Omit<XssVerificationRecord, "verification_id" | "created_at">) {
  const record: XssVerificationRecord = { ...input, verification_id: `XV-${randomUUID()}`, created_at: new Date().toISOString() };
  const digest = recordDigest(record);
  const directory = path.join(root, "verification", "hermes");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(path.join(directory, `${record.verification_id}.json`), JSON.stringify({ record, digest }),
    { flag: "wx", mode: 0o600 });
  return { record, digest };
}
export async function loadXssVerification(root: string, id: string) {
  if (!/^XV-[a-f0-9-]{36}$/u.test(id)) return null;
  try {
    const canonical = await realpath(root);
    const relative = path.join("verification", "hermes", `${id}.json`);
    const file = await realpath(path.join(canonical, relative));
    if (path.relative(canonical, file) !== relative) return null;
    const stored = JSON.parse(await readFile(file, "utf8"));
    return stored.record?.verification_id === id && recordDigest(stored.record) === stored.digest
      ? stored as { record: XssVerificationRecord; digest: string } : null;
  } catch { return null; }
}

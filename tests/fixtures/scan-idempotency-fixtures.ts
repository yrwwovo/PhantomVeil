/**
 * Reusable fixtures for the scan Idempotency-Key contract
 * (deriveScanIdempotencyKey / scanIdempotencyName / canonicalize in
 * src/adapters/reconlab/scan-port.ts). Shared by tests/scan-port.test.ts; other
 * suites (or a Python SDK port) can reuse the same pairs + vectors.
 */

import type { ScanRequest } from "../../src/adapters/reconlab/scan-port.ts";

export interface KeyPair {
  name: string;
  a: ScanRequest;
  b: ScanRequest;
}

const BASE = { kind: "http", target: "https://demo.test", scope_id: "scope-1" } as const;

/** Pairs that MUST derive the SAME key. */
export const SAME_KEY_PAIRS: readonly KeyPair[] = [
  {
    name: "different top-level key order",
    a: { ...BASE, args: { depth: 2, wordlist: "common" } },
    b: { ...BASE, args: { wordlist: "common", depth: 2 } },
  },
  {
    name: "nested objects, different key order at every level",
    a: { ...BASE, args: { opts: { b: { y: 1, x: 2 }, a: true }, depth: 1 } },
    b: { ...BASE, args: { depth: 1, opts: { a: true, b: { x: 2, y: 1 } } } },
  },
  {
    name: "array order preserved (same order inside reordered objects)",
    a: { ...BASE, args: { ports: [443, 80, 8080], mode: "fast" } },
    b: { ...BASE, args: { mode: "fast", ports: [443, 80, 8080] } },
  },
  {
    name: "missing args === empty args {}",
    a: { ...BASE },
    b: { ...BASE, args: {} },
  },
  {
    name: "undefined-valued field === field absent (wire semantics)",
    a: { ...BASE, args: { depth: 2, skip: undefined, nested: { k: undefined, v: 1 } } },
    b: { ...BASE, args: { depth: 2, nested: { v: 1 } } },
  },
];

/** Pairs that MUST derive DIFFERENT keys. */
export const DIFFERENT_KEY_PAIRS: readonly KeyPair[] = [
  {
    name: "null vs missing: {a:null} vs {}",
    a: { ...BASE, args: { a: null } },
    b: { ...BASE, args: {} },
  },
  {
    name: "array order is significant",
    a: { ...BASE, args: { ports: [80, 443] } },
    b: { ...BASE, args: { ports: [443, 80] } },
  },
  {
    name: "different nested value",
    a: { ...BASE, args: { opts: { depth: 1 } } },
    b: { ...BASE, args: { opts: { depth: 2 } } },
  },
  {
    name: "number vs numeric string",
    a: { ...BASE, args: { depth: 2 } },
    b: { ...BASE, args: { depth: "2" } },
  },
];

/**
 * TS <-> Python cross-check vector. Expected values computed independently with
 *   uuid.uuid5(uuid.UUID(SCAN_IDEMPOTENCY_NAMESPACE),
 *              json.dumps([kind, target, scope_id, args], sort_keys=True,
 *                         separators=(",", ":"), ensure_ascii=False))
 * (Python args = the same dict with the undefined-valued "skip" key omitted).
 */
export const CROSS_CHECK_VECTOR = {
  request: {
    kind: "http",
    target: "https://demo.test",
    scope_id: "scope-1",
    args: { depth: 2, wordlist: "common", nested: { b: 1, a: [3, 2, 1] }, skip: undefined },
  } as ScanRequest,
  canonicalName: '["http","https://demo.test","scope-1",{"depth":2,"nested":{"a":[3,2,1],"b":1},"wordlist":"common"}]',
  key: "8ede2adf-b732-5283-94ac-b391b47d49a8",
} as const;

/** No-args vector (args missing -> {}), also Python-checked. */
export const NO_ARGS_VECTOR = {
  request: { ...BASE } as ScanRequest,
  canonicalName: '["http","https://demo.test","scope-1",{}]',
  key: "9f251e5e-a8b1-5d48-bded-209cf5d26d0c",
} as const;

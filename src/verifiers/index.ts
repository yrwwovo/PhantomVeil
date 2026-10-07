import { OpenRedirectVerifier } from "./open-redirect-verifier.ts";
import { ReflectedXssVerifier } from "./reflected-xss-verifier.ts";
import { VerifierRegistry } from "./verifier-registry.ts";

export * from "./verifier-plugin.ts";
export * from "./verifier-registry.ts";
export * from "./reflected-xss-verifier.ts";
export * from "./open-redirect-verifier.ts";
export * from "./rubric-provider.ts";
export * from "./rubric-gate.ts";

/**
 * Build the registry with every shipped verifier plugin registered. Adding a
 * new vulnerability class is a one-line change here plus its own plugin file.
 */
export function createDefaultVerifierRegistry(): VerifierRegistry {
  const registry = new VerifierRegistry();
  registry.register(new ReflectedXssVerifier());
  registry.register(new OpenRedirectVerifier());
  return registry;
}

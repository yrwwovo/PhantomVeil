import assert from "node:assert/strict";
import test from "node:test";

import {
  checkHypothesisCreateAuthorization,
  type AuthorizationRegistry,
} from "../src/scope/authorization-registry.ts";

const target = "http://127.0.0.1:5000/lab/page";
const reference = "LOCAL-LAB-TEST";

function registry(): AuthorizationRegistry {
  return {
    schema_version: 1,
    grants: [{
      reference,
      enabled: true,
      expires_at: "2026-12-31T23:59:59.000Z",
      actions: ["hypothesis_create"],
      scope: {
        allowed_schemes: ["http"],
        allowed_hosts: ["127.0.0.1"],
        allowed_ports: [5000],
        allowed_paths: ["/lab"],
        denied_paths: ["/lab/admin"],
      },
    }],
  };
}

test("有效引用、操作、范围和有效期全部匹配才授权", () => {
  const decision = checkHypothesisCreateAuthorization(
    target, reference, registry(), new Date("2026-09-20T00:00:00.000Z"),
  );
  assert.equal(decision.authorized, true);
  assert.equal(decision.code, "AUTHORIZED");
});

test("模型编造的引用不能匹配本地授权登记", () => {
  const decision = checkHypothesisCreateAuthorization(
    target, "LOCAL-LAB-FAKE", registry(), new Date("2026-09-20T00:00:00.000Z"),
  );
  assert.equal(decision.authorized, false);
  assert.equal(decision.code, "REFERENCE_NOT_FOUND");
});

test("重复引用和无效范围使整个登记失败关闭", () => {
  const duplicate = registry();
  duplicate.grants.push(structuredClone(duplicate.grants[0]));
  const repeated = checkHypothesisCreateAuthorization(target, reference, duplicate);
  assert.equal(repeated.authorized, false);
  assert.equal(repeated.code, "INVALID_REGISTRY");

  const malformed = registry();
  malformed.grants[0].scope.allowed_ports = [70000];
  const invalid = checkHypothesisCreateAuthorization(target, reference, malformed);
  assert.equal(invalid.authorized, false);
  assert.equal(invalid.code, "INVALID_REGISTRY");
});

test("引用不能越过授权记录中的禁止路径", () => {
  const decision = checkHypothesisCreateAuthorization(
    "http://127.0.0.1:5000/lab/admin",
    reference,
    registry(),
    new Date("2026-09-20T00:00:00.000Z"),
  );
  assert.equal(decision.authorized, false);
  assert.equal(decision.code, "TARGET_NOT_ALLOWED");
});

test("独立授权登记同样识别域名与子域名规则", () => {
  const grant = registry();
  grant.grants[0].scope = {
    allowed_schemes: ["https"],
    allowed_hosts: [],
    allowed_domains: ["example.test"],
    denied_hosts: ["admin.example.test"],
    allowed_ports: [443],
    allowed_paths: ["/"],
    denied_paths: [],
  };

  assert.equal(
    checkHypothesisCreateAuthorization("https://oa.example.test/", reference, grant).code,
    "AUTHORIZED",
  );
  assert.equal(
    checkHypothesisCreateAuthorization("https://admin.example.test/", reference, grant).code,
    "TARGET_NOT_ALLOWED",
  );
});

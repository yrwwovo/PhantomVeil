import assert from "node:assert/strict";
import test from "node:test";

import {
  checkUrlScope,
  type ScopeConfig,
} from "../src/scope/scope-guard.ts";

const baseConfig: ScopeConfig = {
  allowed_schemes: ["http", "https"],
  allowed_hosts: ["127.0.0.1", "localhost"],
  allowed_ports: [8080, 8443],
  allowed_paths: ["/", "/login", "/api"],
  denied_paths: ["/admin/delete", "/api/destructive"],
};

test("放行完整匹配的授权 URL", () => {
  const result = checkUrlScope("http://127.0.0.1:8080/login", baseConfig);

  assert.equal(result.allowed, true);
  assert.equal(result.code, "ALLOWED");
  assert.equal(result.target?.port, 8080);
});

test("空白名单默认拒绝", () => {
  const result = checkUrlScope("http://127.0.0.1:8080/", {
    allowed_schemes: [],
    allowed_hosts: [],
    allowed_ports: [],
    allowed_paths: [],
    denied_paths: [],
  });

  assert.equal(result.allowed, false);
  assert.equal(result.code, "SCHEME_NOT_ALLOWED");
});

test("拒绝未授权端口", () => {
  const result = checkUrlScope("http://127.0.0.1:9090/", baseConfig);

  assert.equal(result.allowed, false);
  assert.equal(result.code, "PORT_NOT_ALLOWED");
});

test("规范解析后拒绝伪装主机", () => {
  const result = checkUrlScope(
    "http://127.0.0.1.evil.example:8080/",
    baseConfig,
  );

  assert.equal(result.allowed, false);
  assert.equal(result.code, "HOST_NOT_ALLOWED");
});

test("禁止路径优先于允许路径", () => {
  const result = checkUrlScope(
    "http://127.0.0.1:8080/admin/delete/42",
    baseConfig,
  );

  assert.equal(result.allowed, false);
  assert.equal(result.code, "PATH_DENIED");
});

test("拒绝异常 URL", () => {
  const result = checkUrlScope("这不是一个 URL", baseConfig);

  assert.equal(result.allowed, false);
  assert.equal(result.code, "INVALID_URL");
});

test("路径匹配以完整路径段为边界", () => {
  const result = checkUrlScope("http://127.0.0.1:8080/apiv2", {
    ...baseConfig,
    allowed_paths: ["/api"],
  });

  assert.equal(result.allowed, false);
  assert.equal(result.code, "PATH_NOT_ALLOWED");
});

test("解码并规范化路径后再应用禁止规则", () => {
  const result = checkUrlScope(
    "http://127.0.0.1:8080/api%2F..%2Fadmin%2Fdelete",
    baseConfig,
  );

  assert.equal(result.allowed, false);
  assert.equal(result.code, "PATH_DENIED");
});

test("拒绝含无效端口的授权配置", () => {
  const result = checkUrlScope("http://127.0.0.1:8080/", {
    ...baseConfig,
    allowed_ports: [0, 70_000],
  });

  assert.equal(result.allowed, false);
  assert.equal(result.code, "INVALID_CONFIG");
});

test("错误类型的配置返回结构化拒绝", () => {
  const result = checkUrlScope("http://127.0.0.1:8080/", {
    ...baseConfig,
    allowed_hosts: [123] as unknown as string[],
  });

  assert.equal(result.allowed, false);
  assert.equal(result.code, "INVALID_CONFIG");
});

test("拒绝带用户名或密码的 URL", () => {
  const result = checkUrlScope(
    "http://user:secret@127.0.0.1:8080/",
    baseConfig,
  );

  assert.equal(result.allowed, false);
  assert.equal(result.code, "INVALID_URL");
  assert.equal(result.target, undefined);
});

const domainConfig: ScopeConfig = {
  ...baseConfig,
  allowed_hosts: [],
  allowed_domains: ["example.test"],
  denied_hosts: ["admin.example.test"],
  allowed_ports: [443],
  denied_paths: ["/delete"],
};

test("域名规则允许根域名和多级子域名", () => {
  for (const url of [
    "https://example.test/",
    "https://oa.example.test/",
    "https://dev.oa.example.test/app",
  ]) {
    assert.equal(checkUrlScope(url, domainConfig).code, "ALLOWED", url);
  }
});

test("域名规则不允许伪装后缀和相似主机", () => {
  for (const url of [
    "https://example.test.evil.test/",
    "https://fake-example.test/",
    "https://example-test/",
  ]) {
    assert.equal(checkUrlScope(url, domainConfig).code, "HOST_NOT_ALLOWED", url);
  }
});

test("精确禁止主机优先于整个域名授权", () => {
  assert.equal(
    checkUrlScope("https://admin.example.test/", domainConfig).code,
    "HOST_DENIED",
  );
  assert.equal(
    checkUrlScope("https://sub.admin.example.test/", domainConfig).code,
    "ALLOWED",
  );
});

test("子域名仍需通过端口和禁止路径检查", () => {
  assert.equal(
    checkUrlScope("https://oa.example.test:8443/", domainConfig).code,
    "PORT_NOT_ALLOWED",
  );
  assert.equal(
    checkUrlScope("https://oa.example.test/delete/1", domainConfig).code,
    "PATH_DENIED",
  );
});

test("空域名与空精确主机白名单仍默认拒绝", () => {
  assert.equal(
    checkUrlScope("https://example.test/", { ...domainConfig, allowed_domains: [] }).code,
    "HOST_NOT_ALLOWED",
  );
});

test("域名规则拒绝过宽或无效的配置", () => {
  for (const value of ["com", "127.0.0.1", "localhost", "*.example.test", "example.test.evil.test/path"]) {
    assert.equal(
      checkUrlScope("https://example.test/", { ...domainConfig, allowed_domains: [value] }).code,
      "INVALID_CONFIG",
      value,
    );
  }
});

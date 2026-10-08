/**
 * mcp-server.ts 的「附加」片段（不要重写既有文件，只把本函数的 registerTool 调用
 * 补进 createHermesMcpServer 内即可）。沿用既有风格：中文 description + zod/v4 inputSchema
 * + response() 包装 + askApproval HITL。
 *
 * 落地方式（在既有 mcp-server.ts 里）：
 *   1) import { ApkTaskService } from "./apk-service.ts";
 *   2) import { registerApkTools } from "./mcp-server.apk-additions.ts";
 *   3) 在 createHermesMcpServer(...) 末尾 return server 之前加一行：
 *        if (apkService) registerApkTools(server, apkService, askApproval);
 *      （apkService 由 main() 按会话 Scope 构造，和 HermesTaskService 并列）
 *
 * 纪律：APK 静态分析是只读操作，默认放行（设计 §0），因此四个工具不强制 askApproval；
 * askApproval 作为可选门禁保留，用于将来对「取样/解包落盘」这类副作用加确认。
 * 动态 verifier（apk.exported_component_poc / apk.signature_bypass）本期只在 verify_hooks
 * 登记名字，不在此注册可执行工具。
 */

// 以下 import 在真实仓库解析（stage 内不带 MCP/zod 依赖，故本文件不纳入 stage 独立 typecheck）。
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import type { ApkTaskService } from "./apk-service.ts";

function response(result: { ok: boolean }) {
  return { isError: !result.ok, content: [{ type: "text" as const, text: JSON.stringify(result) }] };
}

export function registerApkTools(
  server: McpServer,
  service: ApkTaskService,
  _askApproval: (message: string) => Promise<boolean>,
): void {
  server.registerTool("apk_acquire_unpack", {
    description: "对本次会话绑定的 APK 做只读采集：计算整包 SHA-256（Scope 主键）、列出 zip 条目、读取签名方案与证书指纹、按文件存在性列出加固指示项。只返回事实，不判定壳类型，也不下任何漏洞结论。",
    inputSchema: z.object({}),
  }, async () => response(await service.acquireUnpack()));

  server.registerTool("apk_decompile_manifest", {
    description: "解包并解析 AndroidManifest：枚举四大组件及其 exported / android:permission / readPermission / writePermission / intent-filter，以及 debuggable / allowBackup / minSdk / targetSdk 等全局开关。只陈列事实与候选定位，不打 CWE 标签。",
    inputSchema: z.object({}),
  }, async () => response(await service.decompileManifest()));

  server.registerTool("apk_dex_smali_audit", {
    description: "用 jadx 反编译后，按固定标记目录清点鉴权/调用方校验/签名读取/native 边界等调用点的 类#方法 与 file:line，并与给定 exported 组件做事实关联（是否出现某类调用点）。报告位置事实，绝不输出“这是漏洞”的判定。",
    inputSchema: z.object({
      components: z.array(z.object({
        name: z.string().describe("组件全限定类名"),
        type: z.enum(["activity", "service", "receiver", "provider"]).optional(),
      })).optional().describe("②阶段得到的 exported 组件清单，用于关联；可省略"),
    }),
  }, async (input) => response(await service.dexSmaliAudit(input)));

  server.registerTool("apk_so_static_audit", {
    description: "对 lib/<abi>/*.so 做只读静态分析：readelf/strings/LIEF 列出架构、动态导出符号（含 JNI Java_*）、导入符号、NEEDED 依赖与签名/密钥相关字符串（脱敏）。只给事实面，so 深度反编译（IDA/Blutter）归受限 capability/用户电脑段。",
    inputSchema: z.object({
      so_path: z.string().describe("box 上 so 文件的绝对路径（lib/<abi>/*.so 解出后）"),
    }),
  }, async ({ so_path }) => response(await service.soStaticAudit({ soPath: so_path })));

  // —— 预留：动态 verifier kind（本期不实现，仅占位，供 verify_hypothesis 将来路由）——
  //   kind "apk.exported_component_poc" → CWE-862/306 组件 PoC（adb 显式 intent 调起）
  //   kind "apk.signature_bypass"       → CWE-347 重签名/篡改绕过校验
  //   二者的 verifier 插件在 pv/verifiers 注册（本期只在 finding.verify_hooks.verifier_plugin 登记名字）。
}

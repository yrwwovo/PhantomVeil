# 取得包之后调用 apk_decompile_manifest

先有 `apk_acquire_unpack` 的事实，再调用 `apk_decompile_manifest`。会话未绑定返回 `NOT_BOUND`，此时不要读清单。其后才是 `apk_dex_smali_audit`；`apk_so_static_audit` 仅用于会话 `workRoot/lib/<abi>/` 内的 `.so`。

工具只返回事实。状态保持 `suspected` 或 `testing`。`cwe` 和 `locator` 由代理自己填写。本说明没有 CWE 编号，也不把某条事实对应成漏洞。

## 来源里保留的观察项

对照 `app测试面/通用测试面方法论.md` 第一节「导出组件」里的清单项，只保留反编译清单后能直接读到的字段。启动组件、传参、以及任何「这意味着问题」的句子都不保留。`apptest/APP_FORMAT.md` 只补充：`versionName` 来自 AndroidManifest。

逐项记下，不要把缺某项写成结论：

1. 组件名：Activity、Service、Receiver、Provider 的类名。
2. 每个组件的 `exported` 标志（清单里写明的值，没有写明就记为未写明）。
3. `intent-filter` 的 action、category、data（scheme、host、path）。原文点名要记下 `VIEW` + `BROWSABLE`，以及 FileProvider 的路径配置原文，只作摘录。
4. `uses-permission` 的权限名列表。原文没有「缺少某权限所以怎样」的对照表，本说明也不加。
5. SDK 字段：`minSdkVersion`、`targetSdkVersion`、`compileSdkVersion`（原文未单列这三项，按工具返回值记录）。
6. 包名，以及 `versionName`（可与 acquire 的 badging 对照，不一致就并列记下）。

权限列表、导出标志、过滤器都只是事实。不要从「没有某权限」或「标了 exported」推出结论。

# 清单之后调用 apk_dex_smali_audit

顺序：`apk_acquire_unpack`，然后 `apk_decompile_manifest`，然后 `apk_dex_smali_audit`。会话未绑定返回 `NOT_BOUND`，不要打开 dex 或 so。`apk_so_static_audit` 只在 `.so` 位于该会话 `workRoot/lib/<abi>/` 时调用；路径在工作目录外就不调用。

工具只返回事实。状态保持 `suspected` 或 `testing`。`cwe` 和 `locator` 由代理自己填写。本说明没有 CWE 编号，也不把某条事实对应成漏洞。符号、类名、行号只作为 locator 的材料，不是结论。

## dex / smali 要看什么

`apptest/通用注入.md` 只出现过反编译输出目录名，没有类、方法、`file:line` 的观察清单，那些步骤不抄。类与方法位置按已注册工具的返回值记录。

对照 `逆向习惯/逆向习惯.md` 里「先静态读 dex」的部分，只保留可定位的事实：

1. 列出 `classes.dex`、`classes2.dex` 等文件名。
2. 记录类名、方法名（含 native 声明的参数类型与个数）。
3. 记录定义或引用所在的 `file:line`。
4. 上层调用点只记成另一处类名 / 方法名 / `file:line`，不解释行为。

## .so 只在会话 lib 目录里看

对照 `逆向习惯/逆向习惯.md` 的静态第一刀，以及 `本地so分析与调试/目的(关键分析)/目的.md` 里「先列出再记录」的表。动态执行、补环境、改写不在本说明里。

仅当文件在 `workRoot/lib/<abi>/`：

1. 导出符号名与地址。
2. NEEDED 依赖库名。
3. 字符串常量原文。
4. 反汇编起点用函数头或段起点，避免从任意地址起读造成错位；记下地址与指令文本，不下结论。

符号命中、字符串出现、依赖存在，都只是 locator 材料。

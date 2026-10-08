# 先调用 apk_acquire_unpack

会话未绑定（返回 `NOT_BOUND`）时，不要读文件，先完成绑定。绑定成功后再按这个顺序：`apk_acquire_unpack`，然后 `apk_decompile_manifest`，然后 `apk_dex_smali_audit`。只有会话 `workRoot/lib/<abi>/` 里确实有 `.so` 时，才调用 `apk_so_static_audit`。

工具只返回事实。状态保持 `suspected` 或 `testing`。`cwe` 和 `locator` 由代理自己填写。本说明没有 CWE 编号，也不把某条事实对应成漏洞。

## 来源里保留的只读顺序

对照 `apptest/ACQUISITION.md` 的只读部分，以及 `apptest/APP_FORMAT.md` 要归档的字段。商店抓取、重命名、下载不在本说明里。

1. 确认目标是已绑定会话工作目录内的 `.apk`。
2. 用 `aapt dump badging` 记录：`package: name`、`application-label`（含 `application-label-zh-CN`）、`versionName`。
3. 对照归档字段记下：`package_name`、来自 AndroidManifest 的 `versionName`、文件摘要。来源用的是 md5；本工具记录文件 sha256。
4. 对照 `逆向习惯/逆向习惯.md`：能静态读就不动态跑。解包后只列出清单和 `lib/<abi>/` 下的 `.so` 路径，不进入动态执行。

证书指纹、zip 条目名在上述原文里没有单独清单。这两项按已注册工具的返回值记录，不另写判定。

## 要记下的事实

- 文件 sha256
- 包名
- 证书指纹（算法与指纹值；提取为空就记为空）
- zip 条目名（含 `AndroidManifest.xml`、`classes*.dex`、`lib/<abi>/*.so`）
- badging 里的应用标签与 `versionName`

这些只是记录。不要根据缺字段、空指纹或条目名写出结论。

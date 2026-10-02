# XSS 特殊字符编码观察

本功能从一个已经完成反射检查、且响应中确实出现 `PV-REFLECT-*` 无害标记的 EV 开始。
它对同一端点和同一 GET 参数再发送一次请求，观察五个 HTML 边界相关标点在原始响应源码中的形式：

- `<`
- `>`
- `"`
- `'`
- `&`

这些字符分别放在唯一的文本边界中，探针不包含标签名、事件处理器、JavaScript、URL 协议或其他
可执行 XSS 载荷。工具不跟随重定向，每次调用最多发送一个请求。

## 前置条件

1. 来源 EV 必须由单参数无害反射检查产生。
2. 来源 HTML 必须确实包含该次反射标记。
3. 目标仍须通过项目 Scope Guard。
4. 本地授权记录必须单独包含 `xss_encoding_probe` 动作。
5. OpenCode 会在单次网络请求前询问一次批准；审批不可用或被拒绝时不发送请求。

`configs/authorization.local.json` 中对应授权记录的动作示例：

```json
"actions": ["parameter_reflection_check", "xss_encoding_probe"]
```

## 运行

OpenCode 中可以说：

```text
请用 authorized_xss_encoding_probe 继续检查 EV-... 的特殊字符编码，授权引用为 LOCAL-LAB-EXAMPLE。
```

也可以从终端明确执行：

```powershell
npm run xss:encoding -- <反射EV编号> <授权引用>
```

终端命令本身代表本地操作者发起该次调用，因此没有 OpenCode 审批界面，但仍执行 Scope、授权引用、
来源 EV、IP、超时、响应大小和禁止重定向检查。

## 结果含义

- `raw`：字符在原始响应源码中原样出现，需要结合反射上下文复核。
- `html_entity`：本次观察到 HTML 实体编码。
- `percent_encoded`：本次观察到 URL 百分号编码。
- `removed`：字符边界存在，但字符被删除。
- `transformed`：字符发生了其他无法归类的转换。

原样字符不等于已确认 XSS；实体编码也不代表整个应用不存在 XSS。工具不会自动创建 HYP，结果会保存为
新的 EV 和 `ENC-*.md` 中文报告，供后续人工复核或独立验证规则使用。

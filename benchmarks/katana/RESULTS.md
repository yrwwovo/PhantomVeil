# Katana 本地入口发现对照（2026-09-30）

## 运行方式

使用官方发行版 Katana `v1.7.0` Windows amd64 二进制，SHA-256：
`e281be66d81eb4f86c01918955279bb8f55ae79f23bb8a01fd8a038b8e4a4801`。
二进制只放在系统临时目录，未加入项目依赖或 Agent。复现命令：

```powershell
node benchmarks/katana/local-comparison.mjs C:\path\to\katana.exe
```

脚本临时启动两个仅监听 `127.0.0.1` 的站点及一个本地代理。主站包含普通链接、查询参数链接、重定向、404、脚本资源、跨端口链接和模拟退出链接。先用项目现有 `runWebCrawl`，再用 Katana 标准模式加 `-jc`；共同深度 2、请求上限 20，不启用 headless、自动填表或认证。Katana 使用单并发、每秒最多 3 次请求，并经代理限制目标；本地站点拒绝超出 20 次的候选请求。实际请求由站点日志计数。
发现范围外请求尝试时，复现脚本仍打印完整 JSON 结果，但以退出码 2 提示边界未通过。

## 结果

| 指标 | 现有爬虫 | Katana v1.7.0 |
| --- | ---: | ---: |
| 主站实际请求 | 6 | 9 |
| 主站 2xx 的不同 URL | 4 | 6 |
| 404 请求 | 1 | 1 |
| 运行耗时 | 约 1.6 秒 | 约 8.2 秒 |

Katana 多访问的两个 2xx URL 是 `/app.js` 和 `/search?q=seed`。前者是脚本资源，后者的 `q` 参数已被现有爬虫从静态 HTML 清点；本次没有新增可复核的业务入口或参数。Katana 输出还包含 `/missing`，但它返回 404。脚本中的 `/api?item=1` 没有被本次候选配置发现，因此也不能据此声称有 JavaScript 入口覆盖收益。

本地代理另拦下一次发往 `http://burpsuite/` 的 GET，目标并非靶场；主站以外实际收到的请求为 0。对照 [Katana v1.7.0 HTTP 客户端源码](https://github.com/projectdiscovery/katana/blob/v1.7.0/pkg/engine/common/http.go) 和其 [代理工具源码](https://github.com/projectdiscovery/utils/blob/main/proxy/burp.go)，这是设置代理后执行的 Burp 识别请求。它不属于本项目授权范围，也不受给主站设置的 `-cs` 规则约束。

## 决定

本轮停止 Katana 接入，不加入 OpenCode 工具或真实站点流程。这个配置没有带来新增业务入口，且代理初始化存在范围外请求尝试。若以后继续评估，需要先找到能在**发送前**覆盖工具自身流量、目标请求、重定向和 DNS/IP 的统一边界，并验证总请求预算；再用更有代表性的本地动态靶场重复对照。本实验只说明这一固定版本、配置和小型本地站点的行为，不能推断真实 SRC 的发现率。

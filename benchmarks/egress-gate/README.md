# 本地出站门禁原型（2026-09-30）

这是一个**只针对合成 HTTP 靶场**的独立实验，未接入 `pveil`、OpenCode 或任何真实目标。它验证候选进程的请求在发送前能否经过项目已有的 Scope Guard、固定 IP、逐跳重定向和总请求预算。

## 结构与复用

`compose.yaml` 建立两个 `internal: true` 的 Docker 网络：`probe` 只在前侧，`fixture` 只在后侧，`gate` 连接两侧；没有向宿主机发布端口。Node 和 Python 镜像按本次验证的摘要固定。`gate.mjs` 是一个只接受绝对 HTTP URL 的 GET 代理入口，复用 `restrictedHttpGet` 与 `checkUrlScope`。它不透传候选请求头或 Cookie，只把 HTML 文本、状态码和 Content-Type 返回给候选；CONNECT、Upgrade、其他方法一律拒绝。日志仅包含 URL 摘要、结果码、重定向数和请求计数。

实验策略只允许 `http://fixture:8000/`，固定解析 IP `172.30.90.10`，禁止 `/forbidden` 和 `/metrics`。默认总预算为 **4 次实际网络请求尝试**；允许的重定向每一跳都消耗一次。范围拒绝发生在 DNS/连接之前，不消耗转发预算。响应上限 256 KiB、超时 5 秒、最多 3 次重定向。

## 复现

在项目根目录、Docker Engine 可用时依次运行：

```powershell
docker compose -f benchmarks/egress-gate/compose.yaml up -d gate fixture
docker compose -f benchmarks/egress-gate/compose.yaml --profile test run --rm --no-deps probe
docker compose -f benchmarks/egress-gate/compose.yaml exec -T gate node -e "require('node:http').get('http://fixture:8000/metrics',r=>{let s='';r.on('data',c=>s+=c);r.on('end',()=>console.log(s))})"
docker compose -f benchmarks/egress-gate/compose.yaml down
```

探针应输出 `GATE_PROBE_PASSED`。在全新容器上，靶场计数应为 `{"/ok":2,"/redirect-allowed":1,"/redirect-denied":1}`；`/forbidden` 和超预算后的 `/ok` 不产生上游请求。探针还直接尝试连接靶场固定 IP，必须失败。结果日志中的 `http://burpsuite/`、跨端口及禁止路径均为 403 且不增加网络尝试数；允许的重定向把计数从 1 增至 3，拒绝的重定向只增加其第一跳，预算用尽后返回 429。

另外把官方 Katana v1.7.0 Linux amd64 二进制放在临时目录，仅连接前侧内部网络运行：**不配置代理时直连 `fixture` 失败**；配置 `-proxy http://gate:8787` 后，门禁日志记录一条 `SCOPE_DENIED` 的代理自检请求和正常靶场请求。Linux 发行包 SHA-256 为 `fe1142d92f418549338ea46d67a472124878482e225d279e9a42700c75d76a4d`，解压出的二进制 SHA-256 为 `2dd9024907d656235409dea7aac18d3cdd88f8a8da332494113a69bff4c295d6`。二进制不在仓库中。

## 验证结果与限制

- 2026-09-30：本地探针全部通过；实测靶场只收到上述 4 次允许的请求。
- Katana 直连因无法解析靶场而失败；经门禁访问成功，`http://burpsuite/` 自检在发送到目标前被拒绝。Katana 的退出码即使在直连失败时也可能为 0，应检查门禁和靶场记录。
- 本次只验证 HTTP GET 与 Docker 内部网络拓扑；HTTPS CONNECT、WebSocket、认证、真实 DNS 变化、多进程并发、宿主机网络隔离和外部授权站点都未验证。不能据此把代理单独视为真实站点的进程级网络沙箱。未来接入需有独立授权登记、操作审批、证据保存与更完整的网络边界验证。

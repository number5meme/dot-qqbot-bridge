# 首次安装与配对

本版本已经实现首次配对，并有真实本地 workerd/SQLite 集成测试。下面区分已有代码、运营者必须配置的外部服务以及尚未完成的真实端到端验收。本次只修改本地准备项目，没有执行部署、创建凭据或向 QQ 发消息。

## 1. 外部前提

需要自己的 Cloudflare Workers 账户和支持 SQLite Durable Objects 的环境、自己可管理且中国大陆网络可访问的 HTTPS 域名、具有 C2C 私聊事件/测试用户权限的 QQ 机器人应用，以及只允许本人邮箱身份的 Cloudflare Access 应用。**腾讯 QQ 平台服务器必须能够实际访问完整 webhook URL，海外访问成功不能代替这项验证。** QQ 平台的申请、审核及权限由平台决定。

还需要能完成 Managed OAuth 并支持项目 MCP 事件接口的客户端/连接器。项目不提供 OAuth 服务端、客户端注册、Access 策略或 ChatGPT 连接器登记。普通 MCP 连接并不保证支持事件订阅。这个外部集成流程仍需在目标账户中核验，不能把下面的本地代码步骤理解为自动完成平台配置。

## 2. 本地检查与私有配置

运行 README 指定的 `npm ci --ignore-scripts --no-audit --no-fund` 和 `npm run check`。复制示例配置到被 Git 忽略的私有文件，填入自己的主机名、Access tenant/audience、QQ app ID、owner email、QQ secret 和 callback 加密 keyring。

`.dev.vars` 只供本地工具使用，不会自动成为线上 Worker secrets。真实部署的 secret bindings 需要运营者通过其授权的安全工作流单独配置，不要将 secrets 放进源代码、公开配置、命令历史或聊天。

四个开关初始都保持关闭：`PAIRING_ENABLED`、`BRIDGE_ENABLED`、`EVENTS_ENABLED`、`MCP_WRITE_ENABLED`。

## 3. 全新隔离部署配置

模板没有账户 ID、域名路由或迁移，需要运营者自行补齐。新部署需要将 `BRIDGE` 绑定到 `BridgeStore` 并建立 SQLite class。对于**全新的 Worker 和 namespace**，相应 Wrangler migration 形状是：

```json
"migrations": [{ "tag": "v1", "new_sqlite_classes": ["BridgeStore"] }]
```

不要把这项新建迁移套到现有生产 Worker。现有安装必须保留自己的 Worker identity、DO namespace、迁移历史和 owner 数据。本公开准备分支不是未经审核即可替换线上版本的补丁。

配置并核验自己拥有的主机名路由：

- MCP 主机名：POST `/mcp`、GET `/auth-check`、GET `/health`。
- 额外 QQ webhook 主机名：仅 POST `/qq/webhook`。MCP 主机名也允许这个 webhook 路径。
- 其他路径、方法、主机名和查询参数被拒绝。

MCP/auth-check 必须使用正确的 Access 身份链。不能为使 QQ callback 可达而放开 MCP 身份保护。QQ webhook 需要可由 QQ 平台访问，不能要求它进行交互式网页登录；项目自己验证普通事件的 QQ 签名。公开 `/health` 只是健康信息，不代表身份验证或配对成功。

在 QQ 平台配置对应 `/qq/webhook` 地址并完成 setup challenge。实现接受受限且新鲜的 op13 challenge，核对 app ID，返回规定签名；这一步可在尚未配对时进行。它不会绑定 owner，也不会启用普通消息。

这些外部操作尚未在本分支上实际执行或验收，具体操作需要遵守账户授权和平台当前界面。

### 部署网络验收（先于配对）

1. **域名与路由一致。** 在 QQ 控制台填写完整地址，例如 `https://qq-webhook.example.com/qq/webhook`。该主机名必须与 `QQ_WEBHOOK_HOSTNAME` 或 `ACCESS_HOSTNAME` 一致，并已关联到目标 Worker。当前模板关闭 `workers.dev`，不能只填默认域名而不配置部署入口。
2. **从中国大陆网络检查。** 检查 DNS 解析、HTTPS 默认 443 连接、证书主机名/有效期/完整信任链，以及可能的 IPv4/IPv6 路径差异。至少在实际使用的大陆网络上测试；一次海外检查或单一运营商成功，不代表所有路径或腾讯回调均成功。不要把默认 `workers.dev` 当作大陆可达性保证，使用自定义域名仍须实测。Cloudflare 对跨境路径的延迟与可靠性有说明，见 [China Network 概述](https://developers.cloudflare.com/china-network/)。
3. **检查精确 URL 和鉴权边界。** 本项目仅允许 POST `/qq/webhook`，没有末尾斜杠或查询参数；只支持 HTTPS 默认 443。QQ 官方列出的可配置端口比本项目更宽，不能据此向本项目填入 8080/8443。该 callback 路径不得跳转到 Access 登录、验证码或浏览器挑战，也不能返回静态网页代替协议响应。只调整正确的 callback 范围，不要关闭 `/mcp` 和 `/auth-check` 的身份验证。
4. **正确解释探测结果。** GET 或 HEAD 请求 `/qq/webhook` 被路由拒绝是预期行为；MCP 域名的 `/health` 只检查基础服务。额外 QQ webhook 域名不提供 `/health`。这些结果不能证明 op13 握手或普通事件已通过。
5. **使用 QQ 平台真实校验。** 在 QQ 平台保存/校验回调配置，确认 op13 请求进入正确路径，平台成功验证响应中的 `plain_token` 和签名。随后在获得测试授权后，用本人私聊确认真实签名事件可达。排障仅记录必要状态码/固定错误阶段，不公开配对码、正文、凭据或完整私密 payload。
6. **检查备案适用范围。** 不将“大陆可达”写成所有 webhook 一律必须 ICP 备案。按实际托管地区、接入服务、平台配置及现行规则核对。例如接入 [Cloudflare China Network](https://developers.cloudflare.com/china-network/) 有其自己的 ICP 前提，而 QQ 官方 [消息 URL 白名单说明](https://github.com/tencent-connect/bot-docs/blob/main/docs/README.md) 是针对消息中链接域名的另一项配置，不能直接替代事件 webhook 的要求。

协议依据：[QQ 官方事件订阅与通知](https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html) 明确说明 HTTPS 回调、平台地址验证及签名校验。精确主机名/路径/方法和默认端口限制则来自本项目 `src/worker.ts` 的 `allowed()`，属于本实现的额外限制。网络可达性必须以目标域名与真实平台的检测为准，本文不声称已验证任何部署的中国大陆连通性。

## 4. 通过已认证 MCP 发起首次配对

1. 确认部署是新安装或没有历史 owner 数据的空库。不要手工删记录来制造空库。
2. 运营者开启 `PAIRING_ENABLED="true"`，其余三个业务开关必须保持关闭。QQ app ID 和 secret 必须已配置。
3. 本人通过 Access 认证。`/auth-check` 或 `bridge_status` 应显示已认证且 `owner_bound: false`。未知用户、过期断言或错误 issuer/audience/email 均不能发码。
4. 在支持该服务的客户端明确调用 MCP 工具 `start_pairing`，参数为空对象 `{}`。它返回 `code`、`expires_at` 和用途说明。代码形状为 `QQPAIR-` 加 32 位十六进制字符，最长 10 分钟有效，并受发码时 Access 断言的到期时间限制。
5. 发码响应设置 `Cache-Control: no-store`；服务端仅保留码的 hash。相同 pending 期间再次调用只返回 `pending: true` 和到期时间，不重复显示或换发原码。不要录屏、公开复制或把码发给其他人。

如果响应丢失或超时，先检查状态。未收到原码时要等旧码失效后重新明确发起，不能盲目重试并假定第一次没发生。已经提交的事务不可能因响应超时自动撤销。

## 5. 在自己的 QQ 私聊完成绑定

1. 本人在自己的机器人私聊中发送**原样配对码**，不要发到群聊或交给其他账号代发。
2. Worker 验证 QQ 签名、新鲜时间和 C2C 格式，匹配 pending hash，然后在一个事务中写入 owner、绑定身份指纹并删除 pending。
3. 再通过本人认证的 `bridge_status` 确认 `owner_bound: true`。配对不发送自动 QQ 回复，所以不能用“是否收到机器人回复”判断是否成功。
4. 关闭 `PAIRING_ENABLED`。即使没有关闭，已绑定安装也不能重新发码或换绑。

持有配对码并能发送真实 QQ 私聊的人可以完成该次绑定；项目不能外部核验 QQ 实名与 Access 邮箱是否属于同一自然人。若码泄露或发现绑定错误，立即关闭配对/业务开关并进行人工事件处理。没有自动解绑、重置、seed-owner 或管理 API。

并发发码只产生一个有效 pending 码。并发消费只绑定一个 owner。过期、错误、重放、群聊和未签名命令不能重新绑定。包含配对码格式的内容会在普通消息入库之前被拦截，包括绑定后的重放，不会转发为事件或进入正文/时延记录。

## 6. 启用业务与真实验收

配对成功时所有业务开关仍关闭。本人明确同意对应数据共享/操作之后，运营者才可开启接收、事件和回复能力，并由客户端建立真实事件订阅。

真实验收应在隔离环境完成，至少包括本人发送测试消息、陌生人被忽略、读取、一次回复、callback challenge、续期、显式取消与旧事件链取消后的回复阻断。`uncertain` 发送结果不得盲目重试。

本次未进行这些外部操作。补齐首次配对代码不等于已通过真实 QQ/Managed OAuth 验收，也不保证特定客户端的事件功能可用。

## 身份连续性与恢复边界

全新空库访问、未签名输入或未配对业务请求不会因“没有 owner”而自动永久锁死。但是出现历史业务数据、旧 SQL owner、绑定指纹，或任何畸形 owner 记录时，不会把它当作新安装。

新绑定的指纹与 owner 在同一事务提交，因此即使在写 SQL 连续性快照之前崩溃，后续 owner 变更也会被发现。删除/修改已有 owner 或指纹不符会持久阻断权限，恢复旧值也不会自动解锁。旧安装没有新指纹时保留原 SQL owner 连续性检查。

不要复制他人的数据库、手工编造 OpenID、部署测试 wrapper 或删除安全标记来绕过这些限制。

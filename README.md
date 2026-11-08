# dot-qqbot-bridge

将 QQ 机器人私聊连接到 dot：通过 Managed OAuth MCP 接收消息事件、读取消息并回复。运行于 Cloudflare Workers 和 SQLite Durable Objects，仅处理已配对本人的消息。

- 工具：`bridge_status`、`start_pairing`、`read_message`、`reply_message`。
- 事件：`qq.message.created`，仅支持已配对本人的私聊。
- 事件订阅、续期和取消；回调目标限定为 `https://connectors.api.openai.com`。

## 部署前提

- Cloudflare Workers 账户及 SQLite Durable Objects。
- 支持 C2C 私聊事件的 QQ 机器人应用，以及只允许本人身份的 Cloudflare Access 应用。
- 支持 Managed OAuth 和本项目 MCP 事件扩展的客户端/连接器。OAuth、Access 策略和连接器登记需自行配置，普通 MCP 客户端不一定支持事件订阅。
- **中国大陆网络可访问、腾讯 QQ 平台服务器实际可达的 HTTPS 回调域名。** 配置公网 DNS、有效 TLS 证书和 Worker 域名路由。默认 `workers.dev` 的大陆可达性无保证，使用自定义域名也需实测；模板已关闭 `workers.dev`。

QQ 控制台填写完整回调地址，例如 `https://qq-webhook.example.com/qq/webhook`，替换为自己的域名。本项目只接受 HTTPS 默认 443 端口上的 POST `/qq/webhook`，不接受查询参数、末尾斜杠或其他路径。

回调路径不能要求交互式 Access 登录、验证码或浏览器挑战；`/mcp` 和 `/auth-check` 必须保留身份保护。部署后先从大陆网络检查 DNS/TLS，再通过 QQ 平台完成地址验证。浏览器打开、GET/HEAD 或 `/health` 成功不能代替实际回调验收。

ICP 备案要求按托管地区、接入服务和平台配置核对，不是所有 webhook 部署的统一要求。详见 [部署网络验收](docs/SETUP.md#部署网络验收先于配对)及 [QQ 官方事件文档](https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/event-emit.html)。

## 快速开始

要求 Node.js 24.11+（24.x）和 npm 11.x。

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check
cp wrangler.example.jsonc wrangler.jsonc
cp .dev.vars.example .dev.vars
```

`check` 执行类型检查、本地构建、测试、秘密模式扫描和格式检查。私有配置已加入忽略规则；`.dev.vars` 不会自动成为线上 Worker secrets。

## 配置

填入以下配置，再按 [安装指南](docs/SETUP.md) 为全新 Worker 补齐账户、域名路由、`BRIDGE` 绑定和 SQLite 迁移：

- `ACCESS_HOSTNAME`：MCP 主机名，不含协议、端口或路径。
- `ACCESS_TEAM_DOMAIN`：自己的 `<team>.cloudflareaccess.com`。
- `ACCESS_AUD`、`ACCESS_OWNER_EMAIL`：Access 应用 audience 和唯一允许的本人邮箱，邮箱区分大小写。
- `QQ_WEBHOOK_HOSTNAME`：可选的独立回调主机名；未设置时使用 MCP 主机名。独立主机仅提供 POST `/qq/webhook`。
- `QQ_APP_ID`、`QQ_APP_SECRET`：QQ 机器人应用凭据。
- `CALLBACK_KEYRING`：回调加密密钥配置，格式见 [示例](.dev.vars.example)及 [安全说明](docs/SECURITY.md)。示例密钥无效，部署前须替换。
- `PAIRING_ENABLED`、`BRIDGE_ENABLED`、`EVENTS_ENABLED`、`MCP_WRITE_ENABLED`：初始全部关闭，仅字符串 `"true"` 开启。

凭据只放在私有配置或 secret bindings 中。现有部署必须保留自己的 Worker、namespace、迁移历史和 owner 数据，不要套用新安装迁移。

## 首次配对

1. 完成 QQ 回调地址验证，保持三个业务开关关闭，只开启 `PAIRING_ENABLED`。
2. 本人通过 Access 认证，调用 `start_pairing`（参数 `{}`），取得仅显示一次、最长 10 分钟有效的配对码。
3. 在自己的 QQ 机器人私聊中发送原样配对码。不要公开或转交他人，持有码的账号可完成绑定。
4. 调用 `bridge_status`，确认 `owner_bound: true`。配对不会自动回复 QQ 消息。
5. 关闭 `PAIRING_ENABLED`，按需开启接收、事件和回复能力，并由客户端建立事件订阅。

发码超时或响应丢失时先查状态；拿不到原码需等待其失效后重新发起。已绑定身份不可换绑；owner 丢失、变更或指纹不符会永久阻断，恢复旧值也不会自动解锁。没有解绑或重置 API。完整步骤见 [首次安装与配对](docs/SETUP.md)。

## 运行与安全

- 消息正文保留 1 小时，最多 100 条，每分钟最多接收 10 条；正文没有应用层加密。回调 URL 和 secret 使用 AES-256-GCM 加密。
- 没有活动订阅时不补发历史事件。事件和 QQ 回复发送结果不确定时不自动重试，可能丢失事件或回复。
- 回复窗口为源消息之后 5 分钟，最多 1500 个 UTF-16 code units；这是项目限制。
- 5 秒请求预算不能撤回已接受的写入或网络请求，不保证端到端延迟。
- 不提交凭据、配对码或数据库；不部署含合成身份和管理入口的测试包装器。

详见 [安全与隐私](docs/SECURITY.md)和 [配对安全评审](docs/PAIRING-REVIEW.md)。

## 验证状态

本地干净安装、构建和 123 项测试已通过，包含 workerd/SQLite 配对、认证、并发、重放、回滚和重启测试。**真实 QQ/Managed OAuth 端到端验收及部署域名的大陆连通性尚未验证。** 详见 [验证记录](docs/VALIDATION.md)和 [发布检查表](docs/RELEASE-CHECKLIST.md)。

## 许可证

[MIT](LICENSE)。依赖使用各自许可证。

## 相关项目

- [grokbot-qqbot-bridge](https://github.com/number5meme/grokbot-qqbot-bridge)：QQ 与通用 HTTP webhook 桥接。
- [grokbot-wechatclaw-bridge](https://github.com/number5meme/grokbot-wechatclaw-bridge)：微信 ClawBot 桥接。
- [grokbot-larkbot-bridge](https://github.com/number5meme/grokbot-larkbot-bridge)：Lark 机器人桥接。

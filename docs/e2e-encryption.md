# 端到端加密设计

> **简体中文** · [English](en/e2e-encryption.md)

本仓（fork）在上游基线之外增加了局域网端到端加密（E2E）。上游文档（[`protocol.md`](protocol.md)、[`tech-design.md`](tech-design.md)）保持原样，本文只记录这条**本地扩展**的设计、边界与排障方式。

一句话概括：两个都声明 `e2e1` 能力的节点之间，单聊与群聊文本用 X25519 协商出的会话密钥做 AES-256-GCM 加密；只要有一端是上游原版，消息自动按明文收发，不需要任何开关。

## 1. 定位与范围

| 项 | 结论 |
|---|---|
| 引入方式 | 仅存在于本 fork 的 `main`，上游 v0.60.2 不含此特性 |
| 开关 | 无开关，默认自动启用 |
| 用户交互 | 无口令、无确认步骤；首次启动自动生成身份密钥对 |
| 协商条件 | 双方 profile 的 `caps` 都含 `e2e1`（`CAPS.e2eEncrypted`）且已保存对端公钥 |
| 上游兼容 | 对端无 `e2e1` 时静默走明文，双向兼容，不会打断既有功能 |

### 加密覆盖范围

| 数据类型 | 是否加密 | 载荷类型 |
|---|---|---|
| 单聊文本 | ✅ | `encrypted-text` |
| 群聊文本 | ✅ 逐成员 | `encrypted-group-text` |
| 文件传输与文件元数据 | ❌ 未实现 | 文件相关报文仍为明文 |
| 在线状态、资料广播、探活 | ❌ 始终明文 | `entry` / `alive` / `profile` 的载荷本身不加密 |

> 注意：`CAPS.e2eEncrypted` 的注释与设置页文案写成"消息和文件元数据"，其中"文件元数据"目前**超出实现范围**，见第 11 节。

## 2. 威胁模型

### 覆盖的威胁

- 同一局域网内的被动嗅探：抓包拿到的文本载荷是 AES-256-GCM 密文。
- 无密钥的主动中间人：无法解密，也无法伪造出能通过 GCM 认证标签的密文。
- 密钥协商过程中的窃听：ECDH 共享密钥由私钥推导，抓包只能拿到双方公钥。

### 不覆盖的威胁

| 威胁 | 说明 |
|---|---|
| 端点被控 | 恶意软件或调试权限可读进程内存、`identity.json`，等价于拿到私钥 |
| 元数据 | 谁与谁通信、消息长度、时间、在线状态、资料内容均不隐藏 |
| 发送者身份冒充 | 解密只使用报文内嵌的 `senderPubKey`，未与库中对端公钥比对；能篡改报文的攻击者可用自己的密钥冒充发送者（但读不到内容）。指纹带外核对可发现 |
| 前向保密 | 长期身份密钥直接参与每次 ECDH，身份私钥泄露即历史密文可解 |
| 重放 | GCM 只保证完整性与来源，协议层没有防重放序号（依赖现有消息去重窗口） |
| 拒绝服务 | 明文探测/阻塞类攻击不在防护范围 |

## 3. 密码学设计

实现位置：`src/main/services/crypto.ts`（纯 Node `crypto`，零第三方依赖）。

| 环节 | 算法 / 参数 |
|---|---|
| 身份密钥 | X25519 密钥对，长期有效；存储的是 32 字节原始密钥，构造 `KeyObject` 时补 `SPKI`/`PKCS8` DER 前缀 |
| 密钥协商 | X25519 ECDH（`crypto.diffieHellman`，因为 `createECDH` 不支持 x25519） |
| 密钥派生 | HKDF-SHA256，`salt` = 每次加密随机 32 字节，`info` = `teahouse-e2ee-v1`，输出 32 字节 AES 密钥 |
| 对称加密 | AES-256-GCM，`iv` 每次随机 12 字节，使用认证标签 |
| 指纹 | `SHA-256(公钥原始 32 字节)` 取前 16 字节 → 32 位十六进制（`src/main/util/key-fingerprint.ts`，纯函数，无 Electron 依赖） |
| 私钥落盘 | `identity.json` 中的 `wrappedPrivateKey`，优先用 Electron `safeStorage` 加密（`wrappedPrivateKeyEnc: true`）；`safeStorage` 不可用时退化为明文并置 `false` |

密文载荷（`EncryptedPayload`）：

```json
{
  "ciphertext": "base64",
  "iv": "base64（12 字节）",
  "authTag": "base64",
  "salt": "base64（32 字节）",
  "senderPubKey": "base64（发送方 32 字节 X25519 公钥）"
}
```

每次加密都使用新的随机 `salt` 与 `iv`，因此同一明文两次发送的密文不同；解密只需报文内嵌的 `senderPubKey` + 本机私钥，**不依赖对端公钥是否已入库**。

## 4. 能力声明与密钥协商

### 4.1 报文

| 位置 | 内容 |
|---|---|
| `Profile.pubKey`（可选） | 本机 X25519 公钥（base64）；随 `entry` / `alive` / `profile` 广播，声明 `e2e1` 时携带 |
| `MSG_TYPES.keyExchange` = `'key-exchange'` | 独立信封，载荷 `KeyExchangePayload { pubKey, fingerprint }`，走现有 TCP 可靠通道 |
| `CAPS.e2eEncrypted` = `'e2e1'` | 能力位；双方都声明才加密 |

### 4.2 协议层校验（`src/main/net/codec.ts`）

- `Profile.pubKey`：可缺省；出现时必须能按**标准 base64** 解出 32 字节 X25519 公钥，且长度 ≤ 100。
- `key-exchange`：`pubKey` 与 `fingerprint` 都必填，`fingerprint` 必须是 32 位十六进制。
- 校验失败按现有约定**丢弃整包**（不回复、不抛错），因此畸形载荷不会污染节点表或密钥库。

### 4.3 协商时序

1. 启动：`CryptoService` 读 `identity.json`；`ensureKeys()`（必须在注册 `ready` 监听之后显式调用）解包已有私钥或生成新密钥对 → `[e2e] crypto ready, pubKey fingerprint=…`。
2. 发现：广播的 `entry` / `alive` / `profile` 携带 `pubKey`（`[e2e] broadcast profile, pubKey=yes|no`）；收到时打印 `[e2e] recv <type> from …, pubKey=…, caps=…`。
3. 落库：节点表 1 秒周期把内存资料写入 `peers` 表，含 `pub_key`（`[e2e] peers.pub_key written …`）。
4. 交换：收到 `key-exchange` → `[e2e] recv keyExchange from …` → `savePeerPubKey` 写库（**不需要**本机私钥就绪）→ 同步更新内存 registry 并 `emit('updated')`（让渲染层指纹立刻刷新）→ 回发本机 `key-exchange`（`[e2e] replying keyExchange to …`），用 `peersKeyExchanged` 去重。
5. 补发：registry `updated` 触发的 200ms 节流推送里，对"在线 + 声明 `e2e1` + 未交换过"的节点补发 `key-exchange`（`[e2e] sending keyExchange to …`）。
6. 未就绪窗口：本机 crypto 尚未 ready 时收到的 `key-exchange` 仍然先落库；本机 ready 后由第 5 步的推送循环补发。

> `peersKeyExchanged` 只记录"已经发过 key-exchange"的节点，避免重复发送；对端换钥（例如 `resetKeys`）由对端新的 `pubKey` 广播与 `key-exchange` 自然覆盖。

## 5. 发送与接收

### 单聊（`src/main/services/chat.ts`）

```
shouldEncrypt = crypto.isReady()
             && peerStore.hasE2eCapability(peerId)   // caps 含 e2e1
             && peerStore.getPubKey(peerId)          // 已保存对端公钥
```

- 加密决策**只读 SQLite**（`peers.caps` / `peers.pub_key`），不依赖内存 registry，因此内存资料抖动不会导致明文降级。
- 加密成功：报文 `kind: 'encrypted-text'`（密文 + `iv` + `authTag` + `salt` + `senderPubKey`），本地入库 `encrypted = 1`（气泡显示锁图标）。
- 加密返回 `null`（密钥缺失或异常）：**降级明文发送**，并打印 `[e2e] encryptText returned null, fallback to plaintext` —— 排障时最需要关注的告警。
- 接收：`encrypted-text` → 组装 `EncryptedPayload` → `decryptText`（只需报文内嵌 `senderPubKey` + 本机私钥）；解密失败保留原文并标记未解密（`[e2e] decrypt failed`）。

### 群聊（`src/main/services/groups.ts`）

- 逐成员决策：`memberPubKey && crypto.shouldEncrypt(member)` → 该成员收到 `encrypted-group-text`；否则该成员单独收到明文 `group-text`（逐成员降级，不影响其他成员）。
- 成员公钥同样来自 `peers.pub_key`（`getPeerPubKey` 注入），每个成员用各自协商的密钥加密，不存在群共享密钥。

## 6. 存储

| 位置 | 内容 |
|---|---|
| `peers.pub_key`（迁移追加，`TEXT NOT NULL DEFAULT ''`） | 对端公钥；`upsert` 使用 `CASE WHEN excluded.pub_key != '' THEN excluded.pub_key ELSE pub_key END`，**空值永不覆盖已有公钥** |
| `messages.encrypted`（迁移追加，`INTEGER NOT NULL DEFAULT 0`） | 本地消息是否以密文发送，映射为 `MsgRow.encrypted: boolean` |
| `userData/data/identity.json` | `{ publicKey, fingerprint, wrappedPrivateKey, wrappedPrivateKeyEnc }`；`wrappedPrivateKeyEnc: false` 表示 `safeStorage` 不可用、私钥明文回退存储 |

两层公钥保护：

1. **存储层**（既有）：`peers.pub_key` 空值不覆盖，保证周期性落库不会把已协商公钥写空。
2. **节点表层**（本次合并加固）：`PeerRegistry.touch` 在对端资料未携带 `pubKey` 时沿用已知值，避免内存态被清空导致界面指纹闪烁/消失；对端 `pubKey` 非空时仍照常覆盖，保证换钥生效。

## 7. 界面表现

| 位置 | 表现 | 数据来源 |
|---|---|---|
| 设置 → 安全 | 端到端加密状态（已启用/未启用）、本机指纹、重置密钥按钮 | `e2e:get-status` / `e2e:reset-keys` / `e2e:status-changed`（`window.pantry.e2eGetStatus()` 等） |
| 消息气泡 | 密文消息显示锁图标 | `messages.encrypted` → `PeerView`/消息行的 `encrypted` |
| 单聊标题区 | 对端指纹（用于带外核对） | `PeerView.e2eFingerprint`，由内存 registry 的 `profile.pubKey` 现算 |
| 会话搜索结果 | 同上的指纹字段 | `services/search.ts` 用 `fingerprintFromPubKey` 现算 |

`E2eStatusView = { hasKeys, unlocked, fingerprint }`；`unlocked` 为 false 时说明私钥未解包（`safeStorage` 失败或密钥被重置），此时不会加密。

## 8. 降级行为与排障

加密是"尽力而为"：任何一步失败都不阻断消息收发，代价是明文或不可解密。全部诊断信息以 `[e2e]` 前缀打印在主进程日志里。

### 日志清单

| 日志 | 含义 |
|---|---|
| `[e2e] crypto ready, pubKey fingerprint=…` | 本机密钥就绪 |
| `[e2e] broadcast profile, pubKey=yes/no` | 广播的资料是否带公钥（`no` 说明密钥未就绪） |
| `[e2e] recv entry/alive/profile from …, pubKey=…, caps=…` | 对端资料是否带公钥与 `e2e1` |
| `[e2e] recv keyExchange from …, fingerprint=…` | 收到对端交换请求 |
| `[e2e] registry pubKey updated for …` / `[e2e] keyExchange from unknown node …, persisted only` | 交换后是否命中内存节点表 |
| `[e2e] replying keyExchange to …` | 已回复对端 |
| `[e2e] sending keyExchange to …` | 补发交换（含 `(registry updated)` 变体） |
| `[e2e] persist peers: N total, M with pubKey` | 周期落库时的公钥覆盖数（仅在变化时打印） |
| `[e2e] savePeerPubKey …, fingerprint=…` / `[e2e] peers.pub_key written …` | 公钥写库 |
| `[e2e] shouldEncrypt(x): true / false (…)` | 加密决策与原因：`keyPair=null`、`peer has no e2e1 cap`、`peer pubKey unknown` |
| `[e2e] sendText to …: cryptoReady=…, shouldEncrypt=…` | 单聊发送决策 |
| `[e2e] encrypt ok, cipherLen=…` / `[e2e] no encryption (shouldEncrypt=false)…` | 单聊加密结果 |
| `[e2e] encryptText returned null, fallback to plaintext` | **告警**：应加密但失败了，本条已明文发出 |
| `[e2e] recv encrypted msg from …` / `[e2e] decrypt ok/failed, plainLen=…` | 单聊解密结果 |
| `[e2e] local crypto not ready, cannot decrypt` | 本机未就绪，无法解密（重启后一般自愈） |
| `[e2e] group send x: pubKey=…, encrypt=…` | 群聊逐成员决策 |
| `[e2e] recv encrypted group msg from …` / `[e2e] group decrypt ok/failed` | 群聊解密结果 |
| `[e2e] new keypair generated, fingerprint=…` / `[e2e] keys unlocked from identity` / `[e2e] stored key unusable, regenerating` | 密钥生命周期 |
| `[e2e] safeStorage unavailable…` / `[e2e] OS keychain not available…` / `[e2e] failed to unwrap private key:` | 私钥保护降级为明文存储 |

### 症状对照

| 症状 | 排查方向 |
|---|---|
| 一直明文发送 | 看 `shouldEncrypt(x)` 的原因：对端没声明 `e2e1`（上游原版）、或 `peers.pub_key` 为空（还没收到 `key-exchange`） |
| 密文但对方显示无法解密 | 对方 `resetKeys` 或重装后公钥已变；等其新 profile 覆盖 `pub_key`，或核对双方指纹 |
| 日志出现 `encryptText returned null` | 本机密钥被重置或对端公钥缺失；先重启应用，若仍出现则检查 `identity.json` 能否正常解包（`[e2e] failed to unwrap private key`） |
| 指纹栏为空 | 内存节点表还没有对端 `pubKey`；等下一次 `alive`/`profile` 或 `key-exchange` |
| 双方都在同一网段却始终不交换 | 检查 TCP 可靠通道是否连通（`key-exchange` 走 TCP，不走 UDP 广播） |

## 9. 与上游原版的兼容性

- 我们不向未声明 `e2e1` 的节点发送密文，因此上游节点收到的永远是它能处理的明文报文。
- 上游节点收到 `key-exchange` 时：`codec` 的载荷校验 `default` 分支只要求载荷是对象，能正常解出；其主进程没有对应类型的分支，于是**静默忽略**，不会报错、不会回包，也不影响既有流程。
- 上游节点升级为本 fork 版本后：下一次 `alive`/`profile` 广播即带上公钥，随后 `key-exchange` 自动完成，无需用户操作。
- 本 fork 节点间的 `profile`/`alive` 增加了可选 `pubKey` 字段；上游节点的 `codec` 对未知字段宽容（`validateProfile` 只校验已知字段），不会因此丢弃报文。

## 10. 测试覆盖

| 文件 | 覆盖点 |
|---|---|
| `src/main/services/crypto.test.ts` | 加解密往返一致、从私钥推导公钥一致、错误私钥解密失败、指纹为 32 位 hex 且由公钥唯一确定、群聊逐成员各自可解、`ensureKeys` 自动生成并触发 `ready`、重启后从包裹私钥恢复同一密钥对、`resetKeys` 生成新指纹、`identity.json` 存的是包裹私钥而非明文、`wrapPrivateKey`/`unwrapPrivateKey` 往返与明文回退 |
| `src/main/net/codec.test.ts`（`describe('codec 端到端加密')`） | 真实 X25519 公钥（含 `+` `/` `=` 的标准 base64）在 `profile`/`entry`/`alive` 上可往返、`key-exchange` 用真实公钥与 32 位指纹可往返、空/非法公钥与错误长度指纹被拒收、`profile` 携带非法 `pubKey` 被拒收 |
| `src/main/services/chat.test.ts` | 加密发送的本地消息标记 `encrypted`，明文发送不标记 |
| `src/main/services/groups.test.ts` | 群聊加密/明文逐成员分支 |
| `src/main/net/peer-registry.test.ts` | **本次加固回归**：对端资料未携带 `pubKey` 时保留已协商公钥；`pubKey` 非空时照常覆盖；双方都无公钥时不引入 `pubKey` 键（避免资料比对永久失配） |

运行方式：

```bash
npx vitest run src/main/services/crypto.test.ts src/main/net/codec.test.ts
npm test        # 全量（含网络回环；Windows 上个别端口可能落在保留区间导致 EACCES，属环境问题）
```

## 11. 已知限制与后续工作

1. **文件与文件元数据未加密**：当前只覆盖单聊/群聊文本。`CAPS.e2eEncrypted` 的注释与设置页文案提到"文件元数据"，与实现不一致，需在后续版本补齐实现或修正文案。
2. **无前向保密**：长期身份密钥直接参与 ECDH，身份私钥泄露即可解历史密文；如需前向保密，应引入临时密钥（如 X3DH/双棘轮）并新增能力位。
3. **无身份核验流程**：目前只展示指纹供人工带外核对，没有"首次接触即信任（TOFU）"的确认弹窗，也没有指纹变更告警。
4. **不校验发送方公钥**：解密只用报文内嵌 `senderPubKey`，未与 `peers.pub_key` 比对，理论上存在冒充发送者（无法读内容）的可能。
5. **无密钥轮换与撤销**：`resetKeys` 后不会主动通知对端清除旧公钥，对端在下一次 profile 覆盖前发给本机的密文无法解密。
6. **无逐条防重放**：仅依赖 GCM 完整性与既有消息去重窗口。
7. **`key-exchange` 无版本/算法协商**：算法参数写在代码常量里，未来升级需要新的能力位区分。
8. **调试日志保留**：本 fork 有意保留全部 `[e2e]` 日志（便于向上游提 PR 时复现与验证）；正式发布前如需降噪，应改为按设置项开关。

## 12. 相关代码入口

| 关注点 | 位置 |
|---|---|
| 密码学原语、`CryptoService`、密钥生命周期 | `src/main/services/crypto.ts` |
| 指纹纯函数（services/search 复用） | `src/main/util/key-fingerprint.ts` |
| 协议字段与常量（`Profile.pubKey`、`KeyExchangePayload`、`CAPS.e2eEncrypted`） | `src/shared/protocol.ts` |
| 收发校验（pubKey / fingerprint 正则与拒收） | `src/main/net/codec.ts` |
| `key-exchange` 收发、周期性补发、落库 | `src/main/index.ts` |
| 资料广播与接收（含 `pubKey`） | `src/main/net/discovery.ts` |
| 节点表与公钥保留加固 | `src/main/net/peer-registry.ts` |
| 公钥存储与空值保护 | `src/main/store/peers-repo.ts` + `src/main/store/migrations.ts` |
| 单聊加密发送/解密接收 | `src/main/services/chat.ts` |
| 群聊逐成员加密 | `src/main/services/groups.ts` |
| IPC 契约（`e2e:get-status` / `e2e:reset-keys` / `e2e:status-changed`、`PeerView.e2eFingerprint`） | `src/shared/ipc.ts` |
| 设置页与消息锁图标 | `src/renderer/src/SettingsApp.vue`、`src/renderer/src/components/MessageRow.vue` |




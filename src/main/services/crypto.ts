// 端到端加密服务：X25519 密钥协商 + AES-256-GCM 对称加密
// 零外部依赖，仅使用 Node 16.17 内置 crypto 模块。

import {
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  createHash,
  createHmac,
  randomBytes,
  scryptSync
} from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { EventEmitter } from 'node:events'
import { safeStorage } from 'electron'
import { fingerprintFromPubKey } from '../util/key-fingerprint'

// ─── X25519 原始密钥 ↔ DER 包装 ──────────────────────────────────────────────
// Node 的 createECDH 不支持 x25519，必须用 crypto.diffieHellman + KeyObject。
// 这里存储的是 32 字节原始密钥，需要补上 DER 头才能构造 KeyObject。

/** X25519 公钥 SPKI DER 头（12 字节） */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')
/** X25519 私钥 PKCS8 DER 头（16 字节） */
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/** 从 32 字节原始公钥构造 KeyObject */
function publicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki'
  })
}

/** 从 32 字节原始私钥构造 KeyObject */
function privateKeyFromRaw(raw: Buffer): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8'
  })
}

/** 从原始私钥推导对应的 32 字节原始公钥 */
function publicRawFromPrivate(privateKeyBase64: string): Buffer {
  const privObj = privateKeyFromRaw(Buffer.from(privateKeyBase64, 'base64'))
  const der = createPublicKey(privObj).export({ type: 'spki', format: 'der' }) as Buffer
  return Buffer.from(der).subarray(der.length - 32)
}

/** X25519 密钥协商：用私钥和对方公钥计算 32 字节共享密钥 */
function x25519SharedSecret(privateKeyBase64: string, publicKeyBase64: string): Buffer {
  const privateKey = privateKeyFromRaw(Buffer.from(privateKeyBase64, 'base64'))
  const publicKey = publicKeyFromRaw(Buffer.from(publicKeyBase64, 'base64'))
  return diffieHellman({ privateKey, publicKey })
}

// ─── 常量 ───────────────────────────────────────────────────────────────────

const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12       // GCM 推荐 12 字节
const SALT_LENGTH = 32     // HKDF salt
const KEY_LENGTH = 32      // AES-256
const HKDF_INFO = 'teahouse-e2ee-v1'
const FINGERPRINT_LENGTH = 16 // SHA-256 前 16 字节 = 32 hex chars

// ─── 类型 ───────────────────────────────────────────────────────────────────

export interface EncryptedPayload {
  /** AES-256-GCM 密文（base64） */
  ciphertext: string
  /** 初始化向量（base64） */
  iv: string
  /** 认证标签（base64） */
  authTag: string
  /** HKDF salt（base64） */
  salt: string
  /** 发送方 X25519 公钥（base64） */
  senderPubKey: string
}

export interface E2eKeyPair {
  /** X25519 公钥（base64） */
  publicKey: string
  /** X25519 私钥（base64） */
  privateKey: string
  /** 公钥指纹（hex，32 字符） */
  fingerprint: string
}

export interface CryptoDeps {
  /** 获取当前节点 ID */
  selfId: string
  /** identity.json 文件路径（用于持久化密钥） */
  identityPath: string
  /** 对端公钥存储（peers 表） */
  peerStore: {
    getPubKey(nodeId: string): string | null
    hasE2eCapability(nodeId: string): boolean
    updatePubKey(nodeId: string, pubKey: string): void
  }
}

// ─── 密钥生成 ────────────────────────────────────────────────────────────────

/** 生成 X25519 密钥对 */
export function generateKeyPair(): E2eKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  })
  // 提取原始 32 字节密钥（去掉 DER 头部）
  const rawPub = publicKey.subarray(publicKey.length - 32)
  const rawPriv = privateKey.subarray(privateKey.length - 32)

  const pubBase64 = rawPub.toString('base64')
  const privBase64 = rawPriv.toString('base64')
  const fingerprint = createHash('sha256').update(rawPub).digest('hex').slice(0, FINGERPRINT_LENGTH * 2)

  return { publicKey: pubBase64, privateKey: privBase64, fingerprint }
}

/** 从 base64 公钥提取指纹（不需私钥）；实现见 util/key-fingerprint（纯函数，可被 search 等复用） */
export { fingerprintFromPubKey } from '../util/key-fingerprint'

// ─── 密码保护 ────────────────────────────────────────────────────────────────

/** 用用户密码加密私钥（PBKDF2 + AES-256-GCM） */
export function encryptPrivateKey(privateKeyBase64: string, password: string): {
  encryptedKey: string
  iv: string
  authTag: string
  salt: string
} {
  const salt = randomBytes(SALT_LENGTH)
  const key = scryptSync(password, salt, KEY_LENGTH)
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv(ALGORITHM, key, iv)

  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(privateKeyBase64, 'base64')),
    cipher.final()
  ])
  const authTag = cipher.getAuthTag()

  return {
    encryptedKey: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    salt: salt.toString('base64')
  }
}

/** 用用户密码解密私钥 */
export function decryptPrivateKey(
  encryptedKeyBase64: string,
  password: string,
  ivBase64: string,
  authTagBase64: string,
  saltBase64: string
): string | null {
  try {
    const salt = Buffer.from(saltBase64, 'base64')
    const key = scryptSync(password, salt, KEY_LENGTH)
    const iv = Buffer.from(ivBase64, 'base64')
    const authTag = Buffer.from(authTagBase64, 'base64')
    const encrypted = Buffer.from(encryptedKeyBase64, 'base64')

    const decipher = createDecipheriv(ALGORITHM, key, iv)
    decipher.setAuthTag(authTag)

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ])

    return decrypted.toString('base64')
  } catch {
    return null // 密码错误或数据损坏
  }
}

// ─── HKDF 密钥派生 ───────────────────────────────────────────────────────────

/** 从 ECDH 共享密钥派生 AES 密钥（简化的 HKDF-like） */
function deriveAesKey(sharedSecret: Buffer, salt: Buffer): Buffer {
  // 使用 HMAC-SHA256 作为 PRF（简化 HKDF-Extract + HKDF-Expand）
  const prk = createHmac('sha256', salt).update(sharedSecret).digest()
  const derived = createHmac('sha256', prk)
    .update(Buffer.from(HKDF_INFO, 'utf8'))
    .update(Buffer.from([0x01])) // counter
    .digest()
  return derived.subarray(0, KEY_LENGTH)
}

// ─── 核心加密/解密 ───────────────────────────────────────────────────────────

/**
 * 使用接收方公钥加密消息
 * @param plaintext 明文
 * @param recipientPubKeyBase64 接收方 X25519 公钥（base64）
 * @param senderPrivateKeyBase64 发送方 X25519 私钥（base64）
 */
export function encryptForPeer(
  plaintext: string,
  recipientPubKeyBase64: string,
  senderPrivateKeyBase64: string
): EncryptedPayload {
  // ECDH 密钥协商（X25519 via crypto.diffieHellman）
  const sharedSecret = x25519SharedSecret(senderPrivateKeyBase64, recipientPubKeyBase64)

  // 生成随机 salt 和 IV
  const salt = randomBytes(SALT_LENGTH)
  const iv = randomBytes(IV_LENGTH)

  // 派生 AES 密钥
  const aesKey = deriveAesKey(sharedSecret, salt)

  // 加密
  const cipher = createCipheriv(ALGORITHM, aesKey, iv)
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ])
  const authTag = cipher.getAuthTag()

  // 发送方公钥（供接收方反向协商）
  const senderPub = publicRawFromPrivate(senderPrivateKeyBase64)

  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    salt: salt.toString('base64'),
    senderPubKey: senderPub.toString('base64')
  }
}

/**
 * 使用自己的私钥解密对端发来的消息
 */
export function decryptFromPeer(
  payload: EncryptedPayload,
  recipientPrivateKeyBase64: string
): string | null {
  try {
    // ECDH 密钥协商（与发送方计算相同的共享密钥）
    const sharedSecret = x25519SharedSecret(recipientPrivateKeyBase64, payload.senderPubKey)

    // 派生 AES 密钥
    const salt = Buffer.from(payload.salt, 'base64')
    const aesKey = deriveAesKey(sharedSecret, salt)

    // 解密
    const iv = Buffer.from(payload.iv, 'base64')
    const authTag = Buffer.from(payload.authTag, 'base64')
    const ciphertext = Buffer.from(payload.ciphertext, 'base64')

    const decipher = createDecipheriv(ALGORITHM, aesKey, iv)
    decipher.setAuthTag(authTag)

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ])

    return decrypted.toString('utf8')
  } catch {
    return null // 解密失败（密钥不匹配、数据损坏等）
  }
}

// ─── 群聊加密 ────────────────────────────────────────────────────────────────

export interface GroupEncryptedResult {
  /** 接收方 nodeId → 加密后的载荷 */
  encryptedForMember: Map<string, EncryptedPayload>
}

/**
 * 群聊 per-member 加密
 * 对每个成员分别做 X25519 协商 + AES-256-GCM 加密（与单聊同一套方案），
 * 保证接收方用 decryptFromPeer 即可解密。
 * 注：groups.ts 实际逐成员调用 encryptText，此函数为批量封装，保持接口一致。
 */
export function encryptForGroup(
  plaintext: string,
  memberPubKeys: Map<string, string>,
  senderPrivateKeyBase64: string
): GroupEncryptedResult {
  const encryptedForMember = new Map<string, EncryptedPayload>()
  for (const [memberId, memberPubKeyBase64] of memberPubKeys) {
    encryptedForMember.set(
      memberId,
      encryptForPeer(plaintext, memberPubKeyBase64, senderPrivateKeyBase64)
    )
  }
  return { encryptedForMember }
}

// ─── 密钥交换服务 ────────────────────────────────────────────────────────────

export interface E2eStatusView {
  hasKeys: boolean
  unlocked: boolean
  hasPassword: boolean
  rememberPassword: boolean
  fingerprint: string
}

export class CryptoService extends EventEmitter {
  private keyPair: E2eKeyPair | null = null
  private deps: CryptoDeps
  private identityData: {
    encryptedPrivateKey?: string
    encryptedKeyIv?: string
    encryptedKeyAuthTag?: string
    encryptedKeySalt?: string
    publicKey?: string
    fingerprint?: string
    rememberPassword?: boolean
    passwordHash?: string
    encryptedPassword?: string
  } | null = null

  constructor(deps: CryptoDeps) {
    super()
    this.deps = deps
    this.loadIdentity()
    // 注意：不要在这里 autoUnlock —— 'ready' 事件会早于外部监听器注册而丢失。
    // 由 index.ts 在注册 crypto.on('ready') 之后显式调用 tryAutoUnlock()。
  }

  /** 从 identity.json 加载密钥数据 */
  private loadIdentity(): void {
    try {
      if (existsSync(this.deps.identityPath)) {
        const data = JSON.parse(readFileSync(this.deps.identityPath, 'utf8'))
        this.identityData = data
      }
    } catch {
      // 文件不存在或解析失败，忽略
    }
  }

  /** 启动时自动解锁：rememberPassword=true 且 encryptedPassword 存在时，用 safeStorage 解密密码并 unlock。
   *  必须在外部注册 'ready' 监听器之后调用。 */
  tryAutoUnlock(): void {
    if (!this.identityData?.rememberPassword || !this.identityData?.encryptedPassword) return
    try {
      const password = safeStorage.decryptString(Buffer.from(this.identityData.encryptedPassword, 'base64'))
      if (password) {
        const unlocked = this.unlock(password)
        console.log(`[e2e] autoUnlock: ${unlocked ? 'ok' : 'failed'}`)
      }
    } catch (err) {
      console.warn('[e2e] autoUnlock failed:', err)
    }
  }

  /** 持久化身份数据到 identity.json */
  private saveIdentity(): void {
    try {
      const dir = dirname(this.deps.identityPath)
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
      }
      // 读取现有数据并合并
      let existing: Record<string, unknown> = {}
      if (existsSync(this.deps.identityPath)) {
        existing = JSON.parse(readFileSync(this.deps.identityPath, 'utf8'))
      }
      const merged = { ...existing, ...this.identityData }
      writeFileSync(this.deps.identityPath, JSON.stringify(merged, null, 2), 'utf8')
    } catch (err) {
      console.error('[crypto] 保存身份数据失败：', err)
    }
  }

  /** 设置用户密码并生成/加密密钥对 */
  setPassword(password: string, remember: boolean): boolean {
    try {
      // 如果还没有密钥对，先生成
      if (!this.identityData?.publicKey || !this.identityData?.encryptedPrivateKey) {
        const kp = generateKeyPair()
        const encrypted = encryptPrivateKey(kp.privateKey, password)
        this.identityData = {
          ...this.identityData,
          publicKey: kp.publicKey,
          fingerprint: kp.fingerprint,
          encryptedPrivateKey: encrypted.encryptedKey,
          encryptedKeyIv: encrypted.iv,
          encryptedKeyAuthTag: encrypted.authTag,
          encryptedKeySalt: encrypted.salt,
          rememberPassword: remember,
          passwordHash: createHash('sha256').update(password).digest('hex'),
          encryptedPassword: remember ? safeStorage.encryptString(password).toString('base64') : undefined
        }
        this.saveIdentity()
        // 设置密钥到内存，使服务就绪
        this.keyPair = kp
        this.emit('ready')
      } else {
        // 已有密钥，更新密码相关字段
        if (this.keyPair) {
          const encrypted = encryptPrivateKey(this.keyPair.privateKey, password)
          this.identityData = {
            ...this.identityData,
            encryptedPrivateKey: encrypted.encryptedKey,
            encryptedKeyIv: encrypted.iv,
            encryptedKeyAuthTag: encrypted.authTag,
            encryptedKeySalt: encrypted.salt,
            rememberPassword: remember,
            passwordHash: createHash('sha256').update(password).digest('hex'),
            encryptedPassword: remember ? safeStorage.encryptString(password).toString('base64') : undefined
          }
        } else {
          // 未解锁状态改密码：先用新密码解密旧密钥验证（如果可能），这里简化处理
          this.identityData = {
            ...this.identityData,
            rememberPassword: remember,
            passwordHash: createHash('sha256').update(password).digest('hex'),
            encryptedPassword: remember ? safeStorage.encryptString(password).toString('base64') : undefined
          }
        }
        this.saveIdentity()
        // 如果未解锁，尝试用新密码解锁
        if (!this.keyPair) {
          this.unlock(password)
        }
      }
      return true
    } catch (err) {
      console.error('[crypto] 设置密码失败：', err)
      return false
    }
  }

  /** 用密码解锁私钥 */
  unlock(password: string): boolean {
    if (!this.identityData?.encryptedPrivateKey) return false
    try {
      const privateKey = decryptPrivateKey(
        this.identityData.encryptedPrivateKey,
        password,
        this.identityData.encryptedKeyIv!,
        this.identityData.encryptedKeyAuthTag!,
        this.identityData.encryptedKeySalt!
      )
      if (!privateKey) return false
      this.keyPair = {
        publicKey: this.identityData.publicKey!,
        privateKey,
        fingerprint: this.identityData.fingerprint!
      }
      this.emit('ready')
      return true
    } catch {
      return false
    }
  }

  /** 锁定（清除内存中的私钥） */
  lock(): void {
    this.keyPair = null
    this.emit('locked')
  }

  /** 生成新的密钥对（会清除旧密钥） */
  resetKeys(password: string): boolean {
    try {
      const kp = generateKeyPair()
      const encrypted = encryptPrivateKey(kp.privateKey, password)
      this.identityData = {
        ...this.identityData,
        publicKey: kp.publicKey,
        fingerprint: kp.fingerprint,
        encryptedPrivateKey: encrypted.encryptedKey,
        encryptedKeyIv: encrypted.iv,
        encryptedKeyAuthTag: encrypted.authTag,
        encryptedKeySalt: encrypted.salt,
        passwordHash: createHash('sha256').update(password).digest('hex'),
        encryptedPassword: this.identityData?.rememberPassword
          ? safeStorage.encryptString(password).toString('base64')
          : undefined
      }
      this.saveIdentity()
      this.keyPair = kp
      this.emit('ready')
      return true
    } catch (err) {
      console.error('[crypto] 重置密钥失败：', err)
      return false
    }
  }

  /** 获取当前状态 */
  getStatus(): E2eStatusView {
    return {
      hasKeys: !!this.identityData?.publicKey,
      unlocked: this.keyPair !== null,
      hasPassword: !!this.identityData?.passwordHash,
      rememberPassword: this.identityData?.rememberPassword ?? false,
      fingerprint: this.identityData?.fingerprint ?? ''
    }
  }

  /** 保存对端公钥 */
  savePeerPubKey(nodeId: string, pubKey: string, fingerprint: string): void {
    console.log(`[e2e] savePeerPubKey ${nodeId}, fingerprint=${fingerprint}`)
    this.deps.peerStore.updatePubKey(nodeId, pubKey)
  }

  /** 从公钥计算指纹（静态方法，不需要私钥） */
  fingerprintFromPubKey(pubKeyBase64: string): string {
    return fingerprintFromPubKey(pubKeyBase64)
  }

  /** 设置当前节点的密钥对（启动时或密码解锁后调用） */
  setKeyPair(kp: E2eKeyPair | null): void {
    this.keyPair = kp
    if (kp) {
      this.emit('ready')
    }
  }

  /** 获取当前节点的密钥对 */
  getKeyPair(): E2eKeyPair | null {
    return this.keyPair
  }

  /** 服务是否就绪（密钥已解锁） */
  isReady(): boolean {
    return this.keyPair !== null
  }

  /** 检查是否应该与对端加密通信 */
  shouldEncrypt(nodeId: string): boolean {
    if (!this.keyPair) {
      console.log(`[e2e] shouldEncrypt(${nodeId}): false (keyPair=null)`)
      return false
    }
    if (!this.deps.peerStore.hasE2eCapability(nodeId)) {
      console.log(`[e2e] shouldEncrypt(${nodeId}): false (peer has no e2e1 cap)`)
      return false
    }
    if (!this.deps.peerStore.getPubKey(nodeId)) {
      console.log(`[e2e] shouldEncrypt(${nodeId}): false (peer pubKey unknown)`)
      return false
    }
    console.log(`[e2e] shouldEncrypt(${nodeId}): true`)
    return true
  }

  /** 加密文本消息给指定对端 */
  encryptText(plaintext: string, peerId: string): EncryptedPayload | null {
    if (!this.keyPair) return null
    const peerPubKey = this.deps.peerStore.getPubKey(peerId)
    if (!peerPubKey) return null
    return encryptForPeer(plaintext, peerPubKey, this.keyPair.privateKey)
  }

  /** 解密从对端收到的消息 */
  decryptText(payload: EncryptedPayload): string | null {
    if (!this.keyPair) return null
    return decryptFromPeer(payload, this.keyPair.privateKey)
  }

  /** 群聊加密：为每个在线成员分别加密 */
  encryptGroupText(
    plaintext: string,
    memberPubKeys: Map<string, string>
  ): GroupEncryptedResult | null {
    if (!this.keyPair) return null
    return encryptForGroup(plaintext, memberPubKeys, this.keyPair.privateKey)
  }

  /** 获取用于广播的公钥（base64） */
  getPublicKeyForBroadcast(): string | null {
    return this.keyPair?.publicKey ?? null
  }

  /** 获取指纹（用于 UI 展示） */
  getFingerprint(): string | null {
    return this.keyPair?.fingerprint ?? null
  }
}

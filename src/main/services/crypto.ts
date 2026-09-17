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
  randomBytes
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

/** 用操作系统密钥链（safeStorage）包裹私钥；不可用时明文回退并告警。
 *  返回 { wrapped, encrypted }：encrypted 标记 wrapped 是否为 safeStorage 密文。 */
export function wrapPrivateKey(privateKeyBase64: string): { wrapped: string; encrypted: boolean } {
  try {
    if (safeStorage.isEncryptionAvailable()) {
      return { wrapped: safeStorage.encryptString(privateKeyBase64).toString('base64'), encrypted: true }
    }
  } catch (err) {
    console.warn('[e2e] safeStorage unavailable, falling back to plaintext key:', err)
  }
  console.warn('[e2e] OS keychain not available; private key stored as plaintext')
  return { wrapped: privateKeyBase64, encrypted: false }
}

/** 解包私钥；失败返回 null（调用方应重新生成密钥对） */
export function unwrapPrivateKey(wrapped: string, encrypted: boolean): string | null {
  if (!encrypted) return wrapped
  try {
    const value = safeStorage.decryptString(Buffer.from(wrapped, 'base64'))
    return value || null
  } catch (err) {
    console.warn('[e2e] failed to unwrap private key:', err)
    return null
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

// ─── 密钥交换服务 ────────────────────────────────────────────────────────────

export interface E2eStatusView {
  hasKeys: boolean
  unlocked: boolean
  fingerprint: string
}

export class CryptoService extends EventEmitter {
  private keyPair: E2eKeyPair | null = null
  private deps: CryptoDeps
  private identityData: {
    publicKey?: string
    fingerprint?: string
    /** safeStorage 包裹（或明文回退）的私钥（base64） */
    wrappedPrivateKey?: string
    /** wrappedPrivateKey 是否为 safeStorage 密文；false/缺省表示明文回退 */
    wrappedPrivateKeyEnc?: boolean
  } | null = null

  constructor(deps: CryptoDeps) {
    super()
    this.deps = deps
    this.loadIdentity()
    // 注意：不要在这里生成/解锁密钥 —— 'ready' 事件会早于外部监听器注册而丢失。
    // 由 index.ts 在注册 crypto.on('ready') 之后显式调用 ensureKeys()。
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

  /** 确保密钥就绪（默认启用加密）：内存已有→就绪；有包裹密钥→解包；否则生成新密钥对。
   *  必须在外部注册 'ready' 监听器之后调用。 */
  ensureKeys(): void {
    if (this.keyPair) {
      this.emit('ready')
      return
    }
    const id = this.identityData
    if (id?.publicKey && id.wrappedPrivateKey) {
      const privateKey = unwrapPrivateKey(id.wrappedPrivateKey, id.wrappedPrivateKeyEnc === true)
      if (privateKey) {
        this.keyPair = { publicKey: id.publicKey, privateKey, fingerprint: id.fingerprint ?? '' }
        console.log('[e2e] keys unlocked from identity')
        this.emit('ready')
        return
      }
      console.warn('[e2e] stored key unusable, regenerating')
    }
    this.generateAndStore()
  }

  /** 生成新密钥对、用 safeStorage 包裹并落盘，随后就绪 */
  private generateAndStore(): void {
    const kp = generateKeyPair()
    const { wrapped, encrypted } = wrapPrivateKey(kp.privateKey)
    this.identityData = {
      ...this.identityData,
      publicKey: kp.publicKey,
      fingerprint: kp.fingerprint,
      wrappedPrivateKey: wrapped,
      wrappedPrivateKeyEnc: encrypted
    }
    this.saveIdentity()
    this.keyPair = kp
    console.log(`[e2e] new keypair generated, fingerprint=${kp.fingerprint}`)
    this.emit('ready')
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

  /** 生成全新的密钥对（无需密码，会清除旧密钥） */
  resetKeys(): boolean {
    try {
      this.generateAndStore()
      return true
    } catch (err) {
      console.error('[crypto] reset keys failed:', err)
      return false
    }
  }

  /** 获取当前状态 */
  getStatus(): E2eStatusView {
    return {
      hasKeys: !!this.identityData?.publicKey,
      unlocked: this.keyPair !== null,
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

  /** 获取用于广播的公钥（base64） */
  getPublicKeyForBroadcast(): string | null {
    return this.keyPair?.publicKey ?? null
  }

  /** 获取指纹（用于 UI 展示） */
  getFingerprint(): string | null {
    return this.keyPair?.fingerprint ?? null
  }
}

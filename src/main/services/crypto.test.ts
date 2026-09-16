import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  safeStorage: {
    isEncryptionAvailable: () => true,
    encryptString: (s: string) => Buffer.from(`enc:${s}`, 'utf8'),
    decryptString: (b: Buffer) => b.toString('utf8').replace(/^enc:/, '')
  }
}))

import {
  CryptoService,
  decryptFromPeer,
  encryptForPeer,
  encryptForGroup,
  fingerprintFromPubKey,
  generateKeyPair,
  unwrapPrivateKey,
  wrapPrivateKey
} from './crypto'

describe('X25519 + AES-256-GCM', () => {
  it('加解密往返一致', () => {
    const alice = generateKeyPair()
    const bob = generateKeyPair()

    const payload = encryptForPeer('你好，茶话会', bob.publicKey, alice.privateKey)
    const plaintext = decryptFromPeer(payload, bob.privateKey)

    expect(plaintext).toBe('你好，茶话会')
  })

  it('发送方公钥可从私钥推导且与生成结果一致', () => {
    const alice = generateKeyPair()
    const payload = encryptForPeer('hi', alice.publicKey, alice.privateKey)
    expect(payload.senderPubKey).toBe(alice.publicKey)
  })

  it('用错误私钥解密失败', () => {
    const alice = generateKeyPair()
    const bob = generateKeyPair()
    const eve = generateKeyPair()

    const payload = encryptForPeer('secret', bob.publicKey, alice.privateKey)
    expect(decryptFromPeer(payload, eve.privateKey)).toBeNull()
  })

  it('指纹由公钥唯一确定且为 32 位 hex', () => {
    const alice = generateKeyPair()
    const fp = fingerprintFromPubKey(alice.publicKey)
    expect(fp).toHaveLength(32)
    expect(fp).toBe(alice.fingerprint)
    expect(fingerprintFromPubKey(alice.publicKey)).toBe(fp)
  })

  it('群聊逐成员加密后各自可解密', () => {
    const alice = generateKeyPair()
    const bob = generateKeyPair()
    const carol = generateKeyPair()

    const result = encryptForGroup(
      '群消息',
      new Map([
        ['bob', bob.publicKey],
        ['carol', carol.publicKey]
      ]),
      alice.privateKey
    )

    expect(result.encryptedForMember.size).toBe(2)
    expect(decryptFromPeer(result.encryptedForMember.get('bob')!, bob.privateKey)).toBe('群消息')
    expect(decryptFromPeer(result.encryptedForMember.get('carol')!, carol.privateKey)).toBe('群消息')
  })
})

describe('CryptoService 默认自动启用', () => {
  const dirs: string[] = []
  afterEach(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
    dirs.length = 0
  })
  function makeService(path?: string): { svc: CryptoService; path: string } {
    const dir = path ? '' : mkdtempSync(join(tmpdir(), 'teahouse-crypto-'))
    if (dir) dirs.push(dir)
    const identityPath = path ?? join(dir, 'identity.json')
    const svc = new CryptoService({
      selfId: 'node-self',
      identityPath,
      peerStore: {
        getPubKey: () => null,
        hasE2eCapability: () => false,
        updatePubKey: () => undefined
      }
    })
    return { svc, path: identityPath }
  }

  it('ensureKeys 自动生成密钥并触发 ready', () => {
    const { svc } = makeService()
    let ready = 0
    svc.on('ready', () => {
      ready += 1
    })
    expect(svc.isReady()).toBe(false)
    svc.ensureKeys()
    expect(svc.isReady()).toBe(true)
    expect(ready).toBe(1)
    expect(svc.getStatus().hasKeys).toBe(true)
    expect(svc.getStatus().unlocked).toBe(true)
    expect(svc.getPublicKeyForBroadcast()).not.toBeNull()
  })

  it('重启后从包裹私钥恢复同一密钥对', () => {
    const { svc, path } = makeService()
    svc.ensureKeys()
    const fingerprint = svc.getStatus().fingerprint

    const { svc: svc2 } = makeService(path)
    svc2.ensureKeys()
    expect(svc2.getStatus().fingerprint).toBe(fingerprint)
    expect(svc2.isReady()).toBe(true)
  })

  it('resetKeys 无需密码即可生成新指纹', () => {
    const { svc } = makeService()
    svc.ensureKeys()
    const before = svc.getStatus().fingerprint
    expect(svc.resetKeys()).toBe(true)
    expect(svc.getStatus().fingerprint).not.toBe(before)
    expect(svc.isReady()).toBe(true)
  })

  it('identity.json 存的是包裹私钥而非明文', () => {
    const { svc, path } = makeService()
    svc.ensureKeys()
    const raw = JSON.parse(readFileSync(path, 'utf8')) as {
      wrappedPrivateKey: string
      wrappedPrivateKeyEnc: boolean
    }
    expect(raw.wrappedPrivateKeyEnc).toBe(true)
    expect(raw.wrappedPrivateKey).not.toBe(svc.getKeyPair()!.privateKey)
  })
})

describe('wrapPrivateKey / unwrapPrivateKey', () => {
  it('safeStorage 包裹后可解包', () => {
    const kp = generateKeyPair()
    const { wrapped, encrypted } = wrapPrivateKey(kp.privateKey)
    expect(encrypted).toBe(true)
    expect(unwrapPrivateKey(wrapped, encrypted)).toBe(kp.privateKey)
  })

  it('明文回退可直接读回', () => {
    const kp = generateKeyPair()
    expect(unwrapPrivateKey(kp.privateKey, false)).toBe(kp.privateKey)
  })
})

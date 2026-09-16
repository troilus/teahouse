import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  safeStorage: {
    encryptString: (s: string) => Buffer.from(s, 'utf8'),
    decryptString: (b: Buffer) => b.toString('utf8')
  }
}))

import {
  decryptFromPeer,
  encryptForPeer,
  encryptForGroup,
  fingerprintFromPubKey,
  generateKeyPair
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

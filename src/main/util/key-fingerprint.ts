import { createHash } from 'node:crypto'

/** 从 base64 公钥计算指纹：sha256 前 16 字节的 hex（32 字符）。
 *  纯函数，无 Electron 依赖，供 services / search 等复用。 */
export function fingerprintFromPubKey(pubKeyBase64: string): string {
  return createHash('sha256').update(Buffer.from(pubKeyBase64, 'base64')).digest('hex').slice(0, 32)
}

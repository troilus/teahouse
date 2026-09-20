# End-to-end encryption design

> [简体中文](../e2e-encryption.md) · **English**

This repository (the fork) adds LAN end-to-end encryption (E2E) on top of the upstream baseline. The upstream documents ([`protocol.md`](../protocol.md), [`tech-design.md`](../tech-design.md)) stay as they are; this document records only that **local extension**.

In one sentence: between two nodes that both advertise the `e2e1` capability, direct and group chat text is encrypted with AES-256-GCM under keys negotiated through X25519. As soon as one side is a stock upstream node, messages are sent and received as plaintext automatically — no switch is involved.

## 1. Scope

| Item | Conclusion |
|---|---|
| How it ships | Only in this fork's `main`; upstream v0.60.2 does not contain it |
| Switch | None, always on |
| User interaction | No passphrase, no confirmation step; the identity key pair is generated on first start |
| Negotiation | Both sides advertise `e2e1` in `caps` (`CAPS.e2eEncrypted`) and have stored the peer's public key |
| Upstream compatibility | A peer without `e2e1` silently stays on plaintext; fully bidirectional, nothing breaks |

### What is encrypted

| Data | Encrypted | Payload kind |
|---|---|---|
| Direct chat text | ✅ | `encrypted-text` |
| Group chat text | ✅ per member | `encrypted-group-text` |
| File transfer and file metadata | ❌ not implemented | File messages remain plaintext |
| Presence, profile broadcast, probes | ❌ always plaintext | The `entry` / `alive` / `profile` payloads themselves are not encrypted |

> Note: the comment on `CAPS.e2eEncrypted` and the settings copy both say "messages and file metadata"; "file metadata" is currently **out of scope for the implementation**. See section 11.

## 2. Threat model

### Covered

- Passive sniffing on the same LAN: captured text payloads are AES-256-GCM ciphertext.
- An active man-in-the-middle without keys: cannot decrypt and cannot forge ciphertext that passes the GCM authentication tag.
- Eavesdropping during key agreement: the ECDH shared secret is derived from private keys; sniffing only yields the two public keys.

### Not covered

| Threat | Note |
|---|---|
| Compromised endpoint | Malware or debug access can read process memory and `identity.json`, which is equivalent to holding the private key |
| Metadata | Who talks to whom, message length, timing, presence and profile content are all visible |
| Sender impersonation | Decryption only uses the `senderPubKey` embedded in the payload and never compares it with the stored peer key; an attacker able to tamper with messages can impersonate a sender (but cannot read content). Out-of-band fingerprint comparison reveals it |
| Forward secrecy | The long-term identity key takes part in every ECDH; leaking it decrypts past ciphertext |
| Replay | GCM only guarantees integrity and origin; the protocol layer has no anti-replay sequence (it relies on the existing message dedup window) |
| Denial of service | Plaintext probing and blocking attacks are out of scope |

## 3. Cryptographic design

Implementation: `src/main/services/crypto.ts` (plain Node `crypto`, zero third-party dependencies).

| Stage | Algorithm / parameters |
|---|---|
| Identity key | X25519 key pair, long-lived; the stored form is the raw 32-byte key, and the `SPKI`/`PKCS8` DER prefix is prepended to build the `KeyObject` |
| Key agreement | X25519 ECDH (`crypto.diffieHellman`, because `createECDH` does not support x25519) |
| Key derivation | HKDF-SHA256 with a fresh random 32-byte `salt` per message, `info` = `teahouse-e2ee-v1`, 32-byte AES key output |
| Symmetric cipher | AES-256-GCM with a fresh random 12-byte `iv` and an authentication tag |
| Fingerprint | `SHA-256(raw 32-byte public key)` truncated to 16 bytes → 32 hex characters (`src/main/util/key-fingerprint.ts`, pure function, no Electron dependency) |
| Private key at rest | `wrappedPrivateKey` inside `identity.json`, preferably encrypted with Electron `safeStorage` (`wrappedPrivateKeyEnc: true`); when `safeStorage` is unavailable it falls back to plaintext storage with the flag set to `false` |

Ciphertext payload (`EncryptedPayload`):

```json
{
  "ciphertext": "base64",
  "iv": "base64 (12 bytes)",
  "authTag": "base64",
  "salt": "base64 (32 bytes)",
  "senderPubKey": "base64 (sender's raw 32-byte X25519 public key)"
}
```

Every encryption uses a fresh random `salt` and `iv`, so the same plaintext produces different ciphertext each time. Decryption only needs the embedded `senderPubKey` plus the local private key — it does **not** depend on the peer key being stored.

## 4. Capability advertisement and key agreement

### 4.1 Messages

| Location | Content |
|---|---|
| `Profile.pubKey` (optional) | This node's X25519 public key (base64); broadcast with `entry` / `alive` / `profile`, carried when `e2e1` is advertised |
| `MSG_TYPES.keyExchange` = `'key-exchange'` | A dedicated envelope with payload `KeyExchangePayload { pubKey, fingerprint }`, sent over the existing reliable TCP path |
| `CAPS.e2eEncrypted` = `'e2e1'` | Capability bit; both sides must advertise it before anything is encrypted |

### 4.2 Wire validation (`src/main/net/codec.ts`)

- `Profile.pubKey`: optional; when present it must decode as **standard base64** into a 32-byte X25519 public key and must be at most 100 characters.
- `key-exchange`: both `pubKey` and `fingerprint` are required, and `fingerprint` must be 32 hex characters.
- A validation failure drops the whole datagram (no reply, no exception), so malformed payloads never reach the peer table or the key store.

### 4.3 Handshake sequence

1. Start-up: `CryptoService` reads `identity.json`; `ensureKeys()` (which must be called explicitly after the `ready` listener is registered) unwraps an existing private key or generates a new key pair → `[e2e] crypto ready, pubKey fingerprint=…`.
2. Discovery: broadcast `entry` / `alive` / `profile` carries `pubKey` (`[e2e] broadcast profile, pubKey=yes/no`), and incoming ones log `[e2e] recv <type> from …, pubKey=…, caps=…`.
3. Persistence: the peer table is flushed to the `peers` table once per second, including `pub_key` (`[e2e] peers.pub_key written …`).
4. Exchange: on `key-exchange` → `[e2e] recv keyExchange from …` → `savePeerPubKey` writes to SQLite (**no local private key needed**) → the in-memory registry is updated and `emit('updated')` refreshes renderer fingerprints immediately → our own `key-exchange` is sent back (`[e2e] replying keyExchange to …`), deduplicated through `peersKeyExchanged`.
5. Follow-up sends: in the 200 ms throttled push triggered by registry `updated`, `key-exchange` is (re)sent to peers that are online, advertise `e2e1`, and are not in `peersKeyExchanged` (`[e2e] sending keyExchange to …`).
6. Not-ready window: a `key-exchange` received before the local crypto service is ready is still persisted, and step 5 covers the send side once it becomes ready.

> `peersKeyExchanged` only tracks "we already sent a key-exchange to this node" to avoid repeated sends; peer key rotation (for example `resetKeys`) is picked up naturally from the peer's new `pubKey` broadcast and `key-exchange`.

## 5. Sending and receiving

### Direct chat (`src/main/services/chat.ts`)

```
shouldEncrypt = crypto.isReady()
             && peerStore.hasE2eCapability(peerId)   // caps contains e2e1
             && peerStore.getPubKey(peerId)          // peer key already stored
```

- The decision reads **only SQLite** (`peers.caps` / `peers.pub_key`), never the in-memory registry, so churn in memory can never silently downgrade a message to plaintext.
- Success: payload `kind: 'encrypted-text'` (ciphertext + `iv` + `authTag` + `salt` + `senderPubKey`), stored locally with `encrypted = 1` (the bubble shows a lock icon).
- `null` from the encryptor (missing key or unexpected error): the message is **sent as plaintext** and `[e2e] encryptText returned null, fallback to plaintext` is logged — the warning to watch when troubleshooting.
- Receive: `encrypted-text` → build an `EncryptedPayload` → `decryptText` (needs only the embedded `senderPubKey` and the local private key); on failure the ciphertext is kept and marked as undecrypted (`[e2e] decrypt failed`).

### Group chat (`src/main/services/groups.ts`)

- The decision is per member: `memberPubKey && crypto.shouldEncrypt(member)` → that member receives `encrypted-group-text`; otherwise that member alone receives plaintext `group-text` (per-member downgrade, other members unaffected).
- Member keys also come from `peers.pub_key` (injected as `getPeerPubKey`). Every member gets their own negotiated key; there is no shared group key.

## 6. Storage

| Location | Content |
|---|---|
| `peers.pub_key` (appended migration, `TEXT NOT NULL DEFAULT ''`) | Peer public key; the upsert uses `CASE WHEN excluded.pub_key != '' THEN excluded.pub_key ELSE pub_key END`, so an **empty value never overwrites a stored key** |
| `messages.encrypted` (appended migration, `INTEGER NOT NULL DEFAULT 0`) | Whether the local message was sent as ciphertext, surfaced as `MsgRow.encrypted: boolean` |
| `userData/data/identity.json` | `{ publicKey, fingerprint, wrappedPrivateKey, wrappedPrivateKeyEnc }`; `wrappedPrivateKeyEnc: false` means `safeStorage` was unavailable and the private key is stored as plaintext |

Two layers of public-key protection:

1. **Storage layer** (pre-existing): blank `peers.pub_key` values never overwrite a stored key, so the periodic flush cannot erase a negotiated key.
2. **Peer-table layer** (hardened during this merge): `PeerRegistry.touch` keeps the known value when an incoming profile carries no `pubKey`, so the in-memory record cannot flicker or lose the fingerprint shown in the UI. A non-empty peer `pubKey` still overwrites, so key rotation keeps working.

## 7. User interface

| Location | Presentation | Source |
|---|---|---|
| Settings → Security | E2E status (enabled / not enabled), local fingerprint, reset-keys button | `e2e:get-status` / `e2e:reset-keys` / `e2e:status-changed` (`window.pantry.e2eGetStatus()` and friends) |
| Message bubble | A lock icon on encrypted messages | `messages.encrypted`, surfaced on the message row |
| Direct chat header | Peer fingerprint for out-of-band comparison | `PeerView.e2eFingerprint`, computed from the in-memory registry's `profile.pubKey` |
| Conversation search | The same fingerprint field | `services/search.ts` computes it with `fingerprintFromPubKey` |

`E2eStatusView = { hasKeys, unlocked, fingerprint }`; when `unlocked` is false the private key is not unwrapped (`safeStorage` failure or reset keys), and nothing is encrypted.

## 8. Degraded behaviour and troubleshooting

Encryption is best-effort: no step blocks message delivery, and the cost of a failure is plaintext or an undecryptable message. All diagnostics are printed in the main process with the `[e2e]` prefix.

### Log reference

| Log | Meaning |
|---|---|
| `[e2e] crypto ready, pubKey fingerprint=…` | Local keys are ready |
| `[e2e] broadcast profile, pubKey=yes/no` | Whether the broadcast profile carries a key (`no` means keys are not ready yet) |
| `[e2e] recv entry/alive/profile from …, pubKey=…, caps=…` | Whether the peer profile carries a key and advertises `e2e1` |
| `[e2e] recv keyExchange from …, fingerprint=…` | Peer exchange request received |
| `[e2e] registry pubKey updated for …` / `[e2e] keyExchange from unknown node …, persisted only` | Whether the exchange matched an in-memory peer record |
| `[e2e] replying keyExchange to …` | Peer reply sent |
| `[e2e] sending keyExchange to …` | Follow-up exchange send (includes the `(registry updated)` variant) |
| `[e2e] persist peers: N total, M with pubKey` | Key coverage at flush time (printed only when it changes) |
| `[e2e] savePeerPubKey …, fingerprint=…` / `[e2e] peers.pub_key written …` | Peer key written to SQLite |
| `[e2e] shouldEncrypt(x): true` or `false (…)` | Decision plus reason: `keyPair=null`, `peer has no e2e1 cap`, `peer pubKey unknown` |
| `[e2e] sendText to …: cryptoReady=…, shouldEncrypt=…` | Direct-chat send decision |
| `[e2e] encrypt ok, cipherLen=…` / `[e2e] no encryption (shouldEncrypt=false)…` | Direct-chat encryption outcome |
| `[e2e] encryptText returned null, fallback to plaintext` | **Warning**: encryption was expected but failed, so this message went out in plaintext |
| `[e2e] recv encrypted msg from …` / `[e2e] decrypt ok/failed, plainLen=…` | Direct-chat decryption outcome |
| `[e2e] local crypto not ready, cannot decrypt` | Local service not ready, so decryption was impossible (usually self-heals after a restart) |
| `[e2e] group send x: pubKey=…, encrypt=…` | Per-member group decision |
| `[e2e] recv encrypted group msg from …` / `[e2e] group decrypt ok/failed` | Group decryption outcome |
| `[e2e] new keypair generated, fingerprint=…` / `[e2e] keys unlocked from identity` / `[e2e] stored key unusable, regenerating` | Key lifecycle |
| `[e2e] safeStorage unavailable…` / `[e2e] OS keychain not available…` / `[e2e] failed to unwrap private key:` | Private-key protection degraded to plaintext storage |

### Symptom matrix

| Symptom | Where to look |
|---|---|
| Messages are always plaintext | Read the reason in `shouldEncrypt(x)`: the peer does not advertise `e2e1` (stock upstream), or `peers.pub_key` is empty (no `key-exchange` yet) |
| Ciphertext that the peer cannot read | The peer ran `resetKeys` or reinstalled, so its key changed; wait for its new profile to overwrite `pub_key`, or compare fingerprints |
| `encryptText returned null` in the log | Local keys were reset or the peer key is missing; restart the app first, then check whether `identity.json` unwraps cleanly (`[e2e] failed to unwrap private key`) |
| Fingerprint field is empty | The in-memory peer table has no `pubKey` yet; wait for the next `alive`/`profile` or `key-exchange` |
| Both nodes are on the same subnet but never exchange | Check the reliable TCP path, because `key-exchange` uses TCP rather than the UDP broadcast |

## 9. Compatibility with stock upstream

- We never send ciphertext to a node that does not advertise `e2e1`, so upstream nodes only ever receive plaintext they already handle.
- When an upstream node receives `key-exchange`: the `default` branch of the payload validator only requires an object payload, so the envelope decodes fine, but the upstream main process has no branch for that type and therefore **ignores it silently** — no error, no reply, and no impact on existing flows.
- After an upstream node upgrades to this fork, the next `alive`/`profile` broadcast carries the public key and `key-exchange` completes automatically with no user action.
- Profiles from this fork add an optional `pubKey` field; the upstream `codec` is tolerant of unknown fields (`validateProfile` only validates known fields) and does not drop such datagrams.

## 10. Test coverage

| File | What it covers |
|---|---|
| `src/main/services/crypto.test.ts` | Encrypt/decrypt round trip, public key derived from the private key matching, wrong private key failing, fingerprints being 32 hex characters and uniquely determined by the key, per-member group encryption, `ensureKeys` generating keys and emitting `ready`, the same key pair restored from the wrapped key after a restart, `resetKeys` producing a new fingerprint, `identity.json` holding a wrapped rather than plaintext key, `wrapPrivateKey`/`unwrapPrivateKey` round trip and plaintext fallback |
| `src/main/net/codec.test.ts` (`describe('codec 端到端加密')`) | Real X25519 keys (standard base64 including `+` `/` `=`) round-tripping on `profile`/`entry`/`alive`, `key-exchange` round-tripping with a real key and a 32-hex fingerprint, empty or invalid keys and wrong-length fingerprints being rejected, and `profile` with an invalid `pubKey` being rejected |
| `src/main/services/chat.test.ts` | Encrypted messages are flagged locally while plaintext messages are not |
| `src/main/services/groups.test.ts` | The per-member encrypted and plaintext branches |
| `src/main/net/peer-registry.test.ts` | **Hardening regression from this merge**: a profile without `pubKey` keeps the negotiated key, a non-empty `pubKey` still overwrites, and when neither side has a key no `pubKey` property is introduced (which would make the upstream profile comparison fail forever) |

How to run:

```bash
npx vitest run src/main/services/crypto.test.ts src/main/net/codec.test.ts
npm test        # full suite, including network loopback
```

## 11. Known limitations and follow-up work

1. **Files and file metadata are not encrypted**: only direct and group text is covered. The comment on `CAPS.e2eEncrypted` and the settings copy mention "file metadata", which does not match the implementation — either implement it or fix the wording in a later release.
2. **No forward secrecy**: the long-term identity key participates in every ECDH, so leaking it decrypts past ciphertext; forward secrecy would need ephemeral keys (X3DH or a double ratchet) behind a new capability bit.
3. **No identity verification flow**: fingerprints are only displayed for manual out-of-band comparison; there is no trust-on-first-use prompt and no fingerprint-change warning.
4. **The sender key is not checked**: decryption only uses the embedded `senderPubKey` and never compares it against `peers.pub_key`, so impersonating a sender is theoretically possible (without reading content).
5. **No key rotation or revocation**: after `resetKeys` the peer is not told to drop the old key, so ciphertext it sends before its next profile update cannot be decrypted.
6. **No per-message anti-replay**: only GCM integrity and the existing message dedup window apply.
7. **`key-exchange` has no version or algorithm negotiation**: the parameters live in code constants, so any future change needs a new capability bit.
8. **Debug logs are kept on purpose**: this fork intentionally keeps every `[e2e]` log line so the upstream pull request can be reproduced and verified; before a public release they should move behind a setting.

## 12. Code map

| Concern | Location |
|---|---|
| Crypto primitives, `CryptoService`, key lifecycle | `src/main/services/crypto.ts` |
| Fingerprint helper reused by services/search | `src/main/util/key-fingerprint.ts` |
| Protocol fields and constants (`Profile.pubKey`, `KeyExchangePayload`, `CAPS.e2eEncrypted`) | `src/shared/protocol.ts` |
| Wire validation and rejection rules | `src/main/net/codec.ts` |
| `key-exchange` receive/reply, follow-up sends, persistence | `src/main/index.ts` |
| Profile broadcast and receive (including `pubKey`) | `src/main/net/discovery.ts` |
| Peer table and public-key preservation | `src/main/net/peer-registry.ts` |
| Public-key storage and empty-value guard | `src/main/store/peers-repo.ts` and `src/main/store/migrations.ts` |
| Direct-chat encryption and decryption | `src/main/services/chat.ts` |
| Per-member group encryption | `src/main/services/groups.ts` |
| IPC contract (`e2e:get-status` / `e2e:reset-keys` / `e2e:status-changed`, `PeerView.e2eFingerprint`) | `src/shared/ipc.ts` |
| Settings page and message lock icon | `src/renderer/src/SettingsApp.vue`, `src/renderer/src/components/MessageRow.vue` |




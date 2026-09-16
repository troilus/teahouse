import type DatabaseT from 'better-sqlite3'
import type { Platform, Profile } from '../../shared/protocol'
import type { PeerRecord } from '../net/peer-registry'

// 联系人持久化（F-DISC-7 历史联系人持久保留）。
// 写入：registry 变化时整表 upsert（≤1000 行事务内毫秒级）；
// 读取：启动时全量载入，以离线态种回 registry。

interface PeerRow {
  node_id: string
  nick: string
  remark: string | null
  company: string
  dept: string
  team: string
  avatar: number
  avatar_hash: string
  host: string
  platform: string
  ip: string
  udp_port: number
  tcp_port: number
  profile_rev: number
  caps: string
  ver: string
  first_seen: number
  last_seen: number
  pub_key: string
}

function toPlatform(value: string): Platform {
  return value === 'win' || value === 'mac' ? value : 'linux'
}

export class PeersRepo {
  private readonly upsertStmt: DatabaseT.Statement
  private readonly selectAllStmt: DatabaseT.Statement
  private readonly remarkStmt: DatabaseT.Statement
  private readonly remarksAllStmt: DatabaseT.Statement
  private readonly getPubKeyStmt: DatabaseT.Statement
  private readonly hasE2eStmt: DatabaseT.Statement
  private readonly updatePubKeyStmt: DatabaseT.Statement
  private readonly upsertManyTx: (records: PeerRecord[]) => void

  constructor(db: DatabaseT.Database) {
    this.upsertStmt = db.prepare(`
      INSERT INTO peers (
        node_id, nick, company, dept, team, avatar, avatar_hash, host, platform,
        ip, udp_port, tcp_port, profile_rev, caps, ver, pub_key, first_seen, last_seen
      ) VALUES (
        @nodeId, @nick, @company, @dept, @team, @avatar, @avatarHash, @host, @platform,
        @ip, @udpPort, @tcpPort, @profileRev, @caps, @ver, @pubKey, @now, @lastSeen
      )
      ON CONFLICT(node_id) DO UPDATE SET
        nick = excluded.nick, company = excluded.company, dept = excluded.dept,
        team = excluded.team, avatar = excluded.avatar, avatar_hash = excluded.avatar_hash,
        host = excluded.host,
        platform = excluded.platform, ip = excluded.ip, udp_port = excluded.udp_port,
        tcp_port = excluded.tcp_port, profile_rev = excluded.profile_rev,
        caps = excluded.caps, ver = excluded.ver,
        pub_key = CASE WHEN excluded.pub_key != '' THEN excluded.pub_key ELSE pub_key END,
        last_seen = excluded.last_seen
    `) // remark 与 first_seen 不被覆盖：备注是本地资产，首次见面时间只写一次

    this.selectAllStmt = db.prepare('SELECT * FROM peers ORDER BY last_seen DESC')
    // 备注是本地资产（F-DISC-9）：节点未入库时也允许先建占位行
    this.remarkStmt = db.prepare(`
      INSERT INTO peers (node_id, nick, remark, first_seen, last_seen)
      VALUES (?, '', ?, 0, 0)
      ON CONFLICT(node_id) DO UPDATE SET remark = excluded.remark
    `)
    this.remarksAllStmt = db.prepare(
      "SELECT node_id, remark FROM peers WHERE remark IS NOT NULL AND remark != ''"
    )

    this.getPubKeyStmt = db.prepare('SELECT pub_key FROM peers WHERE node_id = ?')
    this.hasE2eStmt = db.prepare('SELECT caps FROM peers WHERE node_id = ?')
    this.updatePubKeyStmt = db.prepare('UPDATE peers SET pub_key = ? WHERE node_id = ?')

    this.upsertManyTx = db.transaction((records: PeerRecord[]) => {
      for (const record of records) this.upsertOne(record)
    }) as unknown as (records: PeerRecord[]) => void
  }

  private upsertOne(record: PeerRecord): void {
    const p = record.profile
    this.upsertStmt.run({
      nodeId: p.nodeId,
      nick: p.nick,
      company: p.company,
      dept: p.dept,
      team: p.team,
      avatar: p.avatar,
      avatarHash: p.avatarHash ?? '',
      host: p.host,
      platform: p.platform,
      ip: record.ip,
      udpPort: record.udpPort,
      tcpPort: p.tcpPort,
      profileRev: p.profileRev,
      caps: JSON.stringify(p.caps),
      ver: p.ver,
      pubKey: p.pubKey ?? '',
      now: Date.now(),
      lastSeen: record.lastSeen
    })
  }

  upsertMany(records: PeerRecord[]): void {
    if (records.length > 0) this.upsertManyTx(records)
  }

  setRemark(nodeId: string, remark: string): void {
    this.remarkStmt.run(nodeId, remark)
  }

  loadRemarks(): Map<string, string> {
    const rows = this.remarksAllStmt.all() as Array<{ node_id: string; remark: string }>
    return new Map(rows.map((r) => [r.node_id, r.remark]))
  }

  /** 获取指定节点的公钥 */
  getPubKey(nodeId: string): string | null {
    const row = this.getPubKeyStmt.get(nodeId) as { pub_key: string } | undefined
    return row?.pub_key || null
  }

  /** 检查节点是否声明 e2e1 能力 */
  hasE2eCapability(nodeId: string): boolean {
    const row = this.hasE2eStmt.get(nodeId) as { caps: string } | undefined
    if (!row) return false
    try {
      const caps: unknown = JSON.parse(row.caps)
      return Array.isArray(caps) && caps.includes('e2e1')
    } catch {
      return false
    }
  }

  /** 更新指定节点的公钥（用于密钥交换） */
  updatePubKey(nodeId: string, pubKey: string): void {
    this.updatePubKeyStmt.run(pubKey, nodeId)
  }

  /** 全量载入为离线记录（在线态由网络层实时判定，不持久化） */
  loadAll(): PeerRecord[] {
    const rows = this.selectAllStmt.all() as PeerRow[]
    return rows.map((row) => {
      let caps: string[] = []
      try {
        const parsed: unknown = JSON.parse(row.caps)
        if (Array.isArray(parsed)) caps = parsed.filter((c): c is string => typeof c === 'string')
      } catch {
        // 损坏的 caps 字段不致命，置空即可
      }
      const profile: Profile = {
        nodeId: row.node_id,
        nick: row.nick,
        company: row.company,
        dept: row.dept,
        team: row.team,
        avatar: row.avatar,
        avatarHash: row.avatar_hash || undefined,
        profileRev: row.profile_rev,
        host: row.host,
        platform: toPlatform(row.platform),
        tcpPort: row.tcp_port,
        ver: row.ver,
        caps,
        pubKey: row.pub_key || undefined
      }
      return {
        profile,
        ip: row.ip,
        udpPort: row.udp_port,
        lastSeen: row.last_seen,
        online: false
      }
    })
  }
}

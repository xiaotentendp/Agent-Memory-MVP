"""
【这个文件干什么】
管两个仓库：底层日志库（防篡改）和中层指针库（可修改但需登记指纹）。
"""

import json
import sqlite3
from datetime import datetime

# 调用咱们刚才写的“指纹部门”
from canon import canonical, digest

# 这就是数据库建表的 SQL 语句
# 建了两张表：log_records（底层日志库）和 pointers（中层指针库）
SCHEMA = """
PRAGMA journal_mode=WAL;  -- 开启预写日志模式，防断电崩溃

-- 底层日志库：只进不出，相当于监控录像
CREATE TABLE IF NOT EXISTS log_records(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,  -- 序号，自动增加
  ts TEXT NOT NULL,                        -- 时间戳
  kind TEXT NOT NULL,                      -- 记录类型（interaction/anchor等）
  payload TEXT NOT NULL,                   -- 内容（已经标准化成字符串了）
  prev_hash TEXT NOT NULL,                 -- 上一条的指纹（这就是哈希链）
  hash TEXT NOT NULL                       -- 本条的指纹
);

-- 中层指针库：存经验摘要，可以改，但是…
CREATE TABLE IF NOT EXISTS pointers(
  ptr_id TEXT PRIMARY KEY,       -- 经验编号，比如 p001
  log_seq INTEGER NOT NULL,      -- 指向底层哪一条日志（指针的核心）
  kind TEXT NOT NULL,            -- primary（主经验）还是 candidate（候选）
  summary TEXT NOT NULL,         -- 摘要（给模型看的）
  intent TEXT,                   -- 意图（通风、调温等）
  action TEXT,                   -- 动作（open_window）
  action_obj TEXT,               -- 对象（车窗）
  params TEXT,                   -- 参数（JSON格式）
  tag TEXT,                      -- 标签（检索用）
  domain TEXT,                   -- 领域（vehicle）
  weight REAL NOT NULL,          -- 权重（1.0）
  tier TEXT NOT NULL,            -- 档位（高/中/低）
  version INTEGER NOT NULL,      -- 版本号
  created_ts TEXT NOT NULL,      -- 创建时间
  last_success_ts TEXT,          -- 上次成功时间
  quarantined INTEGER DEFAULT 0, -- 是否被隔离（0否，1是）
  unstable INTEGER DEFAULT 0,    -- 是否不稳定
  cooldown_count INTEGER DEFAULT 0, -- 恢复次数
  taint_src TEXT,                -- 软污点来源
  ptr_hash TEXT NOT NULL         -- 本条的指纹（算出来的）
);
"""

# 这串列表规定了：算指纹的时候，要把哪些字段一起拿进去算
PTR_FIELDS = [
    "ptr_id", "log_seq", "kind", "summary", "intent", "action", "action_obj",
    "params", "tag", "domain", "weight", "tier", "version", "created_ts",
    "last_success_ts", "quarantined", "unstable", "cooldown_count", "taint_src",
]


def now():
    # 返回当前时间，比如 "2026-11-10 22:30:00"
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Store:
    def __init__(self, path):
        self.conn = sqlite3.connect(str(path))   # 连上 SQLite 数据库
        self.conn.row_factory = sqlite3.Row      # 让查出来的数据可以像字典一样用
        self.conn.executescript(SCHEMA)          # 执行建表语句
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ======== 底层日志库操作 ========
    def append_log(self, kind, payload):
        # 1. 查出上一条记录的指纹（如果是第一条，就设为 "GENESIS" 创世记）
        prev_row = self.conn.execute(
            "SELECT hash FROM log_records ORDER BY seq DESC LIMIT 1").fetchone()
        prev = prev_row["hash"] if prev_row else "GENESIS"

        ts = now()
        payload_text = canonical(payload) # 把数据标准化成字符串

        # 2. 核心：把“上一条指纹 + 类型 + 时间 + 内容”拼一起，算一个新指纹
        # 这样只要前面的记录被改了，后面的链条就全对不上
        h = digest(prev + "|" + kind + "|" + ts + "|" + payload_text)

        # 3. 插入数据库
        cur = self.conn.execute(
            "INSERT INTO log_records(ts, kind, payload, prev_hash, hash) VALUES (?,?,?,?,?)",
            (ts, kind, payload_text, prev, h))
        self.conn.commit()
        return cur.lastrowid, h

    def verify_chain(self):
        # 从第一条开始，一条一条验证指纹
        prev = "GENESIS"
        for r in self.conn.execute("SELECT * FROM log_records ORDER BY seq"):
            # 如果当前记录的 prev_hash 和上一条的 hash 对不上，说明被篡改
            if r["prev_hash"] != prev:
                return False, r["seq"]
            # 如果重新算一遍哈希，和存进去的不一样，说明内容被篡改
            h = digest(r["prev_hash"] + "|" + r["kind"] + "|" + r["ts"] + "|" + r["payload"])
            if h != r["hash"]:
                return False, r["seq"]
            prev = r["hash"]
        return True, None

    def latest_anchor(self, ptr_id):
        """
        【作用】去底层日志里，把某个指针最近一次登记的指纹找出来。
        【为什么要遍历】因为同一个指针可能被保存过多次（权重变了就会重存），
        要拿最新的那一次。
        """
        found = None
        for r in self.conn.execute(
                "SELECT payload FROM log_records WHERE kind='anchor' ORDER BY seq"):
            p = json.loads(r["payload"])
            if p.get("ptr_id") == ptr_id:
                found = p.get("hash")
        return found
        
    # ======== 中层指针库操作 ========
    def save_pointer(self, p):
        # 1. 提取出要算指纹的字段
        body = {k: p.get(k) for k in PTR_FIELDS}
        h = digest(canonical(body)) # 算指纹

        p = dict(body)
        p["ptr_hash"] = h

        # 2. 如果记录存在就更新，不存在就插入 (UPSERT 语法)
        cols = PTR_FIELDS + ["ptr_hash"]
        placeholders = ",".join("?" * len(cols))
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "ptr_id")

        self.conn.execute(
            f"INSERT INTO pointers({','.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(ptr_id) DO UPDATE SET {updates}",
            [p[c] for c in cols])
        self.conn.commit()

        # 3. 关键：每保存一次，就往底层日志追加一条 "anchor"（锚点）记录
        # 把这次的指纹存到底层去，以后就靠它来验明正身
        self.append_log("anchor", {"ptr_id": p["ptr_id"], "hash": h})
        return p

    def get_pointer(self, ptr_id):
        row = self.conn.execute("SELECT * FROM pointers WHERE ptr_id=?", (ptr_id,)).fetchone()
        return dict(row) if row else None

    def list_pointers(self, kind=None, domain=None, tag=None, include_quarantined=False):
        # 组装查询语句，默认不查被隔离的
        sql = "SELECT * FROM pointers WHERE 1=1"
        args = []
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if domain:
            sql += " AND domain=?"
            args.append(domain)
        if tag:
            sql += " AND tag=?"
            args.append(tag)
        if not include_quarantined:
            sql += " AND quarantined=0"
        return [dict(r) for r in self.conn.execute(sql, args)]

    def verify_pointer(self, ptr_id):
        # 从数据库里取出这条指针
        row = self.conn.execute("SELECT * FROM pointers WHERE ptr_id=?", (ptr_id,)).fetchone()
        if not row:
            return False, None, None

        # 重新算一遍现在的指纹
        body = {k: row[k] for k in PTR_FIELDS}
        recomputed = digest(canonical(body))

        # 去底层日志查一下当时的指纹
        anchor = self.latest_anchor(ptr_id)

        # 如果现在的指纹和底层记录的不一样，说明被黑！
        return (recomputed == anchor), recomputed, anchor
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
# 越权专卷：越权审计、越权锁、越权切断卡单独落库，不写业务主库
ESCALATION_DB_PATH: Path | None = None
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

PRODUCT = "源到达SLA"
SKELETON = "多源到达时钟对照 SLA 分级，超限则冻结或降级输出，补齐后恢复并对账"

# 越权切断只能走一种：甲＝只读补齐在服务端拦下，正式零写入并记越权审计。
# 乙（补齐先落申请单、值班确认后才写）本仓不实现；甲与乙互斥，混用即“越权偏了”。
ESCALATION_SCHEME = "A"
ESCALATION_CUTOVER_DAY = "2026-11-19"
ESCALATION_CUTOVER_CARD = {
    "scheme": ESCALATION_SCHEME,
    "day": ESCALATION_CUTOVER_DAY,
    "rule": "只读补齐服务端拦下，正式零写入并记越权审计；甲与乙互斥",
}

PROTECTED_WRITES = (
    "补齐恢复",
    "到达登记",
    "角色附页",
    "越权审计列表",
    "源目录牌",
    "补采席队列",
    "水位卡片",
)


def escalation_db_path() -> Path:
    if ESCALATION_DB_PATH is not None:
        return ESCALATION_DB_PATH
    return DB_PATH.parent / "escalation" / "audit.db"


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def escalation_connect():
    path = escalation_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))


def ensure_escalation_schema(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS escalation_audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      at TEXT NOT NULL,
      actor TEXT NOT NULL,
      role TEXT NOT NULL,
      action TEXT NOT NULL,
      source TEXT NOT NULL,
      reason TEXT NOT NULL,
      detail TEXT NOT NULL,
      acked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS escalation_locks(
      source TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      role TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS escalation_cutover(
      id INTEGER PRIMARY KEY CHECK (id = 1),
      scheme TEXT NOT NULL,
      day TEXT NOT NULL,
      sealed INTEGER NOT NULL,
      archived INTEGER NOT NULL,
      card TEXT NOT NULL,
      written_at TEXT NOT NULL
    );
    """)
    conn.commit()


class EscalationDenied(HTTPException):
    def __init__(self, status: int, reason: str):
        super().__init__(status_code=status,
                         detail={"reason": reason, "escalation": True})
        self.reason = reason


class LoginIn(BaseModel):
    username: str
    password: str


def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u


def role_of(username: str) -> str:
    with connect() as c:
        row = c.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    return row["role"] if row else "只读"


def current(authorization: str | None) -> tuple[str, str]:
    u = require_user(authorization)
    return u, role_of(u)


def record_escalation(actor: str, role: str, action: str, reason: str,
                      source: str = "", detail: str = ""):
    """越权审计只落越权专卷，且不被业务事务回滚。"""
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        conn.execute(
            "INSERT INTO escalation_audit(at,actor,role,action,source,reason,detail) "
            "VALUES (?,?,?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), actor, role,
             action, source, reason, detail),
        )
        conn.commit()
    finally:
        conn.close()


def deny(actor: str, role: str, action: str, reason: str, status: int,
         source: str = "", detail: str = ""):
    record_escalation(actor, role, action, reason, source, detail)
    raise EscalationDenied(status, reason)


def require_write(authorization: str | None, action: str) -> tuple[str, str]:
    """受保护写面：只读一律服务端拒写，并记“越权偏了”。"""
    u, role = current(authorization)
    if role != "管理员":
        raise deny(u, role, action, "越权偏了", 403,
                   detail="只读账号尝试写入受保护写面")
    return u, role


def board_state(conn) -> dict[str, str]:
    return {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM board_state")}


def seal_and_archive_board() -> None:
    """写越权切断卡前必须封板并封档。"""
    now = datetime.now().isoformat(timespec="seconds")
    with connect() as conn:
        state = board_state(conn)
        changed = []
        for key in ("sealed", "archived"):
            if state.get(key) != "yes":
                conn.execute(
                    "INSERT INTO board_state(key,value,updated_at) VALUES (?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
                    " updated_at=excluded.updated_at",
                    (key, "yes", now),
                )
                changed.append(key)
    if changed:
        record_escalation("system", "系统", "切断卡", "封板封档",
                          detail="写越权切断卡前封板封档：" + "、".join(changed))


def ensure_cutover_card() -> None:
    """封板封档后才写越权切断卡；切断册当天不许改口。"""
    with connect() as conn:
        state = board_state(conn)
    if state.get("sealed") != "yes" or state.get("archived") != "yes":
        seal_and_archive_board()
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        row = conn.execute("SELECT * FROM escalation_cutover WHERE id=1").fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO escalation_cutover(id,scheme,day,sealed,archived,card,written_at) "
                "VALUES (1,?,?,1,1,?,?)",
                (ESCALATION_SCHEME, ESCALATION_CUTOVER_DAY,
                 str(ESCALATION_CUTOVER_CARD), datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
            record_escalation("system", "系统", "切断卡", "切断卡封档",
                              detail="越权切断卡已封板封档入册")
    finally:
        conn.close()


def cutover_card() -> dict:
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        row = conn.execute("SELECT * FROM escalation_cutover WHERE id=1").fetchone()
    finally:
        conn.close()
    if not row:
        return {}
    return {"scheme": row["scheme"], "day": row["day"], "sealed": bool(row["sealed"]),
            "archived": bool(row["archived"]), "written_at": row["written_at"]}


app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sources(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          sla_minutes INTEGER NOT NULL,
          output_mode TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS arrivals(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT NOT NULL,
          source_clock TEXT NOT NULL,
          ingest_clock TEXT NOT NULL,
          lag_minutes INTEGER NOT NULL,
          level TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS catchups(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT NOT NULL,
          status TEXT NOT NULL,
          restored_mode TEXT NOT NULL,
          note TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS catchup_queue(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT NOT NULL,
          seat TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS board_state(
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        """)
        if conn.execute("SELECT COUNT(*) c FROM sources").fetchone()["c"] == 0:
            conn.executemany("INSERT INTO sources(name,sla_minutes,output_mode) VALUES (?,?,?)", [
                ("订单源", 15, "可写"), ("支付源", 20, "降级只读"), ("物流源", 30, "冻结"),
            ])
            conn.execute("INSERT INTO arrivals(source,source_clock,ingest_clock,lag_minutes,level) VALUES (?,?,?,?,?)",
                         ("支付源", "2026-11-16T08:00:00", "2026-11-16T08:35:00", 35, "告警"))
            conn.execute("INSERT INTO arrivals(source,source_clock,ingest_clock,lag_minutes,level) VALUES (?,?,?,?,?)",
                         ("物流源", "2026-11-16T07:00:00", "2026-11-16T09:10:00", 130, "违约"))
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute("INSERT OR IGNORE INTO board_state(key,value,updated_at) VALUES ('watermark','0',?)", (now,))
    ensure_cutover_card()


def level_of(lag, sla):
    if lag <= sla:
        return "正常"
    if lag <= sla * 2:
        return "告警"
    return "违约"


def mode_of(level):
    return {"正常": "可写", "告警": "降级只读", "违约": "冻结"}[level]


@app.on_event("startup")
def _s():
    init_db()


@app.exception_handler(EscalationDenied)
def _escalation_denied(_request, exc: EscalationDenied):
    return JSONResponse(status_code=exc.status_code,
                        content={"reason": exc.reason, "escalation": True})


@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM sources").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "sources": n,
            "db": str(DB_PATH), "escalation_db": str(escalation_db_path()),
            "escalation_scheme": ESCALATION_SCHEME}


@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username,role FROM users WHERE username=? AND password_sha=?",
                        (body.username, sha(body.password))).fetchone()
    if not row:
        raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16)
    SESSIONS[tok] = row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}


@app.get("/api/permissions")
def permissions(authorization: str | None = Header(default=None)):
    _u, role = current(authorization)
    writable = role == "管理员"
    return {
        "role": role,
        "scheme": ESCALATION_SCHEME,
        "enforced": True,
        "sealed": True,
        "archived": True,
        "write_capabilities": {k: writable for k in PROTECTED_WRITES},
    }


@app.get("/api/sources")
def sources(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM sources ORDER BY id").fetchall()]}


class ArrivalIn(BaseModel):
    source: str
    source_clock: str
    ingest_clock: str


@app.post("/api/arrivals")
def add_arrival(body: ArrivalIn, authorization: str | None = Header(default=None)):
    require_write(authorization, "到达登记")
    with connect() as c:
        src = c.execute("SELECT * FROM sources WHERE name=?", (body.source,)).fetchone()
        if not src:
            raise HTTPException(404, "未知源")
        parse = datetime.fromisoformat
        lag = int((parse(body.ingest_clock) - parse(body.source_clock)).total_seconds() // 60)
        if lag < 0:
            lag = 0
        lv = level_of(lag, src["sla_minutes"])
        mode = mode_of(lv)
        c.execute("INSERT INTO arrivals(source,source_clock,ingest_clock,lag_minutes,level) VALUES (?,?,?,?,?)",
                  (body.source, body.source_clock, body.ingest_clock, lag, lv))
        c.execute("UPDATE sources SET output_mode=? WHERE name=?", (mode, body.source))
    # 新到达开启新的到达周期，释放该源的越权锁，允许下一轮补齐
    release_escalation_lock(body.source)
    return {"lag_minutes": lag, "level": lv, "output_mode": mode}


@app.get("/api/arrivals")
def arrivals(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM arrivals ORDER BY id DESC").fetchall()]}


ESCALATION_LOCK_LEASE_SECONDS = 30


def _prune_expired_locks(conn) -> None:
    cutoff = (datetime.now() - timedelta(seconds=ESCALATION_LOCK_LEASE_SECONDS)).isoformat(timespec="seconds")
    conn.execute("DELETE FROM escalation_locks WHERE status='held' AND created_at<?", (cutoff,))


def acquire_escalation_lock(source: str, actor: str, role: str) -> sqlite3.Row | None:
    """越权锁落越权专卷：已在窗内或已完成则返回原锁；否则本次占锁返回 None。

    held 锁有租约，避免只读一次拒写把源永久锁死；done 锁长期保留，防止同源重复补齐写库。
    """
    now = datetime.now().isoformat(timespec="seconds")
    conn = escalation_connect()
    conn.isolation_level = None
    try:
        ensure_escalation_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        _prune_expired_locks(conn)
        held = conn.execute("SELECT * FROM escalation_locks WHERE source=?", (source,)).fetchone()
        if held:
            conn.execute("COMMIT")
            return held
        conn.execute("INSERT INTO escalation_locks(source,owner,role,status,created_at) VALUES (?,?,?,?,?)",
                     (source, actor, role, "held", now))
        conn.execute("COMMIT")
        return None
    finally:
        conn.close()


def mark_lock_done(source: str, actor: str, role: str) -> None:
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        conn.execute("UPDATE escalation_locks SET owner=?, role=?, status='done', created_at=? WHERE source=?",
                     (actor, role, datetime.now().isoformat(timespec="seconds"), source))
        conn.commit()
    finally:
        conn.close()


def release_escalation_lock(source: str) -> None:
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        conn.execute("DELETE FROM escalation_locks WHERE source=?", (source,))
        conn.commit()
    finally:
        conn.close()


@app.post("/api/catchup/{source}")
def catchup(source: str, scheme: str = Query(default=ESCALATION_SCHEME),
            authorization: str | None = Header(default=None)):
    u, role = current(authorization)
    # 甲与乙互斥：偏离越权切断卡的请求直接拒绝并记“越权偏了”
    if scheme != ESCALATION_SCHEME:
        raise deny(u, role, "补齐恢复", "越权偏了", 400, source,
                   f"切断方案 {scheme} 与本题方案 {ESCALATION_SCHEME} 互斥")
    with connect() as c:
        src = c.execute("SELECT * FROM sources WHERE name=?", (source,)).fetchone()
    if not src:
        raise HTTPException(404, "未知源")

    held = acquire_escalation_lock(source, u, role)
    if held is not None:
        # 后交只记越权补齐争用，正式零改
        status = 409 if role == "管理员" else 403
        raise deny(u, role, "补齐恢复", "越权补齐争用", status, source,
                   f"越权锁已被 {held['owner']}（{held['role']}）占用，状态 {held['status']}")

    if role != "管理员":
        # 甲路径：只读补齐在服务端拦下，正式零写入
        raise deny(u, role, "补齐恢复", "只读越权补齐", 403, source,
                   "只读账号补齐在服务端拦下，业务库零写入")

    now = datetime.now().isoformat(timespec="seconds")
    try:
        with connect() as c:
            c.execute("UPDATE sources SET output_mode='可写' WHERE name=?", (source,))
            c.execute("INSERT INTO catchups(source,status,restored_mode,note,created_at) VALUES (?,?,?,?,?)",
                      (source, "成功", "可写", "补齐后恢复可写", now))
    except Exception:
        # 管理员写入失败则释放越权锁，避免锁被失败写入长期占用
        release_escalation_lock(source)
        raise
    mark_lock_done(source, u, role)
    record_escalation(u, role, "补齐恢复", "补齐通过", source, "值班管理员补齐，越权锁生效")
    return {"ok": True, "output_mode": "可写", "scheme": ESCALATION_SCHEME}


@app.get("/api/catchups")
def catchups(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM catchups ORDER BY id DESC").fetchall()]}


class SourceIn(BaseModel):
    name: str
    sla_minutes: int
    output_mode: str = "可写"


@app.post("/api/sources")
def add_source(body: SourceIn, authorization: str | None = Header(default=None)):
    """源目录牌：只读拒写。"""
    require_write(authorization, "源目录牌")
    with connect() as c:
        c.execute("INSERT INTO sources(name,sla_minutes,output_mode) VALUES (?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET sla_minutes=excluded.sla_minutes,"
                  " output_mode=excluded.output_mode",
                  (body.name, body.sla_minutes, body.output_mode))
        return {"ok": True}


class RoleIn(BaseModel):
    username: str
    role: str


@app.post("/api/roles")
def set_role(body: RoleIn, authorization: str | None = Header(default=None)):
    """角色附页：只读拒写。"""
    require_write(authorization, "角色附页")
    if body.role not in ("管理员", "只读"):
        raise HTTPException(400, "未知角色")
    with connect() as c:
        if not c.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
            raise HTTPException(404, "未知账号")
        c.execute("UPDATE users SET role=? WHERE username=?", (body.role, body.username))
        return {"ok": True}


class QueueIn(BaseModel):
    source: str
    seat: str


@app.post("/api/catchup-queue")
def enqueue(body: QueueIn, authorization: str | None = Header(default=None)):
    """补采席队列：只读拒写。"""
    require_write(authorization, "补采席队列")
    with connect() as c:
        c.execute("INSERT INTO catchup_queue(source,seat,status,created_at) VALUES (?,?,?,?)",
                  (body.source, body.seat, "待补", datetime.now().isoformat(timespec="seconds")))
        return {"ok": True}


@app.get("/api/catchup-queue")
def queue(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM catchup_queue ORDER BY id DESC").fetchall()]}


class WatermarkIn(BaseModel):
    value: str


@app.post("/api/watermark")
def set_watermark(body: WatermarkIn, authorization: str | None = Header(default=None)):
    """水位卡片：只读拒写。"""
    require_write(authorization, "水位卡片")
    with connect() as c:
        c.execute("INSERT INTO board_state(key,value,updated_at) VALUES ('watermark',?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
                  " updated_at=excluded.updated_at",
                  (body.value, datetime.now().isoformat(timespec="seconds")))
        return {"ok": True}


@app.get("/api/watermark")
def watermark(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT value,updated_at FROM board_state WHERE key='watermark'").fetchone()
    return {"value": row["value"] if row else "0", "updated_at": row["updated_at"] if row else ""}


@app.get("/api/escalation/audit")
def audit_list(authorization: str | None = Header(default=None)):
    """越权审计列表读取对两角色开放，写入不开放。"""
    require_user(authorization)
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        rows = conn.execute("SELECT * FROM escalation_audit ORDER BY id DESC").fetchall()
    finally:
        conn.close()
    return {"items": [dict(r) for r in rows]}


@app.post("/api/escalation/audit/ack")
def audit_ack(authorization: str | None = Header(default=None)):
    """越权审计列表写面：只读拒写。"""
    require_write(authorization, "越权审计列表")
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        conn.execute("UPDATE escalation_audit SET acked=1")
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/api/escalation/cutover")
def get_cutover(authorization: str | None = Header(default=None)):
    require_user(authorization)
    return {"cutover": cutover_card(), "card": ESCALATION_CUTOVER_CARD}


class CutoverIn(BaseModel):
    scheme: str


@app.post("/api/escalation/cutover")
def update_cutover(body: CutoverIn, authorization: str | None = Header(default=None)):
    """越权切断册：当天不许改口；甲与乙互斥，任何换方案都记“越权偏了”。"""
    u, role = require_write(authorization, "越权切断卡")
    # 甲与乙互斥：切断册只能在甲内重封，不得改口到乙
    if body.scheme != ESCALATION_SCHEME:
        raise deny(u, role, "越权切断卡", "越权偏了", 400,
                   detail=f"切断方案 {body.scheme} 与本题方案 {ESCALATION_SCHEME} 互斥")
    card = cutover_card()
    if card.get("day") == datetime.now().date().isoformat():
        raise deny(u, role, "越权切断卡", "越权偏了", 400,
                   detail="越权当天不许改口越权切断册")
    seal_and_archive_board()
    conn = escalation_connect()
    try:
        ensure_escalation_schema(conn)
        conn.execute("UPDATE escalation_cutover SET scheme=?, sealed=1, archived=1, "
                     "card=?, written_at=? WHERE id=1",
                     (body.scheme, str({**ESCALATION_CUTOVER_CARD, "scheme": body.scheme}),
                      datetime.now().isoformat(timespec="seconds")))
        conn.commit()
    finally:
        conn.close()
    record_escalation(u, role, "越权切断卡", "重封", detail=f"切断册按方案 {body.scheme} 重封")
    return {"ok": True, "scheme": body.scheme}


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")

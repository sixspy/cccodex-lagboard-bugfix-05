"""越权切断验收测（只读角色越权补齐切断 · 甲路径）。

顺序要求：先复现（fixtures/escalation），再落本文件的两类失败测：
1. 只读写库失败测 —— 只读账号补齐必须被服务端拦下，正式零写入，留越权审计；
2. 双席抢补失败测 —— 同一源补齐争用必须占越权锁，后交只留“越权补齐争用”。
两类测齐备且转绿后，才允许改越权落库。
"""
from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

import app as lagapp

VIEWER = ("viewer", "view123")
ADMIN = ("admin", "123456")


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(lagapp, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(lagapp, "ESCALATION_DB_PATH", tmp_path / "escalation" / "audit.db", raising=False)
    lagapp.SESSIONS.clear()
    lagapp.init_db()
    yield
    lagapp.SESSIONS.clear()


def _login(client: TestClient, creds) -> dict[str, str]:
    r = client.post("/api/login", json={"username": creds[0], "password": creds[1]})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def _snapshot() -> dict[str, list[tuple]]:
    conn = sqlite3.connect(str(lagapp.DB_PATH))
    try:
        present = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        return {
            t: conn.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()
            for t in ("sources", "arrivals", "catchups", "catchup_queue", "board_state")
            if t in present
        }
    finally:
        conn.close()


def _audit(client: TestClient, admin_h: dict[str, str]) -> list[dict]:
    r = client.get("/api/escalation/audit", headers=admin_h)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def _reasons(client: TestClient, admin_h: dict[str, str]) -> list[str]:
    return [row["reason"] for row in _audit(client, admin_h)]


# ---------------------------------------------------------------------------
# 只读写库失败测：只读补齐必须 403，业务表逐字节零变化，且留越权审计
# ---------------------------------------------------------------------------

def test_viewer_catchup_denied_with_zero_write():
    client = TestClient(lagapp.app)
    viewer_h = _login(client, VIEWER)
    admin_h = _login(client, ADMIN)
    before = _snapshot()

    r = client.post("/api/catchup/物流源", headers=viewer_h)

    assert r.status_code == 403, r.text
    assert r.json()["reason"] == "只读越权补齐"
    assert _snapshot() == before, "只读补齐发生了正式写入"
    assert "只读越权补齐" in _reasons(client, admin_h)
    assert client.get("/api/escalation/audit", headers=viewer_h).status_code == 200


def test_viewer_cannot_write_arrival_or_any_protected_write():
    """五处只读拒写，外加到达登记写路径；服务端拦，不是只藏按钮。"""
    client = TestClient(lagapp.app)
    viewer_h = _login(client, VIEWER)
    before = _snapshot()

    probes = [
        ("/api/arrivals", {"source": "订单源", "source_clock": "2026-11-16T10:00:00",
                           "ingest_clock": "2026-11-16T12:00:00"}),
        ("/api/sources", {"name": "影子源", "sla_minutes": 10}),
        ("/api/roles", {"username": "viewer", "role": "管理员"}),
        ("/api/catchup-queue", {"source": "物流源", "seat": "viewer"}),
        ("/api/watermark", {"value": "99"}),
        ("/api/escalation/audit/ack", {}),
    ]
    for path, body in probes:
        r = client.post(path, headers=viewer_h, json=body)
        assert r.status_code == 403, (path, r.text)
        assert r.json()["reason"] == "越权偏了", (path, r.text)

    assert _snapshot() == before, "只读账号在拒写面上留下了写入"
    assert "越权偏了" in _reasons(client, _login(client, ADMIN))


# ---------------------------------------------------------------------------
# 双席抢补失败测：越权锁 + 后交只留“越权补齐争用”
# ---------------------------------------------------------------------------

def test_dual_seat_catchup_contention_leaves_trace():
    client = TestClient(lagapp.app)
    viewer_h = _login(client, VIEWER)
    admin_h = _login(client, ADMIN)

    first = client.post("/api/catchup/物流源", headers=admin_h)
    assert first.status_code == 200, first.text
    catchups_after_first = client.get("/api/catchups", headers=admin_h).json()["items"]

    second = client.post("/api/catchup/物流源", headers=viewer_h)
    assert second.status_code == 403
    assert second.json()["reason"] == "越权补齐争用"
    assert client.get("/api/catchups", headers=admin_h).json()["items"] == catchups_after_first
    assert "越权补齐争用" in _reasons(client, admin_h)


def test_dual_admin_catchup_second_is_contended_not_written():
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)

    assert client.post("/api/catchup/物流源", headers=admin_h).status_code == 200
    second = client.post("/api/catchup/物流源", headers=admin_h)
    assert second.status_code == 409, second.text
    assert second.json()["reason"] == "越权补齐争用"
    assert len(client.get("/api/catchups", headers=admin_h).json()["items"]) == 1
    assert "越权补齐争用" in _reasons(client, admin_h)


def test_viewer_attempt_first_still_leaves_contention_trace_later():
    """只读先交占越权锁；管理员后交只记争用，正式零改。

    争用是瞬时留痕：锁有租约，租约过后管理员可正常补齐，但争用记录仍在册。
    """
    client = TestClient(lagapp.app)
    viewer_h = _login(client, VIEWER)
    admin_h = _login(client, ADMIN)

    assert client.post("/api/catchup/物流源", headers=viewer_h).status_code == 403
    second = client.post("/api/catchup/物流源", headers=admin_h)
    assert second.status_code == 409, second.text
    assert second.json()["reason"] == "越权补齐争用"
    assert client.get("/api/catchups", headers=admin_h).json()["items"] == []
    reasons = _reasons(client, admin_h)
    assert "只读越权补齐" in reasons
    assert "越权补齐争用" in reasons

    # 租约过后锁释放，管理员可补齐；争用仍留在越权审计册
    conn = lagapp.escalation_connect()
    try:
        conn.execute("UPDATE escalation_locks SET created_at='2000-01-01T00:00:00'")
        conn.commit()
    finally:
        conn.close()
    assert client.post("/api/catchup/物流源", headers=admin_h).status_code == 200
    assert len(client.get("/api/catchups", headers=admin_h).json()["items"]) == 1
    assert "越权补齐争用" in _reasons(client, admin_h)


def test_new_arrival_reopens_source_for_catchup():
    """完成补齐后同源不可重复写；新到达开启新周期后才可再次补齐。"""
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)

    assert client.post("/api/catchup/物流源", headers=admin_h).status_code == 200
    assert client.post("/api/catchup/物流源", headers=admin_h).status_code == 409

    r = client.post("/api/arrivals", headers=admin_h,
                    json={"source": "物流源", "source_clock": "2026-11-16T10:00:00",
                          "ingest_clock": "2026-11-16T12:00:00"})
    assert r.status_code == 200 and r.json()["output_mode"] == "冻结"
    assert client.post("/api/catchup/物流源", headers=admin_h).status_code == 200


# ---------------------------------------------------------------------------
# 权限页 / 五处拒写 / 口径
# ---------------------------------------------------------------------------

def test_permission_matrix_matches_enforcement():
    client = TestClient(lagapp.app)
    viewer_h = _login(client, VIEWER)
    admin_h = _login(client, ADMIN)

    viewer = client.get("/api/permissions", headers=viewer_h).json()
    assert viewer["role"] == "只读"
    assert viewer["scheme"] == "A"
    assert viewer["enforced"] is True
    assert all(v is False for v in viewer["write_capabilities"].values())
    assert set(viewer["write_capabilities"]) == {
        "补齐恢复", "到达登记", "角色附页", "越权审计列表", "源目录牌", "补采席队列", "水位卡片",
    }

    admin = client.get("/api/permissions", headers=admin_h).json()
    assert admin["role"] == "管理员"
    assert all(v is True for v in admin["write_capabilities"].values())


def test_off_scheme_request_is_rejected_and_recorded_as_deviation():
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)

    r = client.post("/api/catchup/物流源?scheme=B", headers=admin_h)
    assert r.status_code == 400, r.text
    assert r.json()["reason"] == "越权偏了"
    assert "越权偏了" in _reasons(client, admin_h)


def test_admin_catchup_still_restores_after_fix():
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)
    r = client.post("/api/catchup/物流源", headers=admin_h)
    assert r.status_code == 200
    assert r.json()["output_mode"] == "可写"
    modes = {s["name"]: s["output_mode"] for s in client.get("/api/sources", headers=admin_h).json()["items"]}
    assert modes["物流源"] == "可写"


# ---------------------------------------------------------------------------
# 越权切断卡：写卡前须封板并封档；当天不许改口
# ---------------------------------------------------------------------------

def test_cutover_card_written_only_after_seal_and_archive():
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)
    with sqlite3.connect(str(lagapp.DB_PATH)) as conn:
        state = dict(conn.execute("SELECT key,value FROM board_state").fetchall())
    assert state["sealed"] == "yes"
    assert state["archived"] == "yes"

    card = client.get("/api/escalation/cutover", headers=admin_h).json()
    assert card["cutover"]["scheme"] == "A"
    assert card["cutover"]["sealed"] is True
    assert card["cutover"]["archived"] is True
    assert card["card"]["scheme"] == "A"
    reasons = _reasons(client, admin_h)
    assert "封板封档" in reasons or "切断卡封档" in reasons


def test_cutover_cannot_be_changed_on_cutover_day():
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)
    r = client.post("/api/escalation/cutover", headers=admin_h, json={"scheme": "B"})
    assert r.status_code == 400
    assert r.json()["reason"] == "越权偏了"
    assert client.get("/api/escalation/cutover", headers=admin_h).json()["cutover"]["scheme"] == "A"
    assert "越权偏了" in _reasons(client, admin_h)


def test_cutover_change_after_day_reaches_book():
    """过了切断日只能在甲内重封；换到乙一律“越权偏了”。"""
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)
    conn = lagapp.escalation_connect()
    try:
        conn.execute("UPDATE escalation_cutover SET day='2026-11-18' WHERE id=1")
        conn.commit()
    finally:
        conn.close()

    crossed = client.post("/api/escalation/cutover", headers=admin_h, json={"scheme": "B"})
    assert crossed.status_code == 400, crossed.text
    assert crossed.json()["reason"] == "越权偏了"
    assert client.get("/api/escalation/cutover", headers=admin_h).json()["cutover"]["scheme"] == "A"

    reseal = client.post("/api/escalation/cutover", headers=admin_h, json={"scheme": "A"})
    assert reseal.status_code == 200, reseal.text
    assert reseal.json()["scheme"] == "A"
    reasons = _reasons(client, admin_h)
    assert "越权偏了" in reasons
    assert "重封" in reasons


def test_escalation_volume_is_separate_from_business_db():
    client = TestClient(lagapp.app)
    admin_h = _login(client, ADMIN)
    assert client.post("/api/catchup/物流源", headers=admin_h).status_code == 200
    health = client.get("/api/health").json()
    assert health["escalation_db"] != health["db"]
    assert "escalation" in health["escalation_db"]
    assert lagapp.escalation_db_path().exists()

    with sqlite3.connect(str(lagapp.DB_PATH)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "escalation_audit" not in tables
    assert "escalation_locks" not in tables
    assert "escalation_cutover" not in tables

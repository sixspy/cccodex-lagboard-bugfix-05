"""复现只读账号越权补齐写库（越权切断题的证据夹具）。

修复前：只读账号 POST /api/catchup/{source} 返回 200 并写入 catchups、把输出态
改为可写。修复后：同一请求 403、正式零写入。脚本把改动前后的库文件与差异
报告落到 fixtures/escalation/（越权专卷），用于对比修复前后。

用法（仓库根目录）：
    # 修复后代码
    PYTHONPATH=backend python tests/repro_viewer_catchup_write.py --label after_fix
    # 修复前代码（从 git HEAD 取原始实现到临时目录）
    PYTHONPATH=<tmp>/backend python tests/repro_viewer_catchup_write.py --label before_fix --db-root <tmp>
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "escalation"
TABLES = ("users", "sources", "arrivals", "catchups")


def snapshot(db_path: Path) -> dict[str, list[dict]]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {
            t: [dict(r) for r in conn.execute(f"SELECT * FROM {t}")]
            for t in TABLES
            if t in present
        }
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="after_fix", help="报告与库文件后缀")
    ap.add_argument("--db-root", default=None, help="库文件放置根目录（默认临时目录）")
    args = ap.parse_args()

    import app as lagapp
    from app import app
    from fastapi.testclient import TestClient

    OUT.mkdir(parents=True, exist_ok=True)
    if args.db_root:
        tmp = Path(args.db_root)
    else:
        tmp = Path(tempfile.mkdtemp(prefix="lagboard-escalation-fixture-"))
    tmp.mkdir(parents=True, exist_ok=True)

    lagapp.DB_PATH = tmp / "app.db"
    if hasattr(lagapp, "ESCALATION_DB_PATH"):
        lagapp.ESCALATION_DB_PATH = tmp / "escalation" / "audit.db"
    lagapp.SESSIONS.clear()
    lagapp.init_db()

    client = TestClient(app)
    login = client.post("/api/login", json={"username": "viewer", "password": "view123"})
    assert login.status_code == 200, login.text
    headers = {"Authorization": "Bearer " + login.json()["token"]}

    before = snapshot(lagapp.DB_PATH)
    before_path = OUT / f"viewer_catchup_{args.label}_before.db"
    shutil.copyfile(lagapp.DB_PATH, before_path)

    resp = client.post("/api/catchup/物流源", headers=headers)
    after = snapshot(lagapp.DB_PATH)
    after_path = OUT / f"viewer_catchup_{args.label}_after.db"
    shutil.copyfile(lagapp.DB_PATH, after_path)

    mode_before = next(s["output_mode"] for s in before["sources"] if s["name"] == "物流源")
    mode_after = next(s["output_mode"] for s in after["sources"] if s["name"] == "物流源")
    delta = {t: len(after[t]) - len(before[t]) for t in TABLES if t in before}
    report = {
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "label": args.label,
        "actor": "viewer",
        "role": "只读",
        "endpoint": "POST /api/catchup/物流源",
        "http_status": resp.status_code,
        "response": resp.json(),
        "row_delta": delta,
        "output_mode_before": mode_before,
        "output_mode_after": mode_after,
        "viewer_write_observed": any(v != 0 for v in delta.values()) or mode_before != mode_after,
        "before_db": before_path.name,
        "after_db": after_path.name,
    }
    (OUT / f"repro_{args.label}.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

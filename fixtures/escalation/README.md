# 越权补齐写库夹具（越权专卷）

本目录是“越权切断”题专用的库文件卷，主库 `data/app.db` 不存放本夹具，越权审计 / 越权锁 /
越权切断册也单独落 `data/escalation/audit.db`（越权专卷）。

`tests/repro_viewer_catchup_write.py` 用只读账号 `viewer/view123` 对 `物流源` 发起一次补齐，
并在改动前后各拷贝一份 SQLite 库，产出对照证据：

| 前缀 | 含义 |
|------|------|
| `viewer_catchup_before_fix_before.db` / `..._after.db` | 修复前：只读补齐前 / 后的库（after 多出 catchups 行） |
| `viewer_catchup_after_fix_before.db` / `..._after.db` | 修复后：只读补齐前 / 后的库（两库一致） |
| `repro_before_fix.json` | 修复前报告：HTTP 200，`viewer_write_observed: true` |
| `repro_after_fix.json` | 修复后报告：HTTP 403 `只读越权补齐`，零写入 |

运行方式（仓库根目录）：

```bash
# 修复后代码
PYTHONPATH=backend python tests/repro_viewer_catchup_write.py --label after_fix
# 修复前代码（从 git HEAD 取原始实现到临时目录）
git archive HEAD backend frontend | tar -x -C /tmp/beforefix
PYTHONPATH=/tmp/beforefix/backend python tests/repro_viewer_catchup_write.py \
    --label before_fix --db-root /tmp/beforefix/db
```

该脚本是证据夹具，不是测试用例；验收测试见 `tests/test_escalation_cutoff.py`。

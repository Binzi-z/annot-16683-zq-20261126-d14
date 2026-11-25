"""子进程崩溃助手：由 test_subprocess_crash 以独立 Python 进程调用。

用法：
  python _crash_helper.py crash   <ws> <src> <approval> <relpath>
  python _crash_helper.py abort   <ws> <src> <approval> <relpath>
  python _crash_helper.py recover <ws> ...
  python _crash_helper.py check   <ws> ...
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quarprom import approval as am  # noqa: E402
from quarprom.promoter import PromotionRequest, Promoter  # noqa: E402
from quarprom.recovery import recover  # noqa: E402
from quarprom.workspace import Workspace  # noqa: E402
from inspector import checker  # noqa: E402


def main() -> int:
    mode, ws_root, src, approval_path, relpath = sys.argv[1:6]
    ws = Workspace.open(ws_root)
    keystore = am.KeyStore.load(ws.keystore_path)
    approval = am.load_approval(approval_path)
    with open(src, "rb") as fh:
        data = fh.read()
    codename = "gamma"

    if mode in ("crash", "abort"):
        req = PromotionRequest(
            codename=codename, source=src, relpath=relpath, approval=approval,
            content=data,
            crash_before_receipt=(mode == "crash"),
            fail_last_segment=(mode == "abort"),
            segment_size=256,
        )
        result = Promoter(ws, keystore).promote(req)
        print(json.dumps({"status": result.status, "error": result.error},
                         ensure_ascii=False))
        return 0
    if mode == "recover":
        report = recover(ws)
        print(json.dumps(report.to_dict(), ensure_ascii=False))
        return 0
    if mode == "check":
        report = checker.run_check(ws_root)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report["ok"] and not report["fatal"] else 1
    print(f"unknown mode: {mode}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())

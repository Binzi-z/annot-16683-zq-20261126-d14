"""真实子进程崩溃测试：晋升已持久化但回执丢失（os._exit），新进程重启恢复。

与进程内测试不同，这里用 subprocess 跑独立 Python 进程，进程死亡后没有任何
内存状态可以依赖，恢复只能依据磁盘上的实际目录与决定日志。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from quarprom import approval as am
from quarprom.digest import sha256_file
from quarprom.paths import atomic_write, resolved
from quarprom.workspace import Workspace

HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_crash_helper.py")


class SubprocessCrashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="quarprom-crash-")
        self.ws_root = os.path.join(self.tmp, "ws")
        self.qdir = os.path.join(self.tmp, "quarantine")
        self.adir = os.path.join(self.tmp, "allowed")
        self.ws = Workspace.create(self.ws_root, self.qdir, self.adir)
        self.keystore = am.KeyStore.create(self.ws.keystore_path, ("alice", "bob"))
        # 准备制品与审批
        self.src = os.path.join(self.qdir, "gamma.bin")
        atomic_write(self.src, b"gamma payload " + bytes(range(256)) * 4)
        dig = sha256_file(self.src)
        _q, a_root = self.ws.bound_roots()
        approval = am.issue_approval(
            keystore=self.keystore, target_root=a_root, full_digest=dig,
            codename="gamma", source_aliases=[self.src], signers=("alice", "bob"),
        )
        self.approval_path = os.path.join(self.tmp, "gamma.approval.json")
        am.save_approval(approval, self.approval_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_helper(self, mode: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, HELPER, mode, self.ws_root, self.src,
             self.approval_path, "proj/gamma.bin"],
            capture_output=True, text=True, env=env, timeout=120,
            encoding="utf-8", errors="replace",
        )

    def test_process_dies_after_durable_promotion_without_receipt(self):
        # 1) 子进程在写回执前 os._exit
        proc = self._run_helper("crash")
        self.assertEqual(proc.returncode, 2, msg=proc.stderr)
        # 2) 进程已死：磁盘上晋升决定、视图、目标文件都在，但回执不存在
        from quarprom import receipts as receipts_mod
        self.assertFalse(receipts_mod.receipt_exists(self.ws.receipts_dir, "proj/gamma.bin"))
        final = os.path.join(self.adir, "proj", "gamma.bin")
        self.assertTrue(os.path.exists(final))
        with open(self.ws.log_path, "rb") as fh:
            kinds = [json.loads(line)["kind"] for line in fh if line.strip()]
        self.assertIn("PROMOTED", kinds)
        self.assertTrue(os.path.exists(self.ws.crash_trace_path))

        # 3) 全新进程重启恢复
        proc2 = self._run_helper("recover")
        self.assertEqual(proc2.returncode, 0, msg=proc2.stderr)
        rec = json.loads(proc2.stdout)
        self.assertEqual(rec["rebuilt_receipts"], ["proj/gamma.bin"])
        self.assertEqual(len(rec["public_set"]), 1)
        self.assertEqual(rec["public_set"][0]["relpath"], "proj/gamma.bin")
        # 4) 第三个全新进程运行独立检查器：必须干净通过
        proc3 = self._run_helper("check")
        self.assertEqual(proc3.returncode, 0, msg=proc3.stderr)
        check = json.loads(proc3.stdout)
        self.assertTrue(check["ok"], msg=json.dumps(check["findings"], ensure_ascii=False))

    def test_fail_last_segment_in_subprocess_leaves_clean_state(self):
        proc = self._run_helper("abort")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["status"], "ABORTED")
        final = os.path.join(self.adir, "proj", "gamma.bin")
        self.assertFalse(os.path.exists(final))
        # 恢复后无违规
        proc2 = self._run_helper("recover")
        rec = json.loads(proc2.stdout)
        self.assertEqual(rec["violations"], [])
        self.assertEqual(rec["public_set"], [])

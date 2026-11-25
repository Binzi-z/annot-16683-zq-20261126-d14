"""晋升编排：成功路径、最后一段失败回滚、双线程屏障与视图发布。"""

import os

from quarprom.declog import DecisionLog
from quarprom.journal import list_journals
from quarprom.promoter import PromotionRequest, Promoter
from quarprom.recovery import recover
from quarprom.views import ViewStore

from tests.helpers import WorkspaceCase


class PromotionTests(WorkspaceCase):
    def _request(self, codename: str, relpath: str, **kw):
        src, data, dig = self.make_artifact(codename)
        ap = self.make_approval(codename, dig, src)
        return PromotionRequest(
            codename=codename, source=src, relpath=relpath,
            approval=ap, content=data, **kw
        )

    def test_successful_promotion_persists_receipt_and_view(self):
        promoter = Promoter(self.ws, self.keystore)
        result = promoter.promote(self._request("alpha", "proj/alpha.bin"))
        self.assertEqual(result.status, "PROMOTED")
        _q, a_root = self.ws.bound_roots()
        final = os.path.join(a_root, "proj", "alpha.bin")
        self.assertTrue(os.path.exists(final))
        self.assertIsNotNone(result.receipt_path)
        self.assertTrue(os.path.exists(result.receipt_path))
        # journal 已清理、决定日志含 PROMOTED、视图已发布
        self.assertEqual(list_journals(self.ws.journals_dir), [])
        records = DecisionLog(self.ws.log_path).verify_chain()
        self.assertIn("PROMOTED", [r.kind for r in records])
        store = ViewStore(self.ws.views_dir, self.ws.blobs_dir)
        self.assertEqual(store.current_version(), result.view.version)
        # 新视图可完整重放
        manifest = store.replay(result.view.version)
        self.assertIn("proj/alpha.bin", manifest["files"])

    def test_fail_last_segment_rolls_back_and_logs_aborted(self):
        promoter = Promoter(self.ws, self.keystore)
        req = self._request("beta", "proj/beta.bin",
                            fail_last_segment=True, segment_size=256)
        result = promoter.promote(req)
        self.assertEqual(result.status, "ABORTED")
        self.assertIn("最后一段", result.error)
        # 回滚动作非空，且最终允许区不存在目标文件与暂存文件
        self.assertTrue(len(result.rollback_report) >= 1)
        _q, a_root = self.ws.bound_roots()
        self.assertFalse(os.path.exists(os.path.join(a_root, "proj", "beta.bin")))
        staging = os.path.join(a_root, ".staging", "proj", "beta.bin.tmp")
        self.assertFalse(os.path.exists(staging))
        self.assertEqual(list_journals(self.ws.journals_dir), [])
        # 决定日志哈希链完整且最新决定为 ABORTED
        records = DecisionLog(self.ws.log_path).verify_chain()
        self.assertEqual(records[-1].kind, "ABORTED")
        # 恢复后无违规、公开集合为空
        report = recover(self.ws)
        self.assertEqual(report.violations, [])
        self.assertEqual(report.public_set, [])

    def test_journal_committed_before_mutation_trace(self):
        promoter = Promoter(self.ws, self.keystore)
        result = promoter.promote(self._request("alpha", "proj/alpha.bin"))
        trace = "\n".join(result.thread_trace)
        self.assertIn("undo journal committed", trace)
        self.assertIn("barrier1", trace)
        self.assertIn("commit gate", trace)

    def test_two_promotions_publish_two_immutable_views(self):
        promoter = Promoter(self.ws, self.keystore)
        r1 = promoter.promote(self._request("alpha", "proj/alpha.bin"))
        r2 = promoter.promote(self._request("beta", "proj/beta.bin"))
        self.assertEqual(r1.view.version, 1)
        self.assertEqual(r2.view.version, 2)
        store = ViewStore(self.ws.views_dir, self.ws.blobs_dir)
        # 旧视图 v1 仍可独立重放，且只含第一个文件
        v1 = store.replay(1)
        v2 = store.replay(2)
        self.assertEqual(set(v1["files"]), {"proj/alpha.bin"})
        self.assertEqual(set(v2["files"]), {"proj/alpha.bin", "proj/beta.bin"})

    def test_promotion_uses_two_real_threads(self):
        import threading
        before = threading.active_count()
        promoter = Promoter(self.ws, self.keystore)
        seen = []
        real_start = threading.Thread.start

        def spy_start(self_t):
            if self_t.name in ("gate-controller", "segmented-writer"):
                seen.append(self_t.name)
            return real_start(self_t)

        threading.Thread.start = spy_start
        try:
            promoter.promote(self._request("alpha", "proj/alpha.bin"))
        finally:
            threading.Thread.start = real_start
        self.assertEqual(sorted(seen), ["gate-controller", "segmented-writer"])
        self.assertEqual(threading.active_count(), before)

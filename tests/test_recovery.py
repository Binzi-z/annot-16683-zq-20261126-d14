"""恢复对账：回执丢失重建、残留 journal 回滚、越权可见分类。"""

import json
import os

from quarprom import receipts as receipts_mod
from quarprom.journal import UndoJournal
from quarprom.promoter import PromotionRequest, Promoter
from quarprom.recovery import earliest_violation, recover
from quarprom.paths import atomic_write

from tests.helpers import WorkspaceCase


class RecoveryTests(WorkspaceCase):
    def _promote(self, codename: str, relpath: str):
        src, data, dig = self.make_artifact(codename)
        ap = self.make_approval(codename, dig, src)
        promoter = Promoter(self.ws, self.keystore)
        return promoter.promote(PromotionRequest(
            codename=codename, source=src, relpath=relpath, approval=ap, content=data,
        ))

    def test_receipt_rebuilt_after_durable_promotion(self):
        result = self._promote("alpha", "proj/alpha.bin")
        # 模拟回执丢失：删除回执文件（晋升决定/视图/磁盘文件都保留）
        os.remove(result.receipt_path)
        self.assertFalse(receipts_mod.receipt_exists(self.ws.receipts_dir, "proj/alpha.bin"))
        report = recover(self.ws)
        self.assertEqual(report.rebuilt_receipts, ["proj/alpha.bin"])
        self.assertTrue(receipts_mod.receipt_exists(self.ws.receipts_dir, "proj/alpha.bin"))
        self.assertEqual(len(report.public_set), 1)
        self.assertTrue(report.public_set[0].receipt_rebuilt)
        # 重建回执引用的决定哈希与日志一致
        with open(result.receipt_path, "rb") as fh:
            receipt = json.loads(fh.read())
        self.assertEqual(receipt["decision_hash"], result.decision.record_hash)
        # 再恢复一次不应重复重建
        report2 = recover(self.ws)
        self.assertEqual(report2.rebuilt_receipts, [])

    def test_leftover_journal_is_rolled_back_on_restart(self):
        # 手工制造一个"已提交但未完成"的残留 journal + 一个未登记文件
        _q, a_root = self.ws.bound_roots()
        stray = os.path.join(a_root, "proj", "stray.bin")
        os.makedirs(os.path.dirname(stray), exist_ok=True)
        atomic_write(stray, b"stray bytes")
        jp = os.path.join(self.ws.journals_dir, "leftover.undo.json")
        journal = UndoJournal(journal_id="leftover", path=jp,
                              codename="stray", relpath="proj/stray.bin")
        journal.record_create(stray)
        journal.commit()
        self.assertTrue(os.path.exists(jp))
        report = recover(self.ws)
        self.assertFalse(os.path.exists(stray))
        self.assertFalse(os.path.exists(jp))
        self.assertEqual(len(report.journals_rolled_back), 1)

    def test_aborted_but_visible_is_flagged_with_earliest_timestamp(self):
        src, data, dig = self.make_artifact("beta")
        ap = self.make_approval("beta", dig, src)
        promoter = Promoter(self.ws, self.keystore)
        result = promoter.promote(PromotionRequest(
            codename="beta", source=src, relpath="proj/beta.bin", approval=ap,
            content=data, fail_last_segment=True, segment_size=128,
        ))
        self.assertEqual(result.status, "ABORTED")
        # 攻击者/磁盘错误把已撤销制品写回允许区
        _q, a_root = self.ws.bound_roots()
        target = os.path.join(a_root, "proj", "beta.bin")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        atomic_write(target, b"re-created without any decision")
        report = recover(self.ws)
        codes = [v.code for v in report.violations]
        self.assertIn("ABORTED_BUT_VISIBLE", codes)
        earliest = earliest_violation(report)
        self.assertEqual(earliest.code, "ABORTED_BUT_VISIBLE")
        self.assertIsNotNone(earliest.first_visible_ts_ns)
        self.assertEqual(earliest.evidence["abort_seq"], result.decision.seq)

    def test_undecided_ghost_file_is_flagged(self):
        _q, a_root = self.ws.bound_roots()
        ghost = os.path.join(a_root, "shadow", "ghost.bin")
        os.makedirs(os.path.dirname(ghost), exist_ok=True)
        atomic_write(ghost, b"no decision record")
        report = recover(self.ws)
        self.assertEqual([v.code for v in report.violations], ["UNDECIDED_BUT_VISIBLE"])

    def test_promised_but_missing_is_flagged(self):
        result = self._promote("alpha", "proj/alpha.bin")
        _q, a_root = self.ws.bound_roots()
        os.remove(os.path.join(a_root, "proj", "alpha.bin"))
        report = recover(self.ws)
        self.assertEqual([v.code for v in report.violations], ["PROMISED_BUT_MISSING"])
        self.assertEqual(result.decision.record_hash,
                         report.violations[0].evidence["decision_hash"])

    def test_repeated_recovery_keeps_full_public_set(self):
        """回归：VIEW_PUBLISHED/RECOVERED 事件不得覆盖 PROMOTED 决定。"""
        self._promote("alpha", "proj/alpha.bin")
        self._promote("beta", "proj/beta.bin")
        first = recover(self.ws)
        self.assertEqual({e.relpath for e in first.public_set},
                         {"proj/alpha.bin", "proj/beta.bin"})
        # 第二次恢复：RECOVERED 事件已入链，公开集合必须保持完整且不重复补建
        second = recover(self.ws)
        self.assertEqual({e.relpath for e in second.public_set},
                         {"proj/alpha.bin", "proj/beta.bin"})
        self.assertEqual(second.rebuilt_receipts, [])
        self.assertEqual(second.violations, [])
        third = recover(self.ws)
        self.assertEqual({e.relpath for e in third.public_set},
                         {"proj/alpha.bin", "proj/beta.bin"})
